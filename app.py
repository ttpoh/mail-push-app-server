import os
import json
import base64
import pickle
import logging
import datetime
from urllib.parse import urljoin
import requests
from flask import Flask, request, jsonify, send_from_directory
from bs4 import BeautifulSoup
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from datetime import datetime, timedelta

from auth.gmail_auth import GmailAuth
from auth.outlook_auth import OutlookAuth
from fcm.fcm_service import FcmService

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ACME HTTP-01 challenge 응답용 라우트
def acme_challenge(filename):
    root = os.path.join(app.root_path, 'webroot', '.well-known', 'acme-challenge')
    return send_from_directory(root, filename)

# --- Token stores persistence ---
GMAIL_STORE_FILE = 'gmail_token_store.pkl'
OUTLOOK_STORE_FILE = 'outlook_token_store.pkl'

gmail_token_store = {}
outlook_auth = OutlookAuth(
    client_id='dcf1d4af-a8fc-4474-9857-5801f9ac766e',
    client_secret='fbf142b5-0de7-48bd-9fb8-616dac9c9a84',
    notify_url=f"{os.getenv('NGROK_URL', 'https://3.38.1.61:5000')}/outlook_webhook"
)

def load_token_stores():
    global gmail_token_store
    try:
        with open(GMAIL_STORE_FILE, 'rb') as f:
            gmail_token_store = pickle.load(f)
            logger.info(f"Loaded gmail_token_store: {gmail_token_store}")
    except FileNotFoundError:
        logger.info("Gmail store not found, initializing empty store")
        gmail_token_store = {}
    try:
        with open(OUTLOOK_STORE_FILE, 'rb') as f:
            outlook_auth.token_store = pickle.load(f)
            logger.info(f"Loaded outlook_token_store: {outlook_auth.token_store}")
    except FileNotFoundError:
        logger.info("Outlook store not found, initializing empty store")
        outlook_auth.token_store = {}

def save_token_stores():
    try:
        with open(GMAIL_STORE_FILE, 'wb') as f:
            pickle.dump(gmail_token_store, f)
        with open(OUTLOOK_STORE_FILE, 'wb') as f:
            pickle.dump(outlook_auth.token_store, f)
        logger.info("Token stores saved successfully")
    except Exception as e:
        logger.error(f"Failed to save token stores: {e}")

load_token_stores()
gmail_auth = GmailAuth()
fcm_service = FcmService()
processed_history_ids = set()
processed_message_ids = set()

# --- public client manual token-refresh helper ---
def refresh_access_token(refresh_token: str, client_id: str):
    payload = {
        'grant_type':    'refresh_token',
        'refresh_token': refresh_token,
        'client_id':     client_id,
    }
    resp = requests.post('https://oauth2.googleapis.com/token', data=payload)
    resp.raise_for_status()
    data = resp.json()
    return data['access_token'], data.get('expires_in', 3600)

# --- Token Validation ---
@app.route('/validate_token', methods=['POST'])
def validate_token():
    data = request.get_json() or {}
    logger.info(f"Validate token request: {data}")
    service = data.get('service')
    token = data.get('access_token') or data.get('accessToken')
    if not service or not token:
        return jsonify({'error': 'Required fields missing'}), 400
    if service == 'gmail':
        creds = Credentials(
            token=token,
            token_uri='https://oauth2.googleapis.com/token',
            client_id=gmail_auth.CLIENT_ID,
            scopes=['https://www.googleapis.com/auth/gmail.modify']
        )
        return jsonify({'valid': creds.valid}), 200
    elif service == 'outlook':
        resp = requests.get(
            'https://graph.microsoft.com/v1.0/me',
            headers={'Authorization': f'Bearer {token}'}
        )
        return jsonify({'valid': resp.status_code == 200}), 200
    else:
        return jsonify({'error': 'Unsupported service'}), 400

# --- Gmail Email Details ---
def get_gmail_email_details(fcm_token, history_id, retries=3):
    entry = gmail_token_store.get(fcm_token)
    if not entry:
        logger.error(f"No Gmail tokens for fcm_token: {fcm_token}")
        raise RuntimeError(f"No Gmail tokens for {fcm_token}")

    # 1) 수동 갱신 (토큰 만료 전에도 한 번)
    new_token, expires_in = refresh_access_token(
        entry['refresh_token'],
        gmail_auth.CLIENT_ID
    )
    entry['access_token'] = new_token
    # expiry를 꼭 설정해야 googleapiclient가 자동 갱신을 하지 않습니다
    expiry = datetime.utcnow() + timedelta(seconds=expires_in)
    save_token_stores()

    # 2) credentials 객체 생성 및 expiry 지정
    creds = Credentials(token=new_token)
    creds.expiry = expiry

    # 3) 서비스 빌드
    service = build(
        'gmail', 'v1',
        credentials=creds,
        cache_discovery=False
    )

    # 4) history list
    history = service.users().history().list(
        userId='me',
        startHistoryId=entry.get('last_history_id', '1')
    ).execute()

    # 5) 새 메시지 처리
    for record in history.get('history', []):
        for added in record.get('messagesAdded', []):
            msg_id = added['message']['id']
            if msg_id in processed_message_ids:
                continue

            msg = service.users().messages().get(
                userId='me',
                id=msg_id,
                format='full'
            ).execute()

            headers = msg['payload'].get('headers', [])
            subject = next((h['value'] for h in headers if h['name']=='Subject'), 'No Subject')
            sender  = next((h['value'] for h in headers if h['name']=='From'), 'Unknown Sender')

            def extract_body(part):
                if 'parts' in part:
                    for p in part['parts']:
                        txt = extract_body(p)
                        if txt:
                            return txt
                elif part.get('mimeType') == 'text/plain' and part.get('body', {}).get('data'):
                    return base64.urlsafe_b64decode(part['body']['data']).decode('utf-8', errors='ignore')
                elif part.get('mimeType') == 'text/html' and part.get('body', {}).get('data'):
                    html = base64.urlsafe_b64decode(part['body']['data']).decode('utf-8', errors='ignore')
                    return BeautifulSoup(html, 'html.parser').get_text()
                return ''

            body = extract_body(msg['payload']) or 'No Body'
            processed_message_ids.add(msg_id)
            entry['last_history_id'] = history_id
            save_token_stores()
            return subject, body, sender

    return None, None, None

# --- Outlook Email Details ---
def get_outlook_email_details(fcm_token, message_id, retries=3):
    for attempt in range(retries):
        try:
            token = outlook_auth.get_valid_token(fcm_token)
            url = urljoin('https://graph.microsoft.com/v1.0', f'/me/messages/{message_id}')
            headers = {'Authorization': f'Bearer {token}'}
            resp = requests.get(url, headers=headers)
            resp.raise_for_status()
            msg = resp.json()
            subject = msg.get('subject', 'No Subject')
            sender = msg.get('from', {}).get('emailAddress', {}).get('address', 'Unknown Sender')
            content = msg.get('body', {}).get('content', '')
            if msg.get('body', {}).get('contentType') == 'html':
                body = BeautifulSoup(content, 'html.parser').get_text()
            else:
                body = content
            if message_id in processed_message_ids:
                return None, None, None, None
            processed_message_ids.add(message_id)
            return subject, body, sender, fcm_token
        except requests.HTTPError as e:
            logger.error(f"Failed to fetch Outlook email details (attempt {attempt + 1}): {e}")
            if e.response.status_code == 401 and attempt < retries - 1:
                outlook_auth._refresh_token(fcm_token)
                continue
            return None, None, None, None
        except Exception as e:
            logger.error(f"Unexpected error in get_outlook_email_details: {e}")
            return None, None, None, None
    return None, None, None, None

# --- Routes ---
@app.route('/api/update_tokens', methods=['POST'])
@app.route('/api/issue_tokens', methods=['POST'])
def issue_tokens():
    data = request.get_json() or {}
    logger.info(f"Received update_tokens request: {data}")
    service = data.get('service')
    fcm_token = data.get('fcm_token')
    access_token = data.get('accessToken')
    refresh_token = data.get('refreshToken')
    
    if not service or not fcm_token or not access_token or not refresh_token:
        logger.error(f"Missing required fields: service={service}, fcm_token={fcm_token}, access_token={access_token}, refresh_token={refresh_token}")
        return jsonify({'error': 'Required fields missing'}), 400
    
    if service == 'gmail':
        try:
            creds = Credentials(
                token=access_token,
                refresh_token=refresh_token,
                token_uri='https://oauth2.googleapis.com/token',
                client_id=gmail_auth.CLIENT_ID,
                scopes=['https://www.googleapis.com/auth/gmail.modify']
            )
            service_api = build('gmail', 'v1', credentials=creds)
            profile = service_api.users().getProfile(userId='me').execute()
            email_address = profile.get('emailAddress')
            sub = gmail_auth.watch(fcm_token, access_token, refresh_token)
            gmail_token_store[fcm_token] = {
                'access_token': access_token,
                'refresh_token': refresh_token,
                'last_history_id': sub.get('historyId'),
                'email_address': email_address
            }
            save_token_stores()
            logger.info(f"Gmail tokens stored for fcm_token: {fcm_token}, email: {email_address}")
            return jsonify({'status': 'gmail_subscribed', 'email_address': email_address}), 200
        except Exception as e:
            logger.error(f"Failed to process Gmail tokens: {e}")
            return jsonify({'error': str(e)}), 500
    
    elif service == 'outlook':
        try:
            resp = requests.get(
                'https://graph.microsoft.com/v1.0/me',
                headers={'Authorization': f'Bearer {access_token}'}
            )
            if resp.status_code != 200:
                logger.error(f"Invalid Outlook access token: {resp.status_code} {resp.text}")
                return jsonify({'error': 'Invalid access token'}), 401
            profile = resp.json()
            email_address = profile.get('mail') or profile.get('userPrincipalName')
            outlook_auth.watch(fcm_token, access_token, refresh_token)
            outlook_auth.token_store[fcm_token] = {
                'access_token': access_token,
                'refresh_token': refresh_token,
                'email_address': email_address
            }
            save_token_stores()
            logger.info(f"Outlook tokens stored for fcm_token: {fcm_token}, email: {email_address}")
            return jsonify({'status': 'outlook_subscribed', 'email_address': email_address}), 200
        except Exception as e:
            logger.error(f"Failed to process Outlook tokens: {e}")
            return jsonify({'error': str(e)}), 500
    
    else:
        logger.error(f"Unsupported service: {service}")
        return jsonify({'error': 'Unsupported service'}), 400

@app.route('/pubsub_endpoint', methods=['POST'])
def pubsub_endpoint():
    logger.info(f"Received Pub/Sub request: {request.get_json()}")
    envelope = request.get_json() or {}
    data_encoded = envelope.get('message', {}).get('data', '')
    try:
        data = json.loads(base64.b64decode(data_encoded).decode())
        logger.info(f"Decoded Pub/Sub data: {data}")
    except Exception as e:
        logger.error(f"Failed to decode Pub/Sub data: {e}")
        return jsonify({'status': 'invalid_data'}), 400
    email_addr = data.get('emailAddress')
    history_id = str(data.get('historyId'))
    if history_id in processed_history_ids:
        return jsonify({'status': 'duplicate'}), 200
    processed_history_ids.add(history_id)
    target = next(
        (tok for tok, info in gmail_token_store.items() if info.get('email_address') == email_addr),
        None
    )
    if not target:
        logger.warning(f"No Gmail token for email: {email_addr}")
        return jsonify({'status': 'no_gmail_token'}), 200
    subject, body, sender = get_gmail_email_details(target, history_id)
    if not subject:
        logger.info(f"No new Gmail message for history_id: {history_id}")
        return jsonify({'status': 'no_new_message'}), 200
    fcm_service.send_push(
        target,
        f"{sender} - {subject}",
        body[:200],
        data={'subject': subject, 'body': body, 'sender': sender, 'messageId': history_id}
    )
    return jsonify({'status': 'gmail_pushed'}), 200

@app.route('/outlook_webhook', methods=['GET', 'POST'])
def outlook_webhook():
    logger.info(f"Received Outlook webhook request: method={request.method}, args={request.args}, headers={request.headers}")
    validation = request.args.get('validationToken')
    if validation:
        logger.info(f"Outlook webhook validation token: {validation}")
        return validation, 200, {'Content-Type': 'text/plain'}
    
    # Webhook notification processing
    try:
        payload = request.get_json(silent=True) or {}
        logger.info(f"Outlook webhook payload: {payload}")
    except Exception as e:
        logger.error(f"Failed to parse webhook payload: {e}")
        return jsonify({'status': 'invalid_payload'}), 400
    
    for note in payload.get('value', []):
        state_id = note.get('clientState')
        msg_id = note.get('resourceData', {}).get('id')
        if not state_id or not msg_id:
            logger.warning(f"Missing state_id or msg_id: {note}")
            continue
        try:
            subj, body, sender, fcm_tok = get_outlook_email_details(state_id, msg_id)
            if not subj:
                logger.info(f"No new Outlook message for msg_id: {msg_id}")
                continue
            is_critical = '긴급' in subj or '긴급' in body
            fcm_service.send_push(
                fcm_tok,
                f"{sender} - {subj}",
                body[:200],
                data={
                    'subject': subj,
                    'body': body,
                    'sender': sender,
                    'messageId': msg_id,
                    'mailData': json.dumps({'subject': subj, 'body': body}),
                    'isCritical': str(is_critical).lower()
                }
            )
            logger.info(f"Outlook push sent for msg_id: {msg_id}")
        except Exception as e:
            logger.error(f"Failed to process Outlook webhook: {e}")
    return jsonify({'status': 'outlook_pushed'}), 200

if __name__ == '__main__':
    logger.info(f"Starting server on 127.0.0.1:5000 (NGROK_URL={os.getenv('NGROK_URL')})")
    load_token_stores()
    # Flask 内장 서버는 디버그 OFF, 로컬 인터페이스에만 바인딩
    app.run(host='127.0.0.1',
            port=int(os.getenv('PORT', 5000)),
            debug=False)
