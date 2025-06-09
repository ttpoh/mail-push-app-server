import os
import json
import base64
import pickle
import logging
import datetime
import time
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
from outlook_email_util import get_outlook_email_details  # 새 모듈 임포트
import redis  # Redis 추가

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
    notify_url=f"{os.getenv('NGROK_URL', 'https://mail-push.xtect.net')}/outlook_webhook"
)
redis_client = redis.Redis(host='localhost', port=6379, db=0)

def load_token_stores():
    global gmail_token_store
    try:
        with open(GMAIL_STORE_FILE, 'rb') as f:
            gmail_token_store = pickle.load(f)
            logger.info(f"Loaded gmail_token_store with {len(gmail_token_store)} entries")
    except FileNotFoundError:
        logger.info("Gmail store not found, initializing empty store")
        gmail_token_store = {}
    except Exception as e:
        logger.error(f"Failed to load Gmail store: {e}")
        gmail_token_store = {}

    try:
        with open(OUTLOOK_STORE_FILE, 'rb') as f:
            data = pickle.load(f)
            outlook_auth.token_store = data.get('token_store', {})
            outlook_auth.client_state_to_fcm = data.get('client_state_to_fcm', {})
            logger.info(f"Loaded outlook_token_store with {len(outlook_auth.token_store)} entries")
            logger.info(f"Loaded client_state_to_fcm with {len(outlook_auth.client_state_to_fcm)} entries")
            logger.debug(f"client_state_to_fcm content: {outlook_auth.client_state_to_fcm}")
    except FileNotFoundError:
        logger.info("Outlook store not found, initializing empty store")
        outlook_auth.token_store = {}
        outlook_auth.client_state_to_fcm = {}
    except Exception as e:
        logger.error(f"Failed to load Outlook store: {e}")
        outlook_auth.token_store = {}
        outlook_auth.client_state_to_fcm = {}

def save_token_stores():
    try:
        with open(GMAIL_STORE_FILE, 'wb') as f:
            pickle.dump(gmail_token_store, f)
        with open(OUTLOOK_STORE_FILE, 'wb') as f:
            pickle.dump({
                'token_store': outlook_auth.token_store,
                'client_state_to_fcm': outlook_auth.client_state_to_fcm
            }, f)
        logger.info("Token stores saved successfully")
        logger.debug(f"Saved client_state_to_fcm: {outlook_auth.client_state_to_fcm}")
    except Exception as e:
        logger.error(f"Failed to save token stores: {e}")
        raise

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
# def get_outlook_email_details(fcm_token, message_id, user_id, retries=3):
#     for attempt in range(retries):
#         try:
#             token = outlook_auth.get_valid_token(fcm_token)
#             url = f'https://graph.microsoft.com/v1.0/users/{user_id}/messages/{message_id}'
#             headers = {'Authorization': f'Bearer {token}'}
#             resp = requests.get(url, headers=headers)
#             resp.raise_for_status()
#             msg = resp.json()
#             subject = msg.get('subject', 'No Subject')
#             sender = msg.get('from', {}).get('emailAddress', {}).get('address', 'Unknown Sender')
#             content = msg.get('body', {}).get('content', '')
#             if msg.get('body', {}).get('contentType') == 'html':
#                 body = BeautifulSoup(content, 'html.parser').get_text()
#             else:
#                 body = content
#             if message_id in processed_message_ids:
#                 return None, None, None, None
#             processed_message_ids.add(message_id)
#             return subject, body, sender, fcm_token
#         except requests.HTTPError as e:
#             logger.error(f"Failed to fetch Outlook email details (attempt {attempt + 1}): {e}")
#             if e.response.status_code == 401 and attempt < retries - 1:
#                 outlook_auth._refresh_token(fcm_token)
#                 continue
#             return None, None, None
#         except Exception as e:
#             logger.error(f"Unexpected error in get_outlook_email_details: {e}")
#             return None, None, None
#     return None, None, None


# --- Routes ---
@app.route('/api/update_tokens', methods=['POST'])
def update_tokens():
    data = request.get_json() or {}
    logger.info(f"Received update_tokens request: {data}")
    service = data.get('service')
    fcm_token = data.get('fcm_token')
    access_token = data.get('accessToken')
    refresh_token = data.get('refreshToken')
    client_state = data.get('clientState') or data.get('client_state')

    if not service or not fcm_token or not access_token or not refresh_token:
        logger.error(f"Missing required fields: service={service}, fcm_token={fcm_token}, "
                     f"access_token={access_token}, refresh_token={refresh_token}")
        return jsonify({'error': 'Required fields missing'}), 400
    if service == 'outlook' and not client_state:
        logger.error(f"Missing client_state for Outlook: {data}")
        return jsonify({'error': 'client_state is required for Outlook'}), 400

    if service == 'gmail':
        try:
            creds = Credentials(
                token=access_token,
                refresh_token=refresh_token,
                token_uri='https://oauth2.googleapis.com/token',
                client_id=gmail_auth.CLIENT_ID,
                scopes=['https://www.googleapis.com/auth/gmail.modify']
            )
            service_api = build('gmail', 'v1', credentials=creds, cache_discovery=False)
            profile = service_api.users().getProfile(userId='me').execute()
            email_address = profile.get('emailAddress')
            sub = gmail_auth.watch(fcm_token, access_token, refresh_token)
            gmail_token_store[fcm_token] = {
                'access_token': access_token,
                'refresh_token': refresh_token,
                'last_history_id': sub.get('historyId'),
                'email_address': email_address,
            }
            save_token_stores()
            logger.info(f"Gmail tokens stored for fcm_token: {fcm_token}, email: {email_address}")
            return jsonify({'status': 'gmail_subscribed', 'email_address': email_address}), 200
        except Exception as e:
            logger.error(f"Failed to process Gmail tokens: {e}", exc_info=True)
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

            with outlook_auth._lock:
                # 기존 client_state에 연결된 다른 fcm_token 제거
                for key, entry in list(outlook_auth.token_store.items()):
                    if entry.get('client_state') == client_state and key != fcm_token:
                        logger.info(f"Removing old fcm_token for client_state {client_state}: {key}")
                        del outlook_auth.token_store[key]
                        if client_state in outlook_auth.client_state_to_fcm:
                            del outlook_auth.client_state_to_fcm[client_state]
   
                outlook_auth.client_state_to_fcm[client_state] = fcm_token

                outlook_auth.token_store[fcm_token] = {
                    'access_token': access_token,
                    'refresh_token': refresh_token,
                    'email_address': email_address,
                    'client_state': client_state,
                    'expires_at': time.time() + 3600 - 60
                }
                save_token_stores()

            logger.info(f"Outlook tokens stored for fcm_token: {fcm_token}, email: {email_address}, client_state: {client_state}")
            return jsonify({'status': 'outlook_tokens_updated', 'email_address': email_address, 'tokens_stored': True}), 200
        except Exception as e:
            logger.error(f"Failed to process Outlook tokens: {e}", exc_info=True)
            return jsonify({'error': str(e)}), 500

    else:
        logger.error(f"Unsupported service: {service}")
        return jsonify({'error': 'Unsupported service'}), 400

@app.route('/api/create_subscription', methods=['POST'])
def create_subscription():
    data = request.get_json() or {}
    auth = request.headers.get('Authorization', '')
    access_token = None
    if auth.startswith('Bearer '):
        access_token = auth.split(None, 1)[1]

    resource = data.get('resource')
    change_type = data.get('changeType') or data.get('change_type')
    notification_url = data.get('notificationUrl') or data.get('notification_url')
    client_state = data.get('clientState') or data.get('client_state')
    fcm_token = data.get('fcm_token')

    if not all([access_token, resource, change_type, notification_url, client_state, fcm_token]):
        logger.error(f"Missing required fields: access_token={bool(access_token)}, resource={resource}, "
                     f"change_type={change_type}, notification_url={notification_url}, client_state={client_state}, fcm_token={fcm_token}")
        return jsonify({'error': 'Required fields missing'}), 400

    try:
        with outlook_auth._lock:
            # 동일 email_address 또는 client_state를 가진 기존 구독 삭제
            existing_fcm_tokens = []
            for key, entry in list(outlook_auth.token_store.items()):
                if (entry.get('client_state') == client_state or 
                    (entry.get('email_address') == outlook_auth.token_store.get(fcm_token, {}).get('email_address') and key != fcm_token)):
                    existing_fcm_tokens.append(key)

            for existing_fcm in existing_fcm_tokens:
                logger.info(f"Removing old fcm_token for client_state {client_state} or same email: {existing_fcm}")
                if outlook_auth.token_store.get(existing_fcm, {}).get('subscription_id'):
                    headers = {'Authorization': f'Bearer {outlook_auth.token_store[existing_fcm]["access_token"]}'}
                    try:
                        resp = requests.delete(
                            f'https://graph.microsoft.com/v1.0/subscriptions/{outlook_auth.token_store[existing_fcm]["subscription_id"]}',
                            headers=headers,
                            timeout=10
                        )
                        if resp.status_code == 204:
                            logger.info(f"Deleted old subscription {outlook_auth.token_store[existing_fcm]['subscription_id']}")
                    except requests.exceptions.RequestException as e:
                        logger.error(f"Failed to delete subscription {outlook_auth.token_store[existing_fcm]['subscription_id']}: {e}")
                del outlook_auth.token_store[existing_fcm]
                if outlook_auth.client_state_to_fcm.get(client_state) == existing_fcm:
                    del outlook_auth.client_state_to_fcm[client_state]


        # fcm_token이 없으면 임시 항목 추가
        if fcm_token not in outlook_auth.token_store:
            logger.warning(f"fcm_token {fcm_token} not found in token_store. Adding fallback entry.")
            outlook_auth.token_store[fcm_token] = {
                'access_token': access_token,
                'refresh_token': None,
                'client_state': client_state,
                'email_address': None,
                'expires_at': time.time() + 3600 - 60
            }
            outlook_auth.client_state_to_fcm[client_state] = fcm_token

        # 구독 생성
        sub = outlook_auth.watch(
            fcm_token=fcm_token,
            access_token=access_token,
            resource=resource,
            change_type=change_type,
            notification_url=notification_url,
            client_state=client_state
        )
        subscription_id = sub.get('id')

        outlook_auth.token_store[fcm_token].update({
            'subscription_id': subscription_id,
            'resource': resource
        })
        save_token_stores()

        logger.info(f"Subscription created for fcm_token: {fcm_token}, client_state: {client_state}, subscriptionId: {subscription_id}")
        return jsonify({'status': 'subscription_created', 'subscriptionId': subscription_id}), 200

    except requests.exceptions.Timeout:
        logger.error("Timeout while creating subscription with Microsoft Graph API")
        return jsonify({'error': 'Subscription creation timed out'}), 500
    except requests.exceptions.HTTPError as e:
        logger.error(f"Microsoft Graph API error: {e.response.status_code} {e.response.text}")
        return jsonify({'error': 'Failed to create subscription', 'detail': e.response.text}), 500
    except Exception as e:
        logger.error(f"Failed to create subscription: {e}", exc_info=True)
        return jsonify({'error': 'Failed to create subscription', 'detail': str(e)}), 500

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

def ensure_token_store_loaded():
    if not outlook_auth.client_state_to_fcm:
        logger.warning("Reloading token store because client_state_to_fcm is empty")
        load_token_stores()

@app.route('/outlook_webhook', methods=['GET', 'POST'])
def outlook_webhook():
    ensure_token_store_loaded()  # 여기서 보장
    logger.info(f"Received Outlook webhook request: method={request.method}, args={request.args}, headers={request.headers}")
    logger.info(f"Current client_state_to_fcm keys: {list(outlook_auth.client_state_to_fcm.keys())}")

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
        client_state = note.get('clientState')
        msg_id = note.get('resourceData', {}).get('id')
        resource = note.get('resource')  # 'Users/{user_id}/Messages/{message_id}'
        user_id = resource.split('/')[1] if resource else None

        if not client_state or not msg_id or not user_id:
            logger.warning(f"Missing required info: {note}")
            continue
        try:
            fcm_tok = outlook_auth.get_fcm_token_by_client_state(client_state)
            if not fcm_tok:
                logger.error(f"No fcm_token found for client_state: {client_state}")
                continue

            # get_outlook_email_details 호출 수정
            subj, body, sender, fcm_token = get_outlook_email_details(
                client_state=client_state,
                message_id=msg_id,
                user_id=user_id,
                token_store=outlook_auth.token_store,  # token_store 전달
                processed_message_ids=processed_message_ids,  # processed_message_ids 전달
                redis_client=redis_client,  # Redis 클라이언트 전달
                outlook_auth=outlook_auth
            )
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
    logger.info(f"Starting server on 0.0.0.0:5000 (NGROK_URL={os.getenv('NGROK_URL')})")
    load_token_stores()
    # Flask 内장 서버는 디버그 OFF, 로컬 인터페이스에만 바인딩
    # app.run(host='0.0.0.0',
    #         port=int(os.getenv('PORT', 5000)),
    #         debug=False)