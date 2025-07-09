import base64
import logging
from bs4 import BeautifulSoup
from datetime import datetime
from flask import jsonify
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from auth.gmail_auth import GmailAuth
from models.gmail_users import GmailToken
from models.gmail_mail import GmailEmail
from infra.db import SessionLocal
import re

logger = logging.getLogger(__name__)
gmail_auth = GmailAuth()

# 필터링 키워드
KEYWORDS = ['긴급', '미팅']

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
        return BeautifulSoup(html, 'html.parser').get_text(separator=' ', strip=True)
    return ''

def extract_email_address(header_value):
    email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    match = re.search(email_pattern, header_value)
    return match.group(0) if match else None

def get_gmail_email_details(fcm_token: str, history_id: str, redis_client=None, retries=3):
    with SessionLocal() as db:
        try:
            entry = db.query(GmailToken).filter_by(fcm_token=fcm_token).first()
            if not entry:
                logger.error(f"No Gmail tokens for fcm_token: {fcm_token}")
                return None, None, None
            current_email = entry.email_address
            logger.info(f"Token details for fcm_token: {fcm_token}, access_token: {entry.access_token}, refresh_token: {entry.refresh_token}, email: {current_email}")

            try:
                creds = gmail_auth._get_credentials(entry)
            except Exception as e:
                logger.error(f"Failed to get valid credentials for fcm_token: {fcm_token}, error: {e}")
                return None, None, None

            service = build('gmail', 'v1', credentials=creds, cache_discovery=False)

            try:
                history = service.users().history().list(
                    userId='me',
                    startHistoryId=entry.last_history_id or '1'
                ).execute()
            except HttpError as e:
                logger.error(f"HTTP Error fetching Gmail history for fcm_token: {fcm_token}, error: {e}")
                if e.resp.status == 401:
                    logger.error("Authentication error: Check credentials or refresh token.")
                return None, None, None
            except Exception as e:
                logger.error(f"Failed to fetch Gmail history for fcm_token: {fcm_token}, error: {e}")
                return None, None, None

            processed = False
            for record in history.get('history', []):
                for added in record.get('messagesAdded', []):
                    msg_id = added['message']['id']
                    redis_key = f"gmail_msg:{msg_id}"
                    if redis_client and redis_client.get(redis_key):
                        logger.info(f"[Duplicate] Message {msg_id} already processed (from Redis)")
                        continue

                    try:
                        msg = service.users().messages().get(
                            userId='me',
                            id=msg_id,
                            format='full'
                        ).execute()
                    except HttpError as e:
                        logger.error(f"Failed to fetch message {msg_id}: {e}")
                        continue

                    headers = msg['payload'].get('headers', [])
                    to_header = next((h['value'] for h in headers if h['name'] == 'To'), None)
                    if not to_header:
                        return jsonify({'error': 'No valid To header found'}), 400

                    email_addresses = []
                    for recipient in to_header.replace('\n', '').split(','):
                        email = extract_email_address(recipient.strip())
                        if email == current_email:
                            email_addresses.append(email)

                    if not email_addresses:
                        logger.warning(f"No valid email address found for current account {current_email} in To header")
                        continue

                    sender = next((h['value'] for h in headers if h['name'] == 'From'), 'Unknown Sender')
                    subject = next((h['value'] for h in headers if h['name'] == 'Subject'), 'No Subject')
                    body = extract_body(msg['payload']) or 'No Body'

                    # 키워드 필터링
                    if not any(keyword in subject + " " + body for keyword in KEYWORDS):
                        logger.info(f"Skipped email (no keyword match): {subject}")
                        continue

                    if not db.query(GmailEmail).filter_by(message_id=msg_id, email_address=current_email).first():
                        email = GmailEmail(
                            message_id=msg_id,
                            email_address=current_email,
                            sender=sender,
                            subject=subject,
                            body=body,
                            received_at=datetime.utcnow()
                        )
                        db.add(email)
                        logger.info(f"Gmail saved to DB: {msg_id} for {current_email}")
                        processed = True
                    else:
                        logger.info(f"Gmail {msg_id} for {current_email} already exists in DB")

                    if redis_client and processed:
                        redis_client.setex(redis_key, 86400, "1")

            if history.get('history'):
                entry.last_history_id = max(int(h['id']) for h in history['history'])
                db.commit()
                return subject, body, sender if processed else (None, None, None)
            return None, None, None

        except Exception as e:
            logger.error(f"Unexpected error in get_gmail_email_details for fcm_token: {fcm_token}, error: {e}")
            db.rollback()
            return None, None, None
        finally:
            db.close()
