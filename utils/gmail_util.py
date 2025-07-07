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
            # GmailToken에서 토큰 조회 및 현재 계정 이메일 주소 확인
            entry = db.query(GmailToken).filter_by(fcm_token=fcm_token).first()
            if not entry:
                logger.error(f"No Gmail tokens for fcm_token: {fcm_token}")
                return None, None, None
            current_email = entry.email_address  # GmailToken 모델에 email_address 필드가 있다고 가정
            logger.info(f"Token details for fcm_token: {fcm_token}, access_token: {entry.access_token}, refresh_token: {entry.refresh_token}, email: {current_email}")

            # GmailAuth를 통해 유효한 자격 증명 획득
            try:
                creds = gmail_auth._get_credentials(entry)
            except Exception as e:
                logger.error(f"Failed to get valid credentials for fcm_token: {fcm_token}, error: {e}")
                return None, None, None

            # Gmail API 클라이언트 생성
            service = build('gmail', 'v1', credentials=creds, cache_discovery=False)

            # Gmail 히스토리 조회
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

            # 히스토리 처리
            processed = False
            for record in history.get('history', []):
                for added in record.get('messagesAdded', []):
                    msg_id = added['message']['id']

                    # 전역 중복 체크 (Redis)
                    redis_key = f"gmail_msg:{msg_id}"
                    if redis_client and redis_client.get(redis_key):
                        logger.info(f"[Duplicate] Message {msg_id} already processed (from Redis)")
                        continue

                    # 메일 정보 요청
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

                    # To 헤더에서 이메일 주소 파싱 (현재 계정만 필터링)
                    email_addresses = []
                    for recipient in to_header.replace('\n', '').split(','):
                        email = extract_email_address(recipient.strip())
                        if email == current_email:  # 현재 계정만 처리
                            email_addresses.append(email)

                    if not email_addresses:
                        logger.warning(f"No valid email address found for current account {current_email} in To header")
                        continue

                    # sender, subject, body 추출
                    sender = next((h['value'] for h in headers if h['name'] == 'From'), 'Unknown Sender')
                    subject = next((h['value'] for h in headers if h['name'] == 'Subject'), 'No Subject')
                    body = extract_body(msg['payload']) or 'No Body'

                    # 현재 계정에 대한 레코드만 저장
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

                    # 중복 처리 후 Redis에 저장 (유효 기간 24시간)
                    if redis_client and processed:
                        redis_client.setex(redis_key, 86400, "1")

            # 모든 히스토리 처리 후 마지막 히스토리 ID 업데이트
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