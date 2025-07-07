# ✅ get_outlook_email_details 함수 (token_store 제거 및 DB 저장 포함)
import requests
from bs4 import BeautifulSoup
import logging
from typing import Optional, Tuple
from models.outlook_mail import OutlookEmail
from models.outlook_users import OutlookToken
from infra.db import SessionLocal
from sqlalchemy.orm.exc import NoResultFound
from datetime import datetime

logger = logging.getLogger(__name__)

def get_outlook_email_details(
    client_state: str,
    message_id: str,
    user_id: str,
    processed_message_ids: set,
    outlook_auth,
    redis_client=None,
    retries: int = 3
) -> Tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:

    # 중복 메시지 확인
    if redis_client:
        redis_key = f"outlook_msg:{message_id}"
        if redis_client.get(redis_key):
            logger.info(f"[Duplicate] Message {message_id} already processed (from Redis)")
            return None, None, None, None
        else:
            redis_client.setex(redis_key, 3600, "1")  # 중복 방지를 위해 1시간 TTL 설정
    else:
        if message_id in processed_message_ids:
            logger.info(f"[Duplicate] Message {message_id} already processed (from memory)")
            return None, None, None, None
        processed_message_ids.add(message_id)

    with SessionLocal() as db:
        try:
            token_record = db.query(OutlookToken).filter_by(client_state=client_state).one()
            fcm_token = token_record.fcm_token
            user_id = token_record.email_address
        except NoResultFound:
            logger.error(f"No OutlookToken found for client_state: {client_state}")
            return None, None, None, None

    for attempt in range(retries):
        try:
            token = outlook_auth.get_valid_token(fcm_token)
            if not token:
                logger.error(f"No valid token for fcm_token: {fcm_token}")
                return None, None, None, None

            url = f'https://graph.microsoft.com/v1.0/users/{user_id}/messages/{message_id}'
            headers = {'Authorization': f'Bearer {token}'}
            logger.info(f"Fetching email details for message_id: {message_id}, user_id: {user_id}, attempt: {attempt + 1}")
            resp = requests.get(url, headers=headers)
            resp.raise_for_status()
            msg = resp.json()
            logger.info(f"outlook msg {msg}")

            subject = msg.get('subject', 'No Subject')
            email_address = msg.get('toRecipients', [{}])[0].get('emailAddress', {}).get('address', 'Unknown toRecipients')
            sender = msg.get('from', {}).get('emailAddress', {}).get('address', 'Unknown Sender')
            content = msg.get('body', {}).get('content', '')
            content_type = msg.get('body', {}).get('contentType', 'text')

            try:
                if content_type == 'html':
                    body = BeautifulSoup(content, 'html.parser').get_text(separator=' ', strip=True)
                else:
                    body = content
            except Exception as e:
                logger.error(f"Failed to parse email body: {e}")
                body = content

            if redis_client:
                if redis_client.sismember('processed_message_ids', message_id):
                    logger.info(f"Message already processed: {message_id}")
                    return None, None, None, None
                redis_client.sadd('processed_message_ids', message_id)
            else:
                if message_id in processed_message_ids:
                    logger.info(f"Message already processed: {message_id}")
                    return None, None, None, None
                processed_message_ids.add(message_id)

            # ✅ Save email to DB
            with SessionLocal() as db:
                if not db.query(OutlookEmail).filter_by(message_id=message_id).first():
                    email = OutlookEmail(
                        message_id=message_id,
                        email_address=email_address,
                        subject=subject,
                        sender=sender,
                        body=body,
                        received_at=datetime.utcnow()
                    )
                    db.add(email)
                    db.commit()
                    logger.info(f"Email saved to DB: {message_id}")

            return subject, body, sender, fcm_token

        except requests.HTTPError as e:
            logger.error(f"HTTP error (attempt {attempt + 1}): {e}")
            if e.response.status_code == 401 and attempt < retries - 1:
                try:
                    outlook_auth.refresh_token(fcm_token)
                except Exception as refresh_error:
                    logger.error(f"Failed to refresh token: {refresh_error}")
                    return None, None, None, None
                continue
            return None, None, None, None

        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            return None, None, None, None

    return None, None, None, None