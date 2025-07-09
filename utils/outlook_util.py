import requests
from bs4 import BeautifulSoup
import logging
from typing import Optional, Tuple
from models.outlook_mail import OutlookEmail
from models.outlook_users import OutlookToken
from infra.db import SessionLocal
from datetime import datetime
import re
from urllib.parse import unquote

logger = logging.getLogger(__name__)

def get_outlook_email_details(
    client_state: str,
    message_id: str,
    user_id: str,
    processed_message_ids: set,  # 사용되지 않음, 호환성을 위해 유지
    outlook_auth,
    redis_client=None,
    retries: int = 3
) -> Tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
    # Redis를 사용한 중복 확인
    if redis_client:
        redis_key = f"outlook_msg:{message_id}"
        if redis_client.get(redis_key):
            logger.info(f"[중복] 메시지 {message_id} 이미 처리됨 (Redis에서)")
            return None, None, None, None
        redis_client.setex(redis_key, 3600, "1")  # 1시간 TTL

    with SessionLocal() as db:
        try:
            token_record = db.query(OutlookToken).filter_by(client_state=client_state).one()
            fcm_token = token_record.fcm_token
            email_address = token_record.email_address or user_id
        except Exception as e:
            logger.error(f"client_state에 대한 OutlookToken 없음: {client_state}: {e}")
            return None, None, None, None

        for attempt in range(retries):
            try:
                token = outlook_auth.get_valid_token(fcm_token)
                if not token:
                    logger.error(f"fcm_token에 대한 유효한 토큰 없음: {fcm_token}")
                    return None, None, None, None

                url = f'https://graph.microsoft.com/v1.0/users/{email_address}/messages/{message_id}'
                headers = {'Authorization': f'Bearer {token}'}
                logger.info(f"메시지 세부 정보 가져오기: message_id={message_id}, email_address={email_address}, 시도: {attempt + 1}")
                resp = requests.get(url, headers=headers, timeout=10)
                resp.raise_for_status()
                msg = resp.json()

                odata_ctx = msg.get('@odata.context', '')
                m = re.search(r"users\('(.+?)'\)", odata_ctx)
                user_email = unquote(m.group(1)) if m else email_address

                subject = msg.get('subject', '제목 없음')
                sender = msg.get('from', {}).get('emailAddress', {}).get('address', '알 수 없는 발신자')
                content = msg.get('body', {}).get('content', '')
                content_type = msg.get('body', {}).get('contentType', 'text')

                try:
                    body = BeautifulSoup(content, 'html.parser').get_text(separator=' ', strip=True) if content_type == 'html' else content
                except Exception as e:
                    logger.error(f"이메일 본문 파싱 실패: {e}")
                    body = content

                # 데이터베이스에 이메일 저장
                if not db.query(OutlookEmail).filter_by(message_id=message_id).first():
                    email = OutlookEmail(
                        message_id=message_id,
                        email_address=user_email,
                        subject=subject,
                        sender=sender,
                        body=body,
                        received_at=datetime.utcnow()
                    )
                    db.add(email)
                    db.commit()
                    logger.info(f"데이터베이스에 이메일 저장됨: {message_id}")

                return subject, body, sender, fcm_token

            except requests.HTTPError as e:
                logger.error(f"HTTP 오류 (시도 {attempt + 1}): {e}")
                if e.response.status_code == 401 and attempt < retries - 1:
                    continue  # get_valid_token이 이미 갱신 처리
                return None, None, None, None
            except Exception as e:
                logger.error(f"예상치 못한 오류: {e}")
                return None, None, None, None

    return None, None, None, None