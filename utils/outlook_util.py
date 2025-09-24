import logging
import re
from datetime import datetime
from typing import Optional, Tuple
from urllib.parse import unquote

import requests
from bs4 import BeautifulSoup

from infra.db import SessionLocal
from models.outlook_mail import OutlookEmail
from models.outlook_users import OutlookToken
from models.gmail_rules import MailRule, ConditionType  # ✅ 공용 룰 모델 재사용

logger = logging.getLogger(__name__)

_EMAIL_RE = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')

def _extract_email(header_value: Optional[str]) -> Optional[str]:
    if not header_value:
        return None
    m = _EMAIL_RE.search(header_value)
    return m.group(0).lower() if m else None

def _extract_text(body: str, content_type: str) -> str:
    """HTML이면 텍스트로 변환, 아니면 원문 그대로."""
    if not body:
        return ''
    try:
        if content_type and content_type.lower() == 'html':
            return BeautifulSoup(body, 'html.parser').get_text(separator=' ', strip=True)
        return body
    except Exception as e:
        logger.error(f"본문 파싱 실패: {e}")
        return body

def _matches_condition(condition, subject: str, body: str, sender_header: str) -> bool:
    """Gmail util의 로직과 동일하게 조건 매칭."""
    subj = (subject or '').lower()
    body_l = (body or '').lower()
    combined = f"{subj} {body_l}"
    sender_email = _extract_email(sender_header) or ''

    for kw in condition.keywords:
        term = getattr(kw, 'keyword', '').lower()
        if not term:
            continue
        if condition.type == ConditionType.SUBJECT_CONTAINS and term in combined:
            return True
        if condition.type == ConditionType.BODY_CONTAINS and term in body_l:
            return True
        if condition.type == ConditionType.FROM_SENDER and term in sender_email:
            return True
    return False


def get_outlook_email_details(
    client_state: str,
    message_id: str,
    user_id: str,
    processed_message_ids: set,  # 사용 안 함(하위호환 유지)
    outlook_auth,
    redis_client=None,
    retries: int = 3
) -> Tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
    """
    반환: (subject, body, sender, fcm_token)
    - 룰과 매칭된 경우에만 (subject, body, sender, fcm_token) 반환/저장
    - 매칭 안 되면 (None, None, None, None)
    """

    with SessionLocal() as db:
        # 1) client_state → 토큰/기본 이메일 조회
        try:
            token_record = db.query(OutlookToken).filter_by(client_state=client_state).one()
            fcm_token = token_record.fcm_token
            # Webhook payload의 user_id가 비워질 수 있으므로 DB의 email_address 우선
            base_email = (token_record.email_address or user_id or '').lower()
        except Exception as e:
            logger.error(f"client_state에 대한 OutlookToken 없음: {client_state}: {e}")
            return None, None, None, None

        # 2) M365 Graph에서 메시지 조회 (리트라이 포함)
        for attempt in range(retries):
            try:
                access_token = outlook_auth.get_valid_token(fcm_token)
                if not access_token:
                    logger.error(f"fcm_token에 대한 유효 토큰 없음: {fcm_token}")
                    return None, None, None, None

                url = f'https://graph.microsoft.com/v1.0/users/{base_email}/messages/{message_id}'
                headers = {'Authorization': f'Bearer {access_token}'}
                logger.info(f"메시지 세부 정보 가져오기: message_id={message_id}, base_email={base_email}, 시도: {attempt + 1}")

                resp = requests.get(url, headers=headers, timeout=10)
                resp.raise_for_status()
                msg = resp.json()

                # 실제 사용자 메일주소 추출 (context에 들어있는 경우가 많음)
                odata_ctx = msg.get('@odata.context', '')
                m = re.search(r"users\('(.+?)'\)", odata_ctx)
                owner_email = (unquote(m.group(1)) if m else base_email).lower()

                subject = msg.get('subject', 'No Subject')
                sender = msg.get('from', {}).get('emailAddress', {}).get('address', '') or 'Unknown Sender'
                content = msg.get('body', {}).get('content', '')
                content_type = msg.get('body', {}).get('contentType', 'text')
                body_text = _extract_text(content, content_type)

                # 3) 룰 로드 후 매칭 검사 (소유자 이메일 기준)
                rules = db.query(MailRule).filter_by(owner_email=owner_email, enabled=True).all()
                matched = False
                for rule in rules:
                    for condition in rule.conditions:
                        if _matches_condition(condition, subject, body_text, sender):
                            matched = True
                            # 저장(중복 체크)
                            if not db.query(OutlookEmail).filter_by(message_id=message_id, email_address=owner_email).first():
                                db.add(OutlookEmail(
                                    message_id=message_id,
                                    email_address=owner_email,
                                    subject=subject,
                                    sender=sender,
                                    body=body_text,
                                    received_at=datetime.utcnow()
                                ))
                                try:
                                    db.commit()
                                    logger.info(f"[저장] OutlookEmail message_id={message_id}, owner={owner_email}")
                                except Exception as e:
                                    logger.warning(f"OutlookEmail flush 실패: {e}")
                            # stop_further_rules면 즉시 중단
                            if rule.stop_further_rules:
                                break
                    if matched and rule.stop_further_rules:
                        break

                if not matched:
                    # 룰에 매칭되지 않으면 아무것도 리턴/저장하지 않음
                    return None, None, None, None
                
                    # ✅ Redis 중복 방지
                if redis_client:
                    redis_key = f"outlook_msg:{message_id}"
                    if redis_client.get(redis_key):
                        logger.info(f"[중복] 메시지 {message_id} 이미 처리됨 (Redis)")
                        return None, None, None, None
                    try:
                        redis_client.setex(redis_key, 3600, "1")  # 1시간 TTL
                    except Exception:
                        pass

                # 4) 최종 반환 (매칭된 경우)
                return subject, body_text, sender, fcm_token

            except requests.HTTPError as e:
                logger.error(f"HTTP 오류 (시도 {attempt + 1}): {e}")
                if e.response.status_code == 401 and attempt < retries - 1:
                    # get_valid_token이 내부에서 refresh 후 재시도 여지
                    continue
                return None, None, None, None
            except Exception as e:
                logger.error(f"예상치 못한 오류: {e}")
                return None, None, None, None

    return None, None, None, None


