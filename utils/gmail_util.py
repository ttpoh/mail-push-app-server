import base64
import logging
import re
from datetime import datetime

from bs4 import BeautifulSoup
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from sqlalchemy.exc import IntegrityError

from auth.gmail_auth import GmailAuth
from infra.db import SessionLocal
from models.gmail_users import GmailToken
from models.gmail_mail import GmailEmail
from models.gmail_rules import MailRule, ConditionType

logger = logging.getLogger(__name__)
gmail_auth = GmailAuth()

_EMAIL_RE = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')


def _extract_body(part):
    if 'parts' in part:
        for p in part['parts']:
            txt = _extract_body(p)
            if txt:
                return txt
    mt = part.get('mimeType', '')
    data = part.get('body', {}).get('data')
    if data:
        try:
            decoded = base64.urlsafe_b64decode(data).decode('utf-8', errors='ignore')
        except Exception:
            return ''
        if mt == 'text/plain':
            return decoded
        if mt == 'text/html':
            return BeautifulSoup(decoded, 'html.parser').get_text(separator=' ', strip=True)
    return ''


def _extract_email(header_value):
    if not header_value:
        return None
    m = _EMAIL_RE.search(header_value)
    return m.group(0).lower() if m else None


def _matches_condition(condition, subject, body, sender):
    combined = f"{subject} {body}".lower()
    sender_email = _extract_email(sender) or ''
    for kw in condition.keywords:
        term = getattr(kw, 'keyword', '').lower()
        if condition.type == ConditionType.SUBJECT_CONTAINS and term in combined:
            return True
        if condition.type == ConditionType.BODY_CONTAINS and term in body.lower():
            return True
        if condition.type == ConditionType.FROM_SENDER and term in sender_email:
            return True
    return False


def get_gmail_email_details(fcm_token: str, history_id: str, redis_client=None):
    """
    반환: subject, body, sender, matched(bool), message_id (실제 처리된 메시지)
    """
    with SessionLocal() as db:
        try:
            entry = db.query(GmailToken).filter_by(fcm_token=fcm_token).first()
            if not entry:
                logger.error("No GmailToken for fcm_token=%s", fcm_token)
                return None, None, None, False, None

            creds = gmail_auth._get_credentials(entry)
            service = build('gmail', 'v1', credentials=creds, cache_discovery=False)

            try:
                history = service.users().history().list(
                    userId='me',
                    startHistoryId=entry.last_history_id or '1'
                ).execute()
            except HttpError as e:
                logger.error("History fetch failed for %s: %s", fcm_token, e)
                if getattr(e, 'resp', None) and getattr(e.resp, 'status', None) == 401:
                    logger.error("Authentication error for token %s", fcm_token)
                return None, None, None, False, None

            current_email = entry.email_address.lower()
            processed = False
            matched_flag = False
            last_subject = last_body = last_sender = None
            last_message_id = None

            for record in history.get('history', []):
                for added in record.get('messagesAdded', []):
                    msg_id = added['message']['id']
                    redis_key = f"gmail_msg:{msg_id}"
                    if redis_client and redis_client.get(redis_key):
                        continue

                    try:
                        msg = service.users().messages().get(
                            userId='me',
                            id=msg_id,
                            format='full'
                        ).execute()
                    except Exception as e:
                        logger.warning("Failed to fetch message %s: %s", msg_id, e)
                        continue

                    if 'INBOX' not in msg.get('labelIds', []):
                        continue

                    headers = {h['name'].lower(): h['value'] for h in msg['payload'].get('headers', [])}
                    to_header = headers.get('to', '')
                    if not to_header:
                        continue
                    if not any(_extract_email(r.strip()) == current_email for r in to_header.replace('\n', '').split(',')):
                        continue

                    sender = headers.get('from', 'Unknown Sender')
                    subject = headers.get('subject', 'No Subject')
                    body = _extract_body(msg['payload']) or 'No Body'

                    # 룰 체크
                    rules = db.query(MailRule).filter_by(owner_email=current_email, enabled=True).all()
                    matched = False
                    for rule in rules:
                        for condition in rule.conditions:
                            if _matches_condition(condition, subject, body, sender):
                                matched = True
                                existing = db.query(GmailEmail).filter_by(message_id=msg_id, email_address=current_email).first()
                                if not existing:
                                    email = GmailEmail(
                                        message_id=msg_id,
                                        email_address=current_email,
                                        sender=sender,
                                        subject=subject,
                                        body=body,
                                        received_at=datetime.utcnow()
                                    )
                                    db.add(email)
                                    try:
                                        db.flush()
                                        processed = True
                                        logger.info("Saved email %s for %s", msg_id, current_email)
                                    except IntegrityError:
                                        db.rollback()
                                if rule.stop_further_rules:
                                    break
                        if matched and rule.stop_further_rules:
                            break
                    if not matched:
                        continue

                    last_subject, last_body, last_sender = subject, body, sender
                    last_message_id = msg_id
                    matched_flag = True

                    if redis_client and processed:
                        try:
                            redis_client.setex(redis_key, 86400, "1")
                        except Exception:
                            pass

            if history.get('history'):
                try:
                    entry.last_history_id = max(int(h['historyId']) for h in history['history'])
                except Exception:
                    pass
                db.commit()
                if matched_flag and last_subject:
                    return last_subject, last_body, last_sender, True, last_message_id
            return None, None, None, False, None

        except Exception as e:
            logger.error("Unexpected in get_gmail_email_details: %s", e)
            db.rollback()
            return None, None, None, False, None
        finally:
            db.close()
