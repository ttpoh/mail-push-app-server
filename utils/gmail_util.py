import base64
import logging
import re
from datetime import datetime

from bs4 import BeautifulSoup
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import joinedload

from auth.gmail_auth import GmailAuth
from infra.db import SessionLocal
from models.gmail_users import GmailToken
from models.gmail_mail import GmailEmail
from models.gmail_rules import (
    MailRule,
    ConditionType,
    RuleCondition,
    LogicType,
)

logger = logging.getLogger(__name__)
gmail_auth = GmailAuth()

_EMAIL_RE = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
_ZW_RE = re.compile(r'[\u200B-\u200D\uFEFF]')
_WS_RE = re.compile(r'\s+')
_COMPACT_KEEP_RE = re.compile(r'[^0-9a-zA-Z\uAC00-\uD7A3\u3040-\u30FF\u4E00-\u9FFF]+')


def _to_plain_text(s: str) -> str:
    if not s:
        return ""
    s = _ZW_RE.sub("", s)
    s = _WS_RE.sub(" ", s).strip()
    return s


def _compact(s: str) -> str:
    return _COMPACT_KEEP_RE.sub("", s or "")


def _extract_body(part):
    """Gmail message payload에서 본문 텍스트 추출(plain 우선, html fallback)"""
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
    """헤더 문자열에서 이메일 한 개 추출(없으면 None)"""
    if not header_value:
        return None
    m = _EMAIL_RE.search(header_value)
    return m.group(0).lower() if m else None


def _header_map(payload_headers):
    """payload.headers -> dict[name_lower] = value"""
    return {h.get('name', '').lower(): h.get('value', '') for h in (payload_headers or [])}


def _recipient_matches_me(headers_map, my_email_lc: str) -> bool:
    """
    수신자에 본인 이메일이 들어있는지 검사.
    To, Cc, Delivered-To, X-Original-To, Envelope-To, X-Forwarded-To, Return-Path 까지 검사
    (BCC/포워딩 환경 대비)
    """
    candidates = [
        'to', 'cc', 'delivered-to',
        'x-original-to', 'envelope-to', 'x-forwarded-to', 'return-path'
    ]
    for name in candidates:
        v = headers_map.get(name, '')
        if not v:
            continue
        try:
            for part in v.replace('\n', '').split(','):
                addr = _extract_email(part.strip())
                if (addr or '').lower() == my_email_lc:
                    return True
        except Exception:
            continue
    return False


def _condition_matches(cond: RuleCondition, subject: str, body: str, sender: str) -> bool:
    """
    한 '조건'을 평가.
    - 키워드 리스트를 cond.logic(AND/OR)로 묶어 판단
    - 타입:
        SUBJECT_CONTAINS -> 제목에서 검색
        BODY_CONTAINS    -> 본문에서 검색 (+제목 보조, compact 비교 포함)
        FROM_SENDER      -> 보낸 사람 이메일에서 검색(주소만)
    """
    subj = _to_plain_text(subject or "").lower()
    bod  = _to_plain_text(body or "").lower()
    subj_compact = _compact(subj)
    bod_compact  = _compact(bod)
    subj_bod     = (bod + " " + subj).strip()
    subj_bod_c   = _compact(subj_bod)
    sndr_email   = (_extract_email(sender) or "").lower()

    # 키워드 준비
    kw_list = [(getattr(cond_kw, 'keyword', '') or '').strip().lower()
               for cond_kw in getattr(cond, 'keywords', [])]
    kw_list = [k for k in kw_list if k]
    if not kw_list:
        return False

    def hit(kw: str) -> bool:
        kwc = _compact(kw)
        if cond.type == ConditionType.SUBJECT_CONTAINS:
            return (kw in subj) or (kwc in subj_compact)
        if cond.type == ConditionType.BODY_CONTAINS:
            # 본문 우선, 보조로 제목+본문
            return (
                (kw in bod) or (kwc in bod_compact) or
                (kw in subj_bod) or (kwc in subj_bod_c)
            )
        if cond.type == ConditionType.FROM_SENDER:
            return kw in sndr_email
        return False

    logic = cond.logic if isinstance(cond.logic, LogicType) else LogicType.OR
    ok = all(hit(w) for w in kw_list) if logic == LogicType.AND else any(hit(w) for w in kw_list)

    logger.debug(
        "CondMatch id=%s type=%s logic=%s kw=%s -> %s",
        getattr(cond, 'id', None),
        getattr(cond.type, 'value', str(cond.type)),
        getattr(cond.logic, 'value', str(cond.logic)),
        kw_list,
        ok,
    )
    return ok


def _choose_start_history_id(saved_history_id: str | None, pubsub_history_id: str | None) -> str:
    """
    startHistoryId 선택 규칙:
    - 둘 다 있으면 더 보수적으로 '작은 값'(숫자 비교) 사용해 누락 방지
    - 하나만 있으면 그걸 사용
    - 없으면 '1'
    """
    def as_int(s):
        try:
            return int(s)
        except Exception:
            return 2**63 - 1

    if saved_history_id and pubsub_history_id:
        si = as_int(saved_history_id)
        pi = as_int(pubsub_history_id)
        return str(min(si, pi))
    if pubsub_history_id:
        return str(pubsub_history_id)
    if saved_history_id:
        return str(saved_history_id)
    return '1'


def _reset_history_to_latest(service, entry: GmailToken) -> bool:
    """
    HistoryId too old 등의 경우 최신 historyId로 초기화.
    성공 시 True, 실패 시 False.
    """
    try:
        prof = service.users().getProfile(userId='me').execute()
        latest = str(prof.get('historyId') or '')
        if latest:
            entry.last_history_id = latest
            return True
        return False
    except Exception as e:
        logger.error("Failed to reset history to latest: %s", e)
        return False


def get_gmail_email_details(fcm_token: str, history_id: str, redis_client=None):
    """
    반환: subject, body, sender, matched(bool), message_id
    - 규칙 매칭: 각 규칙은 '모든 조건 AND'로 일치해야 함
    - 각 조건 내부의 키워드는 cond.logic(AND/OR)로 묶여 평가
    - ✅ Gmail history 페이징 전부 순회
    - ✅ 수신자 헤더 확장 (BCC/포워딩 대응)
    - ✅ BODY_CONTAINS 보조/compact 비교
    """
    with SessionLocal() as db:
        try:
            entry = db.query(GmailToken).filter_by(fcm_token=fcm_token).first()
            if not entry:
                logger.error("No GmailToken for fcm_token=%s", fcm_token)
                return None, None, None, False, None

            current_email = (entry.email_address or "").lower()

            creds = gmail_auth._get_credentials(entry)
            service = build('gmail', 'v1', credentials=creds, cache_discovery=False)

            # startHistoryId 결정
            start_history_id = _choose_start_history_id(entry.last_history_id, str(history_id))
            logger.info("History list startHistoryId=%s (saved=%s, pubsub=%s) for %s",
                        start_history_id, entry.last_history_id, history_id, current_email)

            # ===== History 페이지 전체 순회 =====
            all_history = []
            try:
                req = service.users().history().list(
                    userId='me',
                    startHistoryId=start_history_id
                )
                while req is not None:
                    resp = req.execute()
                    if 'history' in resp:
                        all_history.extend(resp['history'])
                    # nextPageToken 처리
                    token = resp.get('nextPageToken')
                    if token:
                        req = service.users().history().list(
                            userId='me',
                            startHistoryId=start_history_id,
                            pageToken=token
                        )
                    else:
                        req = None
            except HttpError as e:
                logger.error("History fetch failed for %s (start=%s): %s", current_email, start_history_id, e)
                status = getattr(getattr(e, 'resp', None), 'status', None)
                if status == 404:
                    if _reset_history_to_latest(service, entry):
                        db.commit()
                        logger.warning("HistoryId too old; reset last_history_id to latest for %s", current_email)
                    else:
                        db.rollback()
                    return None, None, None, False, None
                if status == 401:
                    logger.error("Authentication error for token %s", fcm_token)
                return None, None, None, False, None

            logger.debug("Fetched %d history records (all pages) for %s", len(all_history), current_email)

            processed = False
            matched_flag = False
            last_subject = last_body = last_sender = None
            last_message_id = None

            # 규칙 미리 로드
            rules = (
                db.query(MailRule)
                .options(joinedload(MailRule.conditions).joinedload(RuleCondition.keywords))
                .filter_by(owner_email=current_email, enabled=True)
                .all()
            )
            logger.info("Loaded %d rules for %s", len(rules), current_email)

            for record in all_history:
                for added in record.get('messagesAdded', []):
                    msg_id = added['message']['id']
                    redis_key = f"gmail_msg:{msg_id}"
                    if redis_client and redis_client.get(redis_key):
                        logger.debug("Skip already-processed msg %s by redis", msg_id)
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

                    labels = msg.get('labelIds', []) or []
                    if 'INBOX' not in labels:
                        logger.debug("Skip msg %s: no INBOX label (labels=%s)", msg_id, labels)
                        continue

                    headers_map = _header_map(msg['payload'].get('headers', []))
                    if not _recipient_matches_me(headers_map, current_email):
                        logger.debug("Skip msg %s: recipient not matched my address", msg_id)
                        continue

                    sender = headers_map.get('from', 'Unknown Sender')
                    subject = headers_map.get('subject', 'No Subject')
                    body = _extract_body(msg['payload']) or 'No Body'

                    logger.debug("Candidate msg %s: from=%s subj=%s", msg_id, sender, subject)

                    matched = False
                    for rule in rules:
                        if not rule.conditions:
                            continue
                        if all(_condition_matches(cond, subject, body, sender) for cond in rule.conditions):
                            matched = True

                            existing = db.query(GmailEmail).filter_by(
                                message_id=msg_id, email_address=current_email
                            ).first()
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
                            else:
                                logger.debug("Already saved msg %s for %s", msg_id, current_email)
                            break  # 첫 매칭 규칙 찾으면 더 볼 필요 없음
                    if not matched:
                        logger.debug("No rule matched for msg %s", msg_id)
                        continue

                    last_subject, last_body, last_sender = subject, body, sender
                    last_message_id = msg_id
                    matched_flag = True

                    if redis_client and processed:
                        try:
                            redis_client.setex(redis_key, 86400, "1")
                        except Exception:
                            pass

            # 최신 historyId로 갱신 시도 (응답 마지막 페이지의 historyId가 루트에 없을 수 있어 보조 처리)
            if all_history:
                try:
                    latest_id = str(max(int(h['historyId']) for h in all_history if 'historyId' in h))
                    entry.last_history_id = latest_id
                except Exception:
                    # 보조
                    try:
                        prof = service.users().getProfile(userId='me').execute()
                        entry.last_history_id = str(prof.get('historyId') or entry.last_history_id or '')
                    except Exception:
                        pass
                db.commit()

                if matched_flag and last_subject:
                    return last_subject, last_body, last_sender, True, last_message_id

            return None, None, None, False, None

        except Exception as e:
            logger.error("Unexpected in get_gmail_email_details: %s", e, exc_info=True)
            db.rollback()
            return None, None, None, False, None
        finally:
            db.close()
