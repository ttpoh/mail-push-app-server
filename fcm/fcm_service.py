# fcm_service.py
from firebase_admin import messaging
from firebase_admin import _messaging_utils as mu
import json, logging, uuid, re, html, hashlib, time
from datetime import datetime

from sqlalchemy.orm import joinedload
from sqlalchemy import text, select
from sqlalchemy.exc import IntegrityError

from infra.db import SessionLocal
from models.gmail_rules import (
    MailRule, ConditionType, RuleCondition, LogicType, AlarmLevel,
)
from models.alarm_setting import AlarmSettings
from models.gmail_mail import GmailEmail

logger = logging.getLogger(__name__)

_ZW_RE = re.compile(r'[\u200B-\u200D\uFEFF]')
_TAG_RE = re.compile(r'<[^>]+>')
_WS_RE  = re.compile(r'\s+')
_COMPACT_KEEP_RE = re.compile(r'[^0-9a-zA-Z\uAC00-\uD7A3\u3040-\u30FF\u4E00-\u9FFF]+')

def _to_plain_text(s: str) -> str:
    if not s: return ""
    s = html.unescape(s)
    s = _TAG_RE.sub(" ", s)
    s = _ZW_RE.sub("", s)
    s = _WS_RE.sub(" ", s).strip()
    return s

def _compact(s: str) -> str:
    return _COMPACT_KEEP_RE.sub("", s)

def _compute_rules_version(rules: list[MailRule]) -> str:
    serial = []
    for r in sorted(rules, key=lambda x: (x.id or 0, x.name or "")):
        if not r.enabled:
            continue
        conds = []
        for c in sorted(r.conditions, key=lambda x: x.position):
            conds.append({
                "type": getattr(c.type, "value", str(c.type)),
                "logic": getattr(c.logic, "value", str(c.logic or "or")),
                "position": int(getattr(c, "position", 0) or 0),
                "keywords": sorted([k.keyword for k in c.keywords]),
            })
        serial.append({
            "name": r.name,
            "alarm": getattr(getattr(r, "alarm", None), "value", "normal"),
            "conditions": conds,
        })
    blob = json.dumps(serial, ensure_ascii=False, sort_keys=True)
    digest = hashlib.sha1(blob.encode("utf-8")).hexdigest()
    return digest[:10]

def _as_alarm_level(val) -> AlarmLevel:
    """입력 어떤 형태든 AlarmLevel로 안전 변환."""
    if isinstance(val, AlarmLevel):
        return val
    if isinstance(val, str):
        s = val.strip().lower()
        if s in ("normal", "critical", "until"):
            return AlarmLevel(s)
    v = getattr(val, "value", None)
    if isinstance(v, str):
        s = v.strip().lower()
        if s in ("normal", "critical", "until"):
            return AlarmLevel(s)
    return AlarmLevel.NORMAL

# === 규칙 사운드 파일명 결정( iOS APNs 배너용 ) ===
def _sound_filename(base: str) -> str:
    """
    규칙 사운드 이름에서 확장자를 붙여 APNs에 전달할 파일명 반환.
    - base가 'default'거나 빈 값이면 'default' 반환(시스템 기본음)
    - 그렇지 않으면 '<base>.caf' 반환 (앱 번들에 포함되어 있어야 함)
    """
    if not base or base == "default":
        return "default"
    return f"{base}.caf"

class FcmService:
    def _mark_sent_once(self, db, email_address: str, push_key: str, fcm_token: str) -> bool:
        try:
            db.execute(
                text("""INSERT INTO push_dedupe (email_address, gmail_message_id, fcm_token)
                        VALUES (:email, :mid, :token)"""),
                {"email": email_address, "mid": push_key, "token": fcm_token}
            )
            db.commit()
            return True
        except IntegrityError:
            db.rollback()
            return False
        except Exception as e:
            db.rollback()
            logger.exception("dedupe insert failed: %s", e)
            return False

    def _undedupe(self, db, email_address: str, push_key: str, fcm_token: str):
        try:
            db.execute(
                text("""DELETE FROM push_dedupe
                        WHERE email_address = :email AND gmail_message_id = :mid AND fcm_token = :token"""),
                {"email": email_address, "mid": push_key, "token": fcm_token}
            )
            db.commit()
        except Exception as e:
            db.rollback()
            logger.warning("Failed to revert dedupe for %s/%s: %s", email_address, push_key, e)

    def _delete_invalid_token(self, db, fcm_token: str):
        try:
            db.execute(
                text("""UPDATE alarm_settings SET fcm_token = NULL WHERE fcm_token = :t"""),
                {"t": fcm_token}
            )
            db.commit()
        except Exception as e:
            db.rollback()
            logger.warning("Failed to remove invalid token %s: %s", fcm_token, e)

    def _upsert_gmail_email_alarm(
        self, email_address: str, message_id: str, sender: str, subject: str, body_text: str,
        rule_alarm_str: str, effective_alarm_str: str, matched_rule_name: str, rules_version: str,
    ):
        with SessionLocal() as db:
            dialect = db.bind.dialect.name if db.bind else "unknown"
            if dialect == "postgresql":
                try:
                    db.execute(
                        text("""
                          INSERT INTO gmail_emails (
                            message_id, email_address, sender, subject, body, received_at, read,
                            rule_alarm, effective_alarm, matched_rule_name, rules_version
                          )
                          VALUES (
                            :mid, :email, :sender, :subj, :body, :rcv_at, false,
                            :r_alarm, :e_alarm, :rname, :rver
                          )
                          ON CONFLICT (message_id, email_address)
                          DO UPDATE SET
                            sender=EXCLUDED.sender,
                            subject=EXCLUDED.subject,
                            body=EXCLUDED.body,
                            received_at=COALESCE(gmail_emails.received_at, EXCLUDED.received_at),
                            rule_alarm=EXCLUDED.rule_alarm,
                            effective_alarm=EXCLUDED.effective_alarm,
                            matched_rule_name=EXCLUDED.matched_rule_name,
                            rules_version=EXCLUDED.rules_version
                        """),
                        {
                            "mid": message_id, "email": email_address, "sender": sender,
                            "subj": subject, "body": body_text, "rcv_at": datetime.utcnow(),
                            "r_alarm": rule_alarm_str, "e_alarm": effective_alarm_str,
                            "rname": matched_rule_name, "rver": rules_version,
                        }
                    )
                    db.commit()
                    return
                except Exception as e:
                    db.rollback()
                    logger.exception("PG upsert failed, fallback to ORM: %s", e)

            try:
                row = db.execute(
                    select(GmailEmail).where(
                        GmailEmail.message_id == message_id,
                        GmailEmail.email_address == email_address
                    )
                ).scalar_one_or_none()

                if row is None:
                    row = GmailEmail(
                        message_id=message_id, email_address=email_address,
                        sender=sender, subject=subject, body=body_text,
                        received_at=datetime.utcnow(), read=False,
                    )
                    setattr(row, "rule_alarm", rule_alarm_str)
                    setattr(row, "effective_alarm", effective_alarm_str)
                    setattr(row, "matched_rule_name", matched_rule_name)
                    setattr(row, "rules_version", rules_version)
                    db.add(row)
                    db.commit()
                else:
                    row.sender = sender or row.sender
                    row.subject = subject or row.subject
                    row.body = body_text or row.body
                    if not getattr(row, "received_at", None):
                        row.received_at = datetime.utcnow()
                    setattr(row, "rule_alarm", rule_alarm_str)
                    setattr(row, "effective_alarm", effective_alarm_str)
                    setattr(row, "matched_rule_name", matched_rule_name)
                    setattr(row, "rules_version", rules_version)
                    db.add(row)
                    db.commit()
            except Exception as e:
                db.rollback()
                logger.exception("ORM upsert failed: %s", e)

    def send_push_for_email(
        self, fcm_token: str, email_address: str, subject: str, body: str, sender: str,
        message_id: str | None = None, extra_data: dict | None = None,
    ):
        with SessionLocal() as db:
            rules = (
                db.query(MailRule)
                .options(joinedload(MailRule.conditions).joinedload(RuleCondition.keywords))
                .filter_by(owner_email=email_address, enabled=True)
                .all()
            )
        rule_version = _compute_rules_version(rules)

        raw_subject, raw_body, raw_sender = subject or "", body or "", sender or ""
        subj_norm = _to_plain_text(raw_subject).lower()
        body_norm = _to_plain_text(raw_body).lower()
        sender_norm = _to_plain_text(raw_sender).lower()
        subj_compact = _compact(subj_norm)
        body_compact = _compact(body_norm)
        sender_compact = _compact(sender_norm)
        body_plus_subject_norm = (body_norm + " " + subj_norm).strip()
        body_plus_subject_compact = _compact(body_plus_subject_norm)

        if len(body_norm) < 250:
            logger.info("Body looks short (%d) → use body+subject for BODY_CONTAINS", len(body_norm))

        def _cond_match(cond) -> bool:
            kw_list = [(getattr(kw, "keyword", "") or "").lower().strip() for kw in cond.keywords]
            kw_list = [k for k in kw_list if k]
            if not kw_list:
                return False  # 키워드가 하나도 없으면 매칭 실패로 간주
            def hit(one_kw: str) -> bool:
                kw_norm, kw_compact = one_kw, _compact(one_kw)
                if cond.type == ConditionType.SUBJECT_CONTAINS:
                    return (kw_norm in subj_norm) or (kw_compact in subj_compact)
                if cond.type == ConditionType.BODY_CONTAINS:
                    if (kw_norm in body_norm) or (kw_compact in body_compact):
                        return True
                    return (kw_norm in body_plus_subject_norm) or (kw_compact in body_plus_subject_compact)
                if cond.type == ConditionType.FROM_SENDER:
                    return (kw_norm in sender_norm) or (kw_compact in sender_compact)
                return False
            logic_val = getattr(cond, "logic", None)
            logic = (logic_val.value if isinstance(logic_val, LogicType) else str(logic_val or "or")).lower()
            return all(hit(w) for w in kw_list) if logic == "and" else any(hit(w) for w in kw_list)

        # 규칙 덤프 로깅(문제 추적용)
        try:
            for r in rules:
                alarm_dbg = _as_alarm_level(getattr(r, "alarm", AlarmLevel.NORMAL)).value
                cond_cnt = len(getattr(r, "conditions", []) or [])
                kw_dbg = []
                for c in (r.conditions or []):
                    kw_dbg.extend([k.keyword for k in (c.keywords or []) if getattr(k, "keyword", None)])
                logger.info("RULE DUMP: id=%s name=%s alarm=%s conds=%d keywords=%s",
                            getattr(r, "id", None), getattr(r, "name", None),
                            alarm_dbg, cond_cnt, ",".join(kw_dbg[:10]))
        except Exception as _e:
            logger.warning("RULE DUMP failed: %s", _e)

        # ✅ 조건 없는 규칙은 매칭 제외
        matched_rule = None
        for rule in rules:
            conds = getattr(rule, "conditions", []) or []
            if not conds:
                continue
            if all(_cond_match(cond) for cond in conds):
                matched_rule = rule
                break

        if not matched_rule:
            logger.info("RULE MISS: %s / %s", email_address, raw_subject)
            return None

        # 매칭 규칙 및 알람 레벨 로깅
        logger.info(
            "RULE HIT: id=%s name=%s raw_alarm=%r type=%s",
            getattr(matched_rule, "id", None),
            getattr(matched_rule, "name", None),
            getattr(matched_rule, "alarm", None),
            type(getattr(matched_rule, "alarm", None)).__name__,
        )

        with SessionLocal() as db:
            settings = db.query(AlarmSettings).filter(AlarmSettings.fcm_token == fcm_token).first()

        # ✅ 전역 스위치는 normal_on만 사용 (켜짐/꺼짐)
        global_on = bool(getattr(settings, "normal_on", True)) if settings else True
        if not global_on:
            logger.info("Global alarm OFF → skip all pushes")
            return None

        # ✅ 규칙 알람만으로 최종 의도 결정
        rule_alarm = _as_alarm_level(getattr(matched_rule, "alarm", AlarmLevel.NORMAL))
        rule_sound = (getattr(matched_rule, "sound", None) or "default").strip()  # ← 규칙 사운드

        if rule_alarm == AlarmLevel.UNTIL:
            final_critical, final_until = True, True
            effective_alarm = AlarmLevel.UNTIL
        elif rule_alarm == AlarmLevel.CRITICAL:
            final_critical, final_until = True, False
            effective_alarm = AlarmLevel.CRITICAL
        else:
            final_critical, final_until = False, False
            effective_alarm = AlarmLevel.NORMAL

        title = raw_subject or "New mail"
        body_text = raw_body or ""
        gmail_message_id = message_id or str(uuid.uuid4())
        base_push_key = f"{gmail_message_id}:{rule_version}"

        try:
            self._upsert_gmail_email_alarm(
                email_address=email_address, message_id=gmail_message_id,
                sender=raw_sender, subject=title, body_text=body_text,
                rule_alarm_str=getattr(rule_alarm, "value", str(rule_alarm)),
                effective_alarm_str=getattr(effective_alarm, "value", str(effective_alarm)),
                matched_rule_name=matched_rule.name or "", rules_version=rule_version,
            )
        except Exception as e:
            logger.error("Upsert gmail_emails failed (continue): %s", e)

        # 공통 data
        base_data = {
            "messageId": gmail_message_id,
            "ruleMatched": "true",
            "matchedRule": matched_rule.name or "",
            "ruleVersion": rule_version,
            "mailData": json.dumps({
                "message_id": gmail_message_id,
                "subject": title, "body": body_text, "sender": raw_sender, "email_address": email_address
            }, ensure_ascii=False),
            "ruleAlarm": getattr(rule_alarm, "value", str(rule_alarm)),
            "effectiveAlarm": getattr(effective_alarm, "value", str(effective_alarm)),
            "isCritical": "true" if final_critical else "false",
            "criticalUntil": "true" if final_until else "false",
            "emailAddress": email_address,
            "sound": rule_sound,           # ✅ 규칙 사운드 항상 포함
            "tts": (getattr(matched_rule, "tts", None) or "").strip(),  # ✅ 규칙 TTS 문구
        }

        # (1) BG (사일런트) - 네이티브에서 루프 처리
        payload_data_bg = { **base_data, "pushChannel": "bg" }
        bg_headers = {"apns-push-type": "background", "apns-priority": "5"}
        bg_aps = messaging.Aps(content_available=True)  # ✅ BG는 content_available 필수
        bg_cfg = messaging.APNSConfig(
            headers=bg_headers,
            payload=messaging.APNSPayload(aps=bg_aps, custom_data=payload_data_bg),
        )
        
        bg_send_success = False
        with SessionLocal() as db:
            if not self._mark_sent_once(db, email_address, base_push_key + ":bg", fcm_token):
                logger.info("Skip duplicate (bg) %s", base_push_key)
            else:
                try:
                    resp_bg = messaging.send(messaging.Message(
                        data=payload_data_bg, apns=bg_cfg, token=fcm_token))
                    logger.info("FCM sent(background) %s | flags: critical=%s until=%s",
                                resp_bg, final_critical, final_until)
                    bg_send_success = True
                except mu.UnregisteredError:
                    with SessionLocal() as db:
                        self._delete_invalid_token(db, fcm_token)
                        self._undedupe(db, email_address, base_push_key + ":bg", fcm_token)
                    logger.warning("Unregistered token (bg), but continuing to ALERT: %s", fcm_token)
                except Exception as e:
                    with SessionLocal() as db:
                        self._undedupe(db, email_address, base_push_key + ":bg", fcm_token)
                    logger.warning("BG send failed, continuing to ALERT: %s", e)

        # BG와 ALERT 사이 간격: 1.2s (BG 성공 시에만)
        if bg_send_success:
            time.sleep(1.2)

        # (2) ALERT - 포그라운드/배너 처리
        payload_data_alert = { **base_data, "pushChannel": "alert" }
        alert_headers = {"apns-push-type": "alert", "apns-priority": "10"}

        # iOS APNs 배너 사운드: 규칙 사운드 우선 적용
        if final_until:
            apns_sound = None
            if not bg_send_success:
                name = _sound_filename(rule_sound)
                apns_sound = messaging.CriticalSound(
                    critical=True,
                    name=(name if name != "default" else "siren.caf"),
                    volume=0.5
                )
                payload_data_alert["fallbackLoop"] = "true"
        elif final_critical:
            name = _sound_filename(rule_sound)
            apns_sound = messaging.CriticalSound(
                critical=True,
                name=(name if name != "default" else "siren.caf"),
                volume=0.5
            )
        else:
            name = _sound_filename(rule_sound)
            apns_sound = (name if name != "default" else "default")

        # ✅ ALERT에도 content_available 유지
        alert_aps = messaging.Aps(
            alert=messaging.ApsAlert(title=title, body=body_text),
            sound=apns_sound,
            content_available=True,
        )
        alert_cfg = messaging.APNSConfig(
            headers=alert_headers,
            payload=messaging.APNSPayload(aps=alert_aps, custom_data=payload_data_alert),
        )
        
        alert_send_success = False
        resp_alert = None
        with SessionLocal() as db:
            if not self._mark_sent_once(db, email_address, base_push_key + ":alert", fcm_token):
                logger.info("Skip duplicate (alert) %s", base_push_key)
            else:
                try:
                    resp_alert = messaging.send(messaging.Message(
                        data=payload_data_alert,
                        notification=messaging.Notification(title=title, body=body_text),
                        apns=alert_cfg,
                        token=fcm_token))
                    logger.info("FCM sent(alert) %s | flags: critical=%s until=%s sound=%s",
                                resp_alert, final_critical, final_until, bool(apns_sound))
                    alert_send_success = True
                except mu.UnregisteredError:
                    with SessionLocal() as db:
                        self._delete_invalid_token(db, fcm_token)
                        self._undedupe(db, email_address, base_push_key + ":alert", fcm_token)
                    logger.error("Unregistered token (alert): %s", fcm_token)
                except Exception as e:
                    with SessionLocal() as db:
                        self._undedupe(db, email_address, base_push_key + ":alert", fcm_token)
                    logger.error("Alert send failed: %s", e)
        
        return resp_alert if alert_send_success else None

    def _serialize_message(self, message):
        info = {"data": message.data, "token": message.token}
        if message.apns:
            info["apns"] = {
                "headers": getattr(message.apns, "headers", None),
                "custom_data": getattr(message.apns.payload, "custom_data", None),
            }
        return info
