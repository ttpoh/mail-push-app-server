# fcm_service.py
from firebase_admin import messaging
from firebase_admin import _messaging_utils as mu  # ✅ UnregisteredError 캐치용
import json
import logging
import uuid

from sqlalchemy.orm import joinedload
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError  # ✅ 멱등성 INSERT 중복 캐치

from infra.db import SessionLocal
from models.gmail_rules import MailRule, ConditionType, RuleCondition
from models.alarm_setting import AlarmSettings  # ← 프로젝트에 맞는 경로 유지

logger = logging.getLogger(__name__)

class FcmService:
    # ===================== 헬퍼: 멱등성/토큰정리 =====================
    def _mark_sent_once(self, db, email_address: str, gmail_message_id: str, fcm_token: str) -> bool:
        try:
            db.execute(
                text("""
                    INSERT INTO push_dedupe (email_address, gmail_message_id, fcm_token)
                    VALUES (:email, :mid, :token)
                """),
                {"email": email_address, "mid": gmail_message_id, "token": fcm_token}
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

    def _delete_invalid_token(self, db, fcm_token: str):
        try:
            db.execute(
                text("""
                    UPDATE alarm_settings
                       SET fcm_token = NULL
                     WHERE fcm_token = :t
                """),
                {"t": fcm_token}
            )
            db.commit()
            logger.info("Removed invalid FCM token: %s", fcm_token)
        except Exception as e:
            db.rollback()
            logger.warning("Failed to remove invalid token %s: %s", fcm_token, e)

    # ===================== 메인 로직 =====================
    def send_push_for_email(
        self,
        fcm_token: str,
        email_address: str,
        subject: str,
        body: str,
        sender: str,
        message_id: str | None = None,
        extra_data: dict | None = None,
    ):
        # 1) 룰 + 키워드 로드
        with SessionLocal() as db:
            rules = (
                db.query(MailRule)
                .options(joinedload(MailRule.conditions).joinedload(RuleCondition.keywords))
                .filter_by(owner_email=email_address, enabled=True)
                .all()
            )

        subj_l = (subject or "").lower()
        body_l = (body or "").lower()
        sender_l = (sender or "").lower()

        matched_rule = None

        # 2) 매칭
        for rule in rules:
            rule_matched = False
            for cond in rule.conditions:
                for kw in cond.keywords:
                    term = (getattr(kw, "keyword", "") or "").lower()
                    if not term:
                        continue
                    if cond.type == ConditionType.SUBJECT_CONTAINS and term in subj_l:
                        rule_matched = True; break
                    if cond.type == ConditionType.BODY_CONTAINS and term in body_l:
                        rule_matched = True; break
                    if cond.type == ConditionType.FROM_SENDER and term in sender_l:
                        rule_matched = True; break
                if rule_matched:
                    matched_rule = rule
                    break
            if rule_matched:
                break

        if not matched_rule:
            logger.info("RULE MISS: email=%s subj='%s' sender='%s' -> NO SEND",
                        email_address, subject, sender)
            return None

        # 3) 디바이스 알람 설정
        with SessionLocal() as db:
            settings = (
                db.query(AlarmSettings)
                .filter(AlarmSettings.fcm_token == fcm_token)
                .first()
            )

        normal_on = True
        critical_on = False
        critical_until = False
        if settings:
            normal_on = bool(settings.normal_on)
            critical_on = bool(settings.critical_on)
            critical_until = bool(settings.critical_until_stopped)

        # 4) 최종 크리티컬
        final_critical = bool(critical_on)

        # 일반 알림 비활성화 시 스킵
        if not final_critical and not normal_on:
            logger.info("Normal alerts disabled -> skip. email=%s", email_address)
            return None

        title = subject or "새 메일 도착"
        body_text = body or ""

        # 5) messageId / payload
        gmail_message_id = message_id or str(uuid.uuid4())
        message_id = gmail_message_id

        payload_data: dict[str, str] = {}
        if extra_data:
            payload_data.update({str(k): str(v) for k, v in extra_data.items()})

        payload_data["messageId"]      = message_id
        payload_data["ruleMatched"]    = "true"
        payload_data["mailData"]       = json.dumps(
            {
                "subject": title,
                "body": body_text,
                "sender": sender,
                "email_address": email_address,
            },
            ensure_ascii=False,
        )
        payload_data["isCritical"]     = "true" if final_critical else "false"
        payload_data["criticalUntil"]  = "true" if critical_until else "false"
        payload_data["matchedRule"]    = matched_rule.name
        payload_data["emailAddress"]   = email_address

        logger.info("isCritical=%s, criticalUntil=%s for email=%s", 
                    payload_data["isCritical"], payload_data["criticalUntil"], email_address)

        # 6) APNS 헤더/사운드
        apns_headers = {
            "apns-push-type": "alert",
            "apns-priority": "10",
        }
        aps_alert = messaging.ApsAlert(title=title, body=body_text)

        # ✅ criticalUntil이면 APNS 사운드(심지어 CriticalSound)도 넣지 않아 ding을 막음
        apns_sound = None
        if final_critical and not critical_until:
            apns_sound = messaging.CriticalSound(critical=True, name="siren.caf", volume=0.2)

        apns_cfg = messaging.APNSConfig(
            headers=apns_headers,
            payload=messaging.APNSPayload(
                aps=messaging.Aps(alert=aps_alert, sound=apns_sound),
                custom_data=payload_data,
            ),
        )

        # 7) 멱등성
        with SessionLocal() as db:
            first_time = self._mark_sent_once(db, email_address, message_id, fcm_token)
            if not first_time:
                logger.info("Skip duplicate push: %s / %s / %s", email_address, message_id, fcm_token)
                return None

        # 8) 전송
        message = messaging.Message(data=payload_data, apns=apns_cfg, token=fcm_token)

        try:
            resp = messaging.send(message)
            logger.info("FCM sent to %s for message_id=%s: %s", fcm_token, message_id, resp)
            return resp

        except mu.UnregisteredError:
            logger.error("Unregistered FCM token: %s (message_id=%s)", fcm_token, message_id)
            with SessionLocal() as db:
                self._delete_invalid_token(db, fcm_token)
            return None

        except Exception as e:
            logger.error("FCM send failed to %s for message_id=%s: %s", fcm_token, message_id, e)
            raise

    def _serialize_message(self, message):
        info = {"data": message.data, "token": message.token}
        if message.apns:
            info["apns"] = {
                "headers": getattr(message.apns, "headers", None),
                "custom_data": getattr(message.apns.payload, "custom_data", None),
            }
        return info
