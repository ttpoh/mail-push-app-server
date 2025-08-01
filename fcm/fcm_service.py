from firebase_admin import messaging
import json
import logging
from sqlalchemy.orm import joinedload

from infra.db import SessionLocal
from models.gmail_rules import MailRule, ConditionType, RuleCondition, ConditionKeyword

logger = logging.getLogger(__name__)


class FcmService:
    def send_push_for_email(self, fcm_token: str, email_address: str, subject: str, body: str, sender: str, extra_data: dict = None):
        # 룰과 관계를 한 번에 가져와서 lazy load 실패 방지
        with SessionLocal() as db:
            rules = db.query(MailRule) \
                .options(
                    joinedload(MailRule.conditions).joinedload(RuleCondition.keywords)
                ) \
                .filter_by(owner_email=email_address, enabled=True) \
                .all()

        subject_lower = (subject or "").lower()
        body_lower = (body or "").lower()
        sender_lower = (sender or "").lower()

        matched_rule = None
        matched_keyword = None
        for rule in rules:
            for condition in rule.conditions:
                for kw in condition.keywords:
                    term = getattr(kw, 'keyword', '').lower()
                    if condition.type == ConditionType.SUBJECT_CONTAINS and term in subject_lower:
                        matched_rule = rule
                        matched_keyword = term
                        break
                    if condition.type == ConditionType.BODY_CONTAINS and term in body_lower:
                        matched_rule = rule
                        matched_keyword = term
                        break
                    if condition.type == ConditionType.FROM_SENDER and term in sender_lower:
                        matched_rule = rule
                        matched_keyword = term
                        break
                if matched_rule:
                    break
            if matched_rule:
                if matched_rule.stop_further_rules:
                    break
                else:
                    break

        if not matched_rule:
            logger.info("No matching rule for %s subject='%s'", email_address, subject)
            return None

        # 긴급 판단
        critical = False
        if matched_keyword and '긴급' in matched_keyword:
            critical = True
        elif matched_keyword and '미팅' in matched_keyword:
            critical = False
        else:
            if '긴급' in subject_lower or '긴급' in body_lower:
                critical = True

        title = subject or "새 메일 도착"
        body_text = body or ""

        payload_data = {k: str(v) for k, v in (extra_data or {}).items()}
        payload_data['mailData'] = json.dumps({'subject': title, 'body': body_text, 'sender': sender}, ensure_ascii=False)
        payload_data['isCritical'] = 'true' if critical else 'false'
        payload_data['matchedRule'] = matched_rule.name

        # APNS 구성
        aps_alert = messaging.ApsAlert(title=title, body=body_text)
        sound = messaging.CriticalSound(critical=True, name='siren.mp3', volume=0.2) if critical else 'default'
        apns_cfg = messaging.APNSConfig(
            headers={'apns-priority': '10'},
            payload=messaging.APNSPayload(
                aps=messaging.Aps(alert=aps_alert, sound=sound, content_available=True),
                custom_data=payload_data
            )
        )

        message = messaging.Message(
            notification=messaging.Notification(title=title, body=body_text),
            data=payload_data,
            apns=apns_cfg,
            token=fcm_token,
        )

        try:
            logger.debug("FCM payload: %s", json.dumps(self._serialize_message(message), ensure_ascii=False))
        except Exception:
            pass

        try:
            resp = messaging.send(message)
            logger.info("FCM sent to %s: %s", fcm_token, resp)
            return resp
        except Exception as e:
            logger.error("FCM send failed to %s: %s", fcm_token, e)
            raise

    def _serialize_message(self, message):
        info = {
            'notification': {
                'title': message.notification.title if message.notification else None,
                'body': message.notification.body if message.notification else None
            },
            'data': message.data,
            'token': message.token,
        }
        if message.apns:
            info['apns'] = {
                'headers': getattr(message.apns, 'headers', None),
                'custom_data': getattr(message.apns.payload, 'custom_data', None)
            }
        return info
