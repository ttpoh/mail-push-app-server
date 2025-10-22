from flask import Blueprint, request, jsonify, g
import logging

from infra.db import SessionLocal
from models.gmail_rules import (
    MailRule,
    RuleCondition,
    ConditionKeyword,
    ConditionType,
    LogicType,
    AlarmLevel,   # ✅ 추가
)
from models.gmail_users import GmailToken  # fallback용
from models.outlook_users import OutlookToken  # fallback용

rule_bp = Blueprint("rules", __name__)

# -----------------------------
# 현재 사용자 이메일/FCM fallback
# -----------------------------
def get_current_email_fallback_from_fcm():
    data = request.get_json(silent=True) or {}
    fcm_token = request.args.get("fcm_token") or data.get("fcm_token")
    logging.info(f"fcm_token In get_current_email_fallback_from_fcm: {fcm_token}")

    if not fcm_token:
        return None
    with SessionLocal() as db:
        entry = db.query(GmailToken).filter_by(fcm_token=fcm_token).first()
        if entry:
            return entry.email_address
        entry = db.query(OutlookToken).filter_by(fcm_token=fcm_token).first()
        if entry:
            return entry.email_address
    return None

def get_current_email():
    email = getattr(g, "current_user_email", None)
    logging.info(f"current_user_email resolved to: {email}")
    if email:
        return email
    fb = get_current_email_fallback_from_fcm()
    if fb:
        logging.info(f"Fallback email from fcm_token: {fb}")
    else:
        logging.info("Fallback failed: no fcm_token or no matching token entry.")
    return fb

# -----------------------------
# 변환/직렬화 헬퍼
# -----------------------------
def _parse_condition_type(raw: str) -> ConditionType:
    try:
        return ConditionType(raw)
    except Exception:
        return ConditionType.SUBJECT_CONTAINS

def _parse_logic_type(raw) -> LogicType:
    try:
        if not raw:
            return LogicType.OR
        return LogicType(str(raw))
    except Exception:
        return LogicType.OR

def _parse_alarm(raw) -> AlarmLevel:
    """
    raw: 'normal' | 'critical' | 'until'
    기본값: normal
    """
    try:
        if not raw:
            return AlarmLevel.NORMAL
        return AlarmLevel(str(raw))
    except Exception:
        return AlarmLevel.NORMAL

def _serialize_condition(c: RuleCondition) -> dict:
    return {
        "id": c.id,
        "type": c.type.value,
        "logic": (c.logic.value if c.logic else "or"),
        "position": c.position,
        "keywords": [k.keyword for k in c.keywords],
    }

def _serialize_rule(rule: MailRule) -> dict:
    return {
        "id": rule.id,
        "name": rule.name,
        "enabled": rule.enabled,
        "alarm": (rule.alarm.value if rule.alarm else "normal"),  # ✅ 알람 유지
        "sound": rule.sound,  # ✅ 추가
        "tts": rule.tts,      # ✅ 추가
        "conditions": [_serialize_condition(c) for c in sorted(rule.conditions, key=lambda x: x.position)],
    }

# -----------------------------
# 목록
# -----------------------------
@rule_bp.route("/", methods=["GET"])
def list_rules():
    owner = get_current_email()
    logging.info(f"owner In list_rules: {owner}")

    if not owner:
        return jsonify({"error": "unauthenticated"}), 401

    try:
        with SessionLocal() as db:
            rules = db.query(MailRule).filter_by(owner_email=owner).all()
            logging.info(f"found {len(rules)} rules for owner={owner}")
            return jsonify([_serialize_rule(r) for r in rules])
    except Exception as e:
        logging.exception("list_rules failed: %s", e)
        return jsonify({"error": "internal_error"}), 500

# -----------------------------
# 생성
# -----------------------------
@rule_bp.route("", methods=["POST"])
def create_rule():
    owner = get_current_email()
    logging.info(f"owner in create_rule: {owner}")
    if not owner:
        return jsonify({"error": "unauthenticated"}), 401

    payload = request.get_json(silent=True) or {}
    name = (payload.get("name") or "").strip()
    if not name:
        return jsonify({"error": "invalid payload: name required"}), 400

    enabled = bool(payload.get("enabled", True))
    alarm = _parse_alarm(payload.get("alarm"))  # ✅ 유지
    conditions = payload.get("conditions", []) or []
    sound = payload.get("sound")   # ✅ 추가
    tts = payload.get("tts")       # ✅ 추가

    try:
        with SessionLocal() as db:
            rule = MailRule(
                owner_email=owner,
                name=name,
                enabled=enabled,
                alarm=alarm,
                sound=sound,   # ✅ 저장
                tts=tts        # ✅ 저장
            )
            db.add(rule)
            db.flush()

            for idx, cond in enumerate(conditions):
                ctype = _parse_condition_type(cond.get("type", "subjectContains"))
                clogic = _parse_logic_type(cond.get("logic", "or"))
                position = int(cond.get("position", idx) or idx)

                rc = RuleCondition(
                    mail_rule_id=rule.id,
                    type=ctype,
                    logic=clogic,
                    position=position,
                )
                db.add(rc)
                db.flush()

                for kw in (cond.get("keywords", []) or []):
                    kw_str = (kw or "").strip()
                    if kw_str:
                        db.add(ConditionKeyword(rule_condition_id=rc.id, keyword=kw_str))

            db.commit()
            return jsonify({"id": rule.id}), 201
    except Exception as e:
        logging.exception("create_rule failed: %s", e)
        return jsonify({"error": "internal_error"}), 500

# -----------------------------
# 수정
# -----------------------------
@rule_bp.route("/<int:rule_id>", methods=["PUT"])
def update_rule(rule_id):
    owner = get_current_email()
    if not owner:
        return jsonify({"error": "unauthenticated"}), 401

    payload = request.get_json(silent=True) or {}

    try:
        with SessionLocal() as db:
            rule = db.query(MailRule).filter_by(id=rule_id, owner_email=owner).first()
            if not rule:
                return jsonify({"error": "not found"}), 404

            if "name" in payload:
                nm = (payload.get("name") or "").strip()
                if not nm:
                    return jsonify({"error": "rule name required"}), 400
                rule.name = nm

            if "enabled" in payload:
                rule.enabled = bool(payload.get("enabled"))

            if "alarm" in payload:
                rule.alarm = _parse_alarm(payload.get("alarm"))

            # ✅ 여기 추가: sound, tts 수정
            if "sound" in payload:
                rule.sound = payload.get("sound")
            if "tts" in payload:
                rule.tts = payload.get("tts")

            # 조건 전체 재구성
            for c in list(rule.conditions):
                db.delete(c)
            db.flush()

            conditions = payload.get("conditions", []) or []
            for idx, cond in enumerate(conditions):
                ctype = _parse_condition_type(cond.get("type", "subjectContains"))
                clogic = _parse_logic_type(cond.get("logic", "or"))
                position = int(cond.get("position", idx) or idx)

                rc = RuleCondition(
                    mail_rule_id=rule.id,
                    type=ctype,
                    logic=clogic,
                    position=position,
                )
                db.add(rc)
                db.flush()

                for kw in (cond.get("keywords", []) or []):
                    kw_str = (kw or "").strip()
                    if kw_str:
                        db.add(ConditionKeyword(rule_condition_id=rc.id, keyword=kw_str))

            db.commit()
            return jsonify({"status": "ok"})
    except Exception as e:
        logging.exception("update_rule failed: %s", e)
        return jsonify({"error": "internal_error"}), 500

# -----------------------------
# 삭제
# -----------------------------
@rule_bp.route("/<int:rule_id>", methods=["DELETE"])
def delete_rule(rule_id):
    logging.info(f"rule_id In delete_rule: {rule_id}")
    owner = get_current_email()
    logging.info(f"owner In delete_rule: {owner}")

    if not owner:
        return jsonify({"error": "unauthenticated"}), 401

    try:
        with SessionLocal() as db:
            rule = db.query(MailRule).filter_by(id=rule_id, owner_email=owner).first()
            if not rule:
                return jsonify({"error": "not found"}), 404
            db.delete(rule)
            db.commit()
            return jsonify({"status": "deleted"})
    except Exception as e:
        logging.exception("delete_rule failed: %s", e)
        return jsonify({"error": "internal_error"}), 500
