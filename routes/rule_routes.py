from flask import Blueprint, request, jsonify, g
from requests import Session
import logging
from models.gmail_rules import MailRule, RuleCondition, ConditionKeyword
from models.gmail_users import GmailToken  # fallback용
from models.outlook_users import OutlookToken  # fallback용

from infra.db import SessionLocal

rule_bp = Blueprint("rules", __name__)

def get_current_email_fallback_from_fcm():
    fcm_token = request.args.get("fcm_token") or (request.get_json(silent=True) or {}).get("fcm_token")
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
        logging.info("Fallback failed: no fcm_token or no matching GmailToken entry.")
    return fb

@rule_bp.route("/", methods=["GET"])
def list_rules():
    owner = get_current_email()
    logging.info(f"owner In list_rules: {owner}")

    if not owner:
        return jsonify({"error": "unauthenticated"}), 401
    with SessionLocal() as db:
        rules = db.query(MailRule).filter_by(owner_email=owner).all()
        def serialize(rule: MailRule):
            return {
                "id": rule.id,
                "name": rule.name,
                "enabled": rule.enabled,
                "stop_further_rules": rule.stop_further_rules,
                "conditions": [
                    {
                        "id": c.id,
                        "type": c.type.value,
                        "position": c.position,
                        "keywords": [k.keyword for k in c.keywords],
                    }
                    for c in sorted(rule.conditions, key=lambda x: x.position)
                ],
            }
        logging.info(f"rules In list_rules: {rules}")

        return jsonify([serialize(r) for r in rules])
# create/update/delete 동일하게 owner 얻는 부분만 위 get_current_email() 사용


@rule_bp.route("", methods=["POST"])
def create_rule():
    owner = get_current_email()
    logging.info(f"owner in create_rule: {owner}")
    if not owner:
        return jsonify({"error": "unauthenticated"}), 401
    payload = request.get_json()
    if not payload or "name" not in payload:
        return jsonify({"error": "invalid payload"}), 400
    db: Session = SessionLocal()
    rule = MailRule(
        owner_email=owner,
        name=payload["name"],
        stop_further_rules=payload.get("stop_further_rules", False),
        enabled=payload.get("enabled", True),
    )
    for idx, cond in enumerate(payload.get("conditions", [])):
        condition = RuleCondition(
            type=cond.get("type", ""),
            position=idx,
        )
        for kw in cond.get("keywords", []):
            condition.keywords.append(ConditionKeyword(keyword=kw))
        rule.conditions.append(condition)
    db.add(rule)
    db.commit()
    db.refresh(rule)
    return jsonify({"id": rule.id}), 201

@rule_bp.route("/<int:rule_id>", methods=["PUT"])
def update_rule(rule_id):
    owner = get_current_email()
    if not owner:
        return jsonify({"error": "unauthenticated"}), 401
    db: Session = SessionLocal()
    rule: MailRule | None = db.query(MailRule).filter_by(id=rule_id, owner_email=owner).first()
    if not rule:
        return jsonify({"error": "not found"}), 404
    payload = request.get_json()
    if "name" in payload:
        rule.name = payload["name"]
    if "enabled" in payload:
        rule.enabled = payload["enabled"]
    if "stop_further_rules" in payload:
        rule.stop_further_rules = payload["stop_further_rules"]
    # 조건 재설정: 기존 삭제하고 새로 붙이는 방식 (간단)
    rule.conditions.clear()
    for idx, cond in enumerate(payload.get("conditions", [])):
        condition = RuleCondition(
            type=cond.get("type", ""),
            position=idx,
        )
        for kw in cond.get("keywords", []):
            condition.keywords.append(ConditionKeyword(keyword=kw))
        rule.conditions.append(condition)
    db.commit()
    return jsonify({"status": "ok"})

@rule_bp.route("/<int:rule_id>", methods=["DELETE"])
def delete_rule(rule_id):
    logging.info(f"rule_id In delete_rule: {rule_id}")

    owner = get_current_email()
    logging.info(f"owner In delete_rule: {owner}")

    if not owner:
        return jsonify({"error": "unauthenticated"}), 401
    db: Session = SessionLocal()
    rule: MailRule | None = db.query(MailRule).filter_by(id=rule_id, owner_email=owner).first()
    if not rule:
        return jsonify({"error": "not found"}), 404
    db.delete(rule)
    db.commit()
    return jsonify({"status": "deleted"})
