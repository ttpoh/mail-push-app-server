# email_routes.py
from flask import Blueprint, request, jsonify
from models.gmail_mail import GmailEmail
from models.outlook_mail import OutlookEmail  # 각각의 SQLAlchemy 모델
from infra.db import SessionLocal
from datetime import datetime
import re
import logging
from sqlalchemy import or_

logger = logging.getLogger(__name__)
email_bp = Blueprint('email', __name__)

EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$')

# 기본 페이지 사이즈 상한 (악의적/실수로 너무 많은 요청 방지)
MAX_FETCH = 200

@email_bp.route('/api/emails/mark-read', methods=['POST'])
def mark_email_read():
    data = request.get_json(silent=True) or {}
    service = (data.get('service') or '').lower().strip()
    email_address = (data.get('email_address') or '').strip()

    # 클라가 보낼 수 있는 두 가지 키 지원
    message_id = (data.get('message_id') or '').strip()   # 원본 메시지 ID
    pk_id = data.get('id')                                # DB PK (숫자일 수도, 문자열일 수도)

    read_flag = data.get('read', True)

    if service not in ('gmail', 'outlook'):
        return jsonify({'error': 'Invalid service type'}), 400
    if not email_address:
        return jsonify({'error': 'Missing email_address'}), 400
    if not EMAIL_REGEX.match(email_address):
        return jsonify({'error': 'Invalid email_address format'}), 400
    if not isinstance(read_flag, bool):
        return jsonify({'error': 'read must be a boolean'}), 400
    if not message_id and pk_id is None:
        return jsonify({'error': 'Missing message_id or id'}), 400

    Model = GmailEmail if service == 'gmail' else OutlookEmail

    try:
        with SessionLocal() as db:
            q = db.query(Model).filter(Model.email_address == email_address)

            # message_id 또는 pk(id)로 매칭 시도
            filters = []
            if message_id:
                filters.append(Model.message_id == message_id)
            if pk_id is not None:
                try:
                    filters.append(Model.id == int(pk_id))
                except Exception:
                    # 숫자 변환 실패 시 string 비교는 의미 없으니 무시
                    pass

            row = q.filter(or_(*filters)).first() if filters else None

            if not row:
                logger.info("mark-read miss: %s/%s/%s not found",
                            service, email_address, message_id or pk_id)
                return jsonify({'error': 'Email not found'}), 404

            if row.read != read_flag:
                row.read = read_flag
                db.add(row)
                db.commit()
                logger.info("mark-read updated: %s/%s/%s -> %s",
                            service, email_address, message_id or row.message_id, read_flag)
            else:
                logger.info("mark-read idempotent hit: %s/%s/%s already %s",
                            service, email_address, message_id or row.message_id, read_flag)

            return jsonify({
                'ok': True,
                'service': service,
                'email_address': email_address,
                'message_id': row.message_id,  # 항상 원본 message_id로 회신
                'id': row.id,                  # 참고용으로 PK도 회신
                'read': row.read,
            }), 200

    except Exception as e:
        logger.exception("mark-read failed: %s", e)
        return jsonify({'error': 'Internal server error'}), 500

@email_bp.route('/api/emails', methods=['GET'])
def get_emails():
    email_address = request.args.get('email_address', '').strip()
    service = (request.args.get('service') or '').lower().strip()
    since = request.args.get('since')  # ISO8601, e.g. 2025-08-04T09:00:00Z or without Z
    limit_param = request.args.get('limit')
    try:
        limit = int(limit_param) if limit_param else None
    except ValueError:
        return jsonify({'error': 'Invalid limit parameter'}), 400

    if limit is None:
        limit = MAX_FETCH
    else:
        limit = min(limit, MAX_FETCH)

    logger.info("Received request for service: %s, email_address: %s, since: %s, limit: %s", service, email_address, since, limit)

    if service not in ['gmail', 'outlook']:
        return jsonify({'error': 'Invalid service type'}), 400
    if not email_address:
        return jsonify({'error': 'Missing email_address parameter'}), 400
    if not EMAIL_REGEX.match(email_address):
        return jsonify({'error': 'Invalid email_address format'}), 400

    # 파싱된 since timestamp
    since_dt = None
    if since:
        try:
            # ISO8601 파싱, timezone 없으면 naive로 처리
            since_dt = datetime.fromisoformat(since.replace('Z', '+00:00')) if 'Z' in since else datetime.fromisoformat(since)
        except Exception:
            return jsonify({'error': 'Invalid since parameter, must be ISO8601'}), 400

    with SessionLocal() as db:
        if service == 'gmail':
            query = db.query(GmailEmail).filter(GmailEmail.email_address == email_address)
        else:
            query = db.query(OutlookEmail).filter(OutlookEmail.email_address == email_address)

        if since_dt:
            query = query.filter((GmailEmail.received_at if service == 'gmail' else OutlookEmail.received_at) > since_dt)

        # 최신순 정렬
        if service == 'gmail':
            query = query.order_by(GmailEmail.received_at.desc())
        else:
            query = query.order_by(OutlookEmail.received_at.desc())

        emails = query.limit(limit).all()

        if not emails:
            logger.debug("No emails found for %s in %s_emails (since=%s)", email_address, service, since)

        logger.info("Fetched %d emails for %s (service=%s)", len(emails), email_address, service)

        def serialize(email_obj):
            return {
                "id": email_obj.id,
                "messageId": getattr(email_obj, "message_id", None),  # ✅ 원본 메시지 ID 추가
                "email_address": email_obj.email_address,
                "sender": email_obj.sender,
                "subject": email_obj.subject,
                "body": email_obj.body,
                "received_at": email_obj.received_at.isoformat(),
                "read": email_obj.read,
                "ruleAlarm": getattr(email_obj, "rule_alarm", None),
                "effectiveAlarm": getattr(email_obj, "effective_alarm", None),
            }

        return jsonify([serialize(e) for e in emails]), 200
