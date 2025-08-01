from flask import Blueprint, request, jsonify, current_app
import base64
import json
import logging
from infra.db import SessionLocal
from models.gmail_users import GmailToken
from utils.gmail_util import get_gmail_email_details
from fcm.fcm_service import FcmService

logger = logging.getLogger(__name__)
gmail_bp = Blueprint('gmail', __name__)
fcm_service = FcmService()


def _history_dedup_key(email_address: str, history_id: str):
    return f"pubsub:history:{email_address}:{history_id}"


def _message_push_dedup_key(message_id: str):
    return f"pushed:message:{message_id}"


@gmail_bp.route('/pubsub_endpoint', methods=['POST'])
def pubsub_endpoint():
    try:
        envelope = request.get_json() or {}
        logger.info("Pub/Sub received: %s", envelope)

        msg = envelope.get('message', {})
        data_encoded = msg.get('data', '')
        try:
            data = json.loads(base64.b64decode(data_encoded).decode())
        except Exception:
            return jsonify({'error': 'invalid_payload'}), 400

        email_address = data.get('emailAddress')
        history_id = data.get('historyId')
        if not email_address or not history_id:
            return jsonify({'error': 'missing_fields'}), 400

        redis_client = getattr(current_app, 'extensions', {}).get('redis')

        history_key = _history_dedup_key(email_address, history_id)
        if redis_client and redis_client.get(history_key):
            logger.info("Duplicate Pub/Sub (history) skip for %s %s", email_address, history_id)
            # 계속 진행해서 message-level dedup로 한 번 더 확인할 수도 있음

        with SessionLocal() as db:
            tokens = db.query(GmailToken).filter_by(email_address=email_address).all()
            if not tokens:
                return jsonify({'error': f'no_tokens_for_{email_address}'}), 404

        first_token = tokens[0].fcm_token
        subject, body, sender, matched, message_id = get_gmail_email_details(
            first_token, history_id, redis_client=redis_client
        )

        if not subject or not matched or not message_id:
            if redis_client:
                redis_client.setex(history_key, 300, "1")
            logger.info("No new or unmatched email for history_id %s", history_id)
            return jsonify({'status': 'no_new_message_or_unmatched'}), 200

        # message-level dedup for push
        push_key = _message_push_dedup_key(message_id)
        if redis_client:
            was_set = redis_client.set(push_key, "1", nx=True, ex=86400)  # atomic: 없으면 set
            if not was_set:
                logger.info("Already pushed message %s, skipping push", message_id)
                return jsonify({'status': 'already_pushed'}), 200

        notified = 0
        for token_entry in tokens:
            try:
                fcm_service.send_push_for_email(
                    token_entry.fcm_token,
                    email_address,
                    subject,
                    body,
                    sender,
                    extra_data={'historyId': history_id, 'messageId': message_id}
                )
                notified += 1
            except Exception as e:
                logger.error("FCM send failure to %s: %s", token_entry.fcm_token, e)

        if redis_client:
            redis_client.setex(history_key, 3600, "1")

        return jsonify({'status': 'gmail_processed', 'tokens_notified': notified}), 200

    except Exception as e:
        logger.exception("Pub/Sub endpoint error: %s", e)
        return jsonify({'error': 'internal'}), 500
