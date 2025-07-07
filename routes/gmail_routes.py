from flask import Blueprint, request, jsonify
from fcm.fcm_service import FcmService
from utils.gmail_util import get_gmail_email_details
from models.gmail_users import GmailToken
from infra.db import SessionLocal
import base64
import json
import logging
from models.gmail_mail import GmailEmail

logger = logging.getLogger(__name__)
gmail_bp = Blueprint('gmail', __name__)
fcm_service = FcmService()
processed_history_ids = set()

@gmail_bp.route('/pubsub_endpoint', methods=['POST'])
def pubsub_endpoint():
    logger.info(f"Received Pub/Sub request: {request.get_json()}")
    envelope = request.get_json() or {}
    data_encoded = envelope.get('message', {}).get('data', '')

    try:
        data = json.loads(base64.b64decode(data_encoded).decode())
        logger.info(f"Decoded Pub/Sub data: {data}")

        email_address = data.get('emailAddress')
        history_id = data.get('historyId')
        if not email_address or not history_id:
            return jsonify({'error': 'Missing emailAddress or historyId'}), 400

        # email_address에 해당하는 모든 fcm_token 조회
        with SessionLocal() as db:
            tokens = db.query(GmailToken).filter_by(email_address=email_address).all()
            if not tokens:
                logger.error(f"No Gmail tokens for email_address: {email_address}")
                return jsonify({'error': f"No Gmail tokens for {email_address}"}), 404

            # 이메일 세부 정보는 하나만 가져오면 됨 (모든 토큰에 동일 내용 푸시)
            first_token = tokens[0].fcm_token
            subject, body, sender = get_gmail_email_details(first_token, history_id)
            logger.info(f"Email details: subject={subject}, sender={sender}")
            if not subject or not body or not sender:
                logger.info(f"No new Gmail message for history_id: {history_id}")
                return jsonify({'status': 'no_new_message'}), 200

            # 여러 FCM 토큰에 대해 푸시 전송
            for token in tokens:
                try:
                    fcm_service.send_push(
                        token.fcm_token,
                        f"{sender} - {subject}",
                        body[:200],
                        data={
                            'subject': subject,
                            'body': body,
                            'sender': sender,
                            'messageId': history_id
                        }
                    )
                except Exception as e:
                    logger.error(f"Failed to send push to token {token.fcm_token}: {e}")

            return jsonify({'status': 'gmail_pushed', 'tokens_notified': len(tokens)}), 200

    except Exception as e:
        logger.error(f"Failed to process Pub/Sub request: {str(e)}")
        raise

