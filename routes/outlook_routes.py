from flask import Blueprint, request, jsonify
from fcm.fcm_service import FcmService
from auth.outlook_auth import OutlookAuth
from models.outlook_users import OutlookToken
from infra.db import SessionLocal
from utils.outlook_util import get_outlook_email_details
from infra.redis_client import redis_client
import logging
import json

logger = logging.getLogger(__name__)

outlook_bp = Blueprint('outlook', __name__)
fcm_service = FcmService()
processed_message_ids = set()
outlook_processed_ids = set()


@outlook_bp.route('/outlook_webhook', methods=['GET', 'POST'])
def outlook_webhook():
    logger.info(f"Outlook webhook request: {request.method}, args={request.args}, headers={request.headers}")
    global outlook_processed_ids

    if 'validationToken' in request.args:
        return request.args['validationToken'], 200, {'Content-Type': 'text/plain'}

    try:
        payload = request.get_json(silent=True) or {}
        logger.info(f"Outlook webhook payload: {payload}")
    except Exception as e:
        logger.error(f"Failed to parse webhook payload: {e}")
        return jsonify({'status': 'invalid_payload'}), 400

    outlook_auth = OutlookAuth(
        client_id=request.headers.get('X-Outlook-Client-Id'),
        client_secret=request.headers.get('X-Outlook-Client-Secret')
    )

    for note in payload.get('value', []):
        client_state = note.get('clientState')
        msg_id = note.get('resourceData', {}).get('id')
        logger.info(f"[Webhook Payload] client_state={client_state}, msg_id={msg_id}")

        if not client_state or not msg_id:
            continue

        try:
            with SessionLocal() as db:
                # ✅ 1. 해당 client_state 로부터 email_address 조회
                main_token = db.query(OutlookToken).filter_by(client_state=client_state).first()
                if not main_token:
                    logger.warning(f"No token found for client_state: {client_state}")
                    continue

                email_address = main_token.email_address
                logger.info(f"Processing email for: {email_address}")

                # ✅ 2. 해당 email_address로 등록된 모든 토큰 레코드 조회
                all_tokens = db.query(OutlookToken).filter_by(email_address=email_address).all()
                logger.info(f"[Token Count] fcm_tokens for {email_address}: {len(all_tokens)}")

                # ✅ 3. 한 번만 메일 정보 파싱
                subj, body, sender, _ = get_outlook_email_details(
                    client_state=client_state,
                    message_id=msg_id,
                    user_id=None,
                    processed_message_ids=outlook_processed_ids,
                    redis_client=redis_client,
                    outlook_auth=outlook_auth
                )

                if not subj:
                    continue

                is_critical = '긴급' in subj or '긴급' in body

                # ✅ 4. 모든 토큰에 대해 FCM 전송
                for token in all_tokens:
                    logger.info(f"[Token Detail] fcm_token={token.fcm_token}, client_state={token.client_state}")
                    fcm_service.send_push(
                        token.fcm_token,
                        f"{sender} - {subj}",
                        body[:200],
                        data={
                            'subject': subj,
                            'body': body,
                            'sender': sender,
                            'messageId': msg_id,
                            'mailData': json.dumps({'subject': subj, 'body': body}),
                            'isCritical': str(is_critical).lower()
                        }
                    )
                    logger.info(f"Outlook push sent to {token.fcm_token} for msg_id: {msg_id}")
        except Exception as e:
            logger.error(f"Failed to process Outlook webhook: {e}")

    return jsonify({'status': 'outlook_pushed'}), 200

