from flask import Blueprint, request, jsonify
from fcm.fcm_service import FcmService
from auth.outlook_auth import OutlookAuth
from models.outlook_users import OutlookToken
from infra.db import SessionLocal
from utils.outlook_util import get_outlook_email_details
from infra.redis_client import redis_client
import logging
import json
from datetime import datetime

logger = logging.getLogger(__name__)

outlook_bp = Blueprint('outlook', __name__)
fcm_service = FcmService()

@outlook_bp.route('/outlook_webhook', methods=['GET', 'POST'])
def outlook_webhook():
    logger.info(f"Outlook 웹훅 요청: {request.method}, args={request.args}, headers={request.headers}")

    if 'validationToken' in request.args:
        return request.args['validationToken'], 200, {'Content-Type': 'text/plain'}

    try:
        payload = request.get_json(silent=True) or {}
        logger.info(f"Outlook 웹훅 페이로드: {payload}")
    except Exception as e:
        logger.error(f"웹훅 페이로드 파싱 실패: {e}")
        return jsonify({'status': 'invalid_payload'}), 400

    outlook_auth = OutlookAuth(
        client_id=request.headers.get('X-Outlook-Client-Id'),
        client_secret=request.headers.get('X-Outlook-Client-Secret')
    )

    with SessionLocal() as db:
        for note in payload.get('value', []):
            client_state = note.get('clientState')
            msg_id = note.get('resourceData', {}).get('id')
            logger.info(f"[웹훅 페이로드] client_state={client_state}, msg_id={msg_id}")

            if not client_state or not msg_id:
                logger.warning("페이로드에 client_state 또는 msg_id 누락")
                continue

            try:
                # fcm_token 및 email_address 가져오기
                main_token = db.query(OutlookToken).filter_by(client_state=client_state).first()
                if not main_token:
                    logger.warning(f"client_state에 대한 토큰 없음: {client_state}")
                    continue

                email_address = main_token.email_address
                logger.info(f"이메일 처리 중: {email_address}")

                # 만료 임박 시 구독 갱신
                if main_token.access_token_exp and (main_token.access_token_exp - datetime.utcnow()).total_seconds() < 3600:
                    try:
                        outlook_auth.renew_subscription(main_token.fcm_token, main_token.subscription_id)
                    except Exception as e:
                        logger.error(f"fcm_token {main_token.fcm_token}에 대한 구독 갱신 실패: {e}")
                        continue

                # 이메일 세부 정보 가져오기
                subj, body, sender, _ = get_outlook_email_details(
                    client_state=client_state,
                    message_id=msg_id,
                    user_id=email_address,
                    processed_message_ids=None,  # Redis에만 의존
                    redis_client=redis_client,
                    outlook_auth=outlook_auth
                )

                if not subj:
                    logger.info(f"msg_id에 대한 이메일 세부 정보 없음: {msg_id}")
                    continue

                is_critical = '긴급' in subj or '긴급' in body

                # 이메일 주소에 대한 모든 토큰에 FCM 알림 전송
                all_tokens = db.query(OutlookToken).filter_by(email_address=email_address).all()
                for token in all_tokens:
                    logger.info(f"[토큰 세부 정보] fcm_token={token.fcm_token}, client_state={token.client_state}")
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
                    logger.info(f"msg_id {msg_id}에 대해 {token.fcm_token}으로 Outlook 푸시 전송")
            except Exception as e:
                logger.error(f"msg_id {msg_id}에 대한 Outlook 웹훅 처리 실패: {e}")
                continue

    return jsonify({'status': 'outlook_pushed'}), 200