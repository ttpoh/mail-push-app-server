from flask import Blueprint, request, jsonify
from models.outlook_users import OutlookToken
from infra.db import SessionLocal
import requests
import logging

logger = logging.getLogger(__name__)
logout_outlook_bp = Blueprint('logout_outlook', __name__)

@logout_outlook_bp.route('/api/outlook/logout', methods=['POST'])
def logout_outlook():
    data = request.get_json()
    client_state = data.get('client_state')

    if not client_state:
        return jsonify({'error': 'Missing client_state'}), 400

    try:
        with SessionLocal() as db:
            token_record = db.query(OutlookToken).filter_by(client_state=client_state).first()

            if not token_record:
                return jsonify({'error': 'Token not found'}), 404

            # 구독 ID 삭제 요청
            subscription_id = token_record.subscription_id
            access_token = token_record.access_token

            if subscription_id and access_token:
                try:
                    resp = requests.delete(
                        f'https://graph.microsoft.com/v1.0/subscriptions/{subscription_id}',
                        headers={'Authorization': f'Bearer {access_token}'},
                        timeout=10
                    )
                    logger.info(f"Deleted subscription {subscription_id}: {resp.status_code}")
                except Exception as e:
                    logger.warning(f"Failed to delete subscription {subscription_id}: {e}")

            # DB 토큰 삭제 또는 갱신
            db.delete(token_record)  # 또는 아래처럼 값을 Null 처리
            # token_record.access_token = None
            # token_record.refresh_token = None
            # token_record.subscription_id = None
            # db.add(token_record)

            db.commit()
            return jsonify({'status': 'logout_success'}), 200

    except Exception as e:
        logger.error(f"Error during logout: {e}", exc_info=True)
        return jsonify({'error': 'Internal server error'}), 500
