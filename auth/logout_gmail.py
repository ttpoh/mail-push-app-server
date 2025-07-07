from flask import Blueprint, request, jsonify
from infra.db import SessionLocal
from models.gmail_users import GmailToken  # FCM 토큰 저장 테이블
import logging
from google.oauth2 import service_account
from google.cloud import pubsub_v1
from google.api_core.exceptions import NotFound

logout_gmail_bp = Blueprint('logout_gmail', __name__)
logger = logging.getLogger(__name__)

@logout_gmail_bp.route('/api/logout_gmail', methods=['POST'])
def logout_gmail():
    try:
        data = request.get_json()
        fcm_token = data.get('fcm_token')

        if not fcm_token:
            return jsonify({'error': 'Missing fcm_token'}), 400

        with SessionLocal() as db:
            token_entry = db.query(GmailToken).filter_by(fcm_token=fcm_token).first()

            if not token_entry:
                logger.info(f"No GmailToken entry found for fcm_token: {fcm_token}")
                return jsonify({'status': 'ok', 'message': 'Token already removed'}), 200

            # 👉 먼저 Pub/Sub 구독 삭제 처리
            subscription_id = token_entry.subscription_id
            if subscription_id:
                project_id = "mail-push-app-815d4"
                subscription_path = f"projects/{project_id}/subscriptions/{subscription_id}"
                credentials = service_account.Credentials.from_service_account_file(
                    "/home/ubuntu/mail-push-server/mail-push-app-815d4-888b7cbde2f4.json"
                )
                subscriber = pubsub_v1.SubscriberClient(credentials=credentials)

                try:
                    subscriber.delete_subscription(subscription=subscription_path)
                    logger.info(f"✅ Deleted Pub/Sub subscription: {subscription_id}")
                except NotFound:
                    logger.warning(f"⚠️ Pub/Sub subscription not found: {subscription_id}")
                except Exception as e:
                    logger.error(f"❌ Failed to delete Pub/Sub subscription: {e}", exc_info=True)

            # 👉 그 후 DB에서 GmailToken 삭제
            db.delete(token_entry)
            db.commit()
            logger.info(f"✅ Deleted GmailToken for fcm_token: {fcm_token}")

        return jsonify({'status': 'success', 'message': 'Gmail logout and subscription cleanup complete'}), 200

    except Exception as e:
        logger.error(f"❌ Error during Gmail logout: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500
