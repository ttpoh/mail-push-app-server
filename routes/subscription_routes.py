from flask import Blueprint, request, jsonify
import requests
import logging
from datetime import datetime, timedelta
from google.oauth2 import service_account
from google.cloud import pubsub_v1
from google.api_core.exceptions import AlreadyExists, NotFound
from auth.outlook_auth import OutlookAuth
from models.outlook_users import OutlookToken
from models.gmail_users import GmailToken
from infra.db import SessionLocal

logger = logging.getLogger(__name__)
subscription_bp = Blueprint('subscription', __name__)
subscription_gmail_bp = Blueprint('subscription_gmail', __name__)

@subscription_gmail_bp.route('/api/create_gmail_subscription', methods=['POST'])
def create_gmail_subscription():
    project_id = "mail-push-app-815d4"
    topic_id = "gmail-notifications"
    subscription_id = "gmail-subscription"
    push_endpoint = "https://mail-push.xtect.net/pubsub_endpoint"
    service_account_file = "/home/ubuntu/mail-push-server/mail-push-app-815d4-888b7cbde2f4.json"

    # 명시적으로 서비스 계정 credential 로드
    credentials = service_account.Credentials.from_service_account_file(service_account_file)
    subscriber = pubsub_v1.SubscriberClient(credentials=credentials)

    topic_path = f"projects/{project_id}/topics/{topic_id}"
    subscription_path = f"projects/{project_id}/subscriptions/{subscription_id}"

    try:
        # 구독 존재 여부 확인
        subscriber.get_subscription(subscription=subscription_path)
        logger.info(f"Subscription {subscription_id} already exists")
        subscription_exists = True
    except NotFound:
        logger.info(f"Subscription {subscription_id} not found. Proceeding to create it.")
        subscription_exists = False
    except Exception as e:
        logger.error(f"Error checking subscription: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

    if not subscription_exists:
        try:
            subscription = subscriber.create_subscription(
                name=subscription_path,
                topic=topic_path,
                push_config=pubsub_v1.types.PushConfig(
                    push_endpoint=push_endpoint,
                ),
                ack_deadline_seconds=10
            )
            logger.info(f"✅ Subscription created: {subscription.name}")
        except AlreadyExists:
            logger.info(f"Subscription {subscription_id} already exists (race condition)")
        except Exception as e:
            logger.error(f"⚠️ Subscription creation failed: {e}")
            return jsonify({"status": "error", "message": str(e)}), 500

    # ✅ DB에 subscription_id 저장
    try:
        data = request.get_json()
        fcm_token = data.get("fcm_token")
        access_token = data.get("access_token")
        refresh_token = data.get("refresh_token")
        email_address = data.get("email_address")

        if not all([fcm_token, access_token, refresh_token, email_address]):
            return jsonify({"status": "error", "message": "Missing required fields"}), 400

        with SessionLocal() as db:
            token_record = db.query(GmailToken).filter_by(fcm_token=request.json.get("fcm_token")).first()

            if token_record:
                token_record.subscription_id = subscription_id
                token_record.updated_at = datetime.utcnow()
                logger.info(f"Updated existing GmailToken record for FCM token: {fcm_token}")
            else:
                new_record = GmailToken(
                    fcm_token=fcm_token,
                    access_token=access_token,
                    refresh_token=refresh_token,
                    email_address=email_address,
                    subscription_id=subscription_id,
                    created_at=datetime.utcnow(),
                    updated_at=datetime.utcnow(),
                )
                db.add(new_record)
                logger.info(f"Created new GmailToken record for FCM token: {fcm_token}")
            db.commit()

        return jsonify({"status": "success", "subscription": subscription_id}), 200
    except Exception as e:
        logger.error(f"⚠️ DB 저장 실패: {e}")
        return jsonify({"status": "error", "message": f"DB 저장 실패: {e}"}), 500


@subscription_bp.route('/api/create_subscription', methods=['POST'])
def create_subscription():
    data = request.get_json() or {}
    logger.info(f"create_subscription data: {data}")
    
    # 1. Extract access token from Authorization header
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Invalid or missing Authorization header'}), 401
    access_token = auth_header.split(' ')[1]

    # 2. Extract required data
    fcm_token = data.get('fcm_token')
    client_state = data.get('clientState') or data.get('client_state')
    resource = data.get('resource')
    change_type = data.get('changeType')
    notification_url = data.get('notificationUrl')

    if not all([access_token, fcm_token, client_state, resource, change_type, notification_url]):
        return jsonify({'error': 'Missing required fields'}), 400

    try:
        outlook_auth = OutlookAuth(
            client_id=request.headers.get('X-Outlook-Client-Id'),
            client_secret=request.headers.get('X-Outlook-Client-Secret')
        )

        # 3. Create or update token + subscription in one session
        with SessionLocal() as db:
            # (1) Delete existing subscriptions (by client_state or matching email)
            # old_tokens = db.query(OutlookToken).filter(
            #     (OutlookToken.client_state == client_state) |
            #     ((OutlookToken.email_address == db.query(OutlookToken.email_address)
            #         .filter_by(fcm_token=fcm_token).scalar()) &
            #      (OutlookToken.fcm_token != fcm_token))
            # ).all()

            # for tok in old_tokens:
            #     if tok.subscription_id:
            #         try:
            #             requests.delete(
            #                 f'https://graph.microsoft.com/v1.0/subscriptions/{tok.subscription_id}',
            #                 headers={'Authorization': f'Bearer {tok.access_token}'},
            #                 timeout=10
            #             )
            #         except Exception as e:
            #             logger.warning(f"Failed to delete subscription {tok.subscription_id}: {e}")
            #     db.delete(tok)

            # (2) Create new subscription on Microsoft Graph
            subscription = outlook_auth.watch(
                fcm_token=fcm_token,
                access_token=access_token,
                resource=resource,
                change_type=change_type,
                notification_url=notification_url,
                client_state=client_state
            )
            subscription_id = subscription.get('id')

            # (3) Get email address from access token
            email_address = outlook_auth.get_user_email(access_token)
            logger.info(f"Fetched email address for subscription: {email_address}")

                # 기존 client_state가 있는지 확인
            existing = db.query(OutlookToken).filter_by(client_state=client_state).first()

            if existing:
                logger.info(f"Duplicate client_state found, deleting existing: {client_state}")
                db.delete(existing)
                db.commit()  # 꼭 commit 해줘야 실제 삭제됨

            # (4) Insert new token record
            new_token = OutlookToken(
                fcm_token=fcm_token,
                access_token=access_token,
                refresh_token=None,  # 또는 data.get("refresh_token") 사용 가능
                email_address=email_address,
                client_state=client_state,
                subscription_id=subscription_id or None,  # 명시적 설정
                # resource=resource,
                expires_at=datetime.utcnow() + timedelta(hours=1),
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow()
            )
            db.add(new_token)

            try:
                db.commit()
                return jsonify({'status': 'subscription_created', 'subscriptionId': subscription_id}), 200
            except Exception as e:
                db.rollback()
                logger.error(f"Failed to commit new subscription token: {e}", exc_info=True)
                return jsonify({'error': 'Database commit failed'}), 500

    except Exception as e:
        logger.error(f"Subscription creation error: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500
    
def list_outlook_subscriptions(access_token: str):
    url = 'https://graph.microsoft.com/v1.0/subscriptions'
    headers = {
        'Authorization': f'Bearer {access_token}'
    }

    response = requests.get(url, headers=headers)
    if response.ok:
        data = response.json()
        print("Current Subscriptions:")
        for sub in data.get('value', []):
            print(f"ID: {sub['id']}, Resource: {sub['resource']}, Expires: {sub['expirationDateTime']}")
        return data.get('value', [])
    else:
        print("Failed to list subscriptions:", response.text)
        return []