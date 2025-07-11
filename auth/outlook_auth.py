import time
import logging
import requests
from datetime import datetime, timedelta, timezone
from urllib.parse import urljoin
from msal import ConfidentialClientApplication
from sqlalchemy.orm import Session
from infra.db import SessionLocal
from models.outlook_users import OutlookToken

logger = logging.getLogger(__name__)

class OutlookAuth:
    def __init__(self, client_id: str, client_secret: str, tenant: str = 'common', notify_url: str = 'https://mail-push.xtect.net/outlook_webhook'):
        self.CLIENT_ID = client_id
        self.CLIENT_SECRET = client_secret
        self.AUTHORITY = f'https://login.microsoftonline.com/{tenant}'
        self.SCOPES = ['User.Read', 'Mail.Read', 'offline_access']
        self.REFRESH_SCOPES = ['User.Read', 'Mail.Read']  #
        self.app = ConfidentialClientApplication(
            self.CLIENT_ID,
            authority=self.AUTHORITY,
            client_credential=self.CLIENT_SECRET
        )
        self.notify_url = notify_url

    def _refresh_token(self, token: OutlookToken, db: Session) -> str:
        if not token.refresh_token:
            raise RuntimeError("리프레시 토큰이 없습니다")
        
        result = self.app.acquire_token_by_refresh_token(
            token.refresh_token,
            scopes=self.REFRESH_SCOPES
        )
        if 'access_token' not in result:
            error = result.get('error_description', '알 수 없는 오류')
            logger.error(f"토큰 갱신 실패: {error}")
            raise RuntimeError(f"토큰 갱신 실패: {error}")

        token.access_token = result['access_token']
        token.access_token_exp = datetime.utcnow() + timedelta(seconds=result['expires_in'] - 30)  # 안전을 위한 버퍼
        token.updated_at = datetime.utcnow()
        db.merge(token)
        db.commit()
        logger.info(f"fcm_token에 대한 토큰 갱신: {token.fcm_token}")
        return token.access_token

    def _ensure_valid_token(self, token: OutlookToken, db: Session) -> str:
        logger.info(f"_ensure_valid_token: {token.access_token_exp}")

        if not token:
            raise RuntimeError("저장된 토큰이 없습니다")
        # access_token_exp가 없거나, 만료되었거나, 5분 이내 만료될 경우 토큰 갱신
        if not token.access_token_exp or \
            token.access_token_exp <= datetime.utcnow() + timedelta(minutes=1):
            logger.info(f"_refresh_token in _ensure_valid_token")
            return self._refresh_token(token, db)
        
        return token.access_token

    def get_valid_token(self, fcm_token: str) -> str:
        with SessionLocal() as db:
            token = db.query(OutlookToken).filter_by(fcm_token=fcm_token).first()
            if not token:
                logger.error(f"fcm_token에 대한 토큰 없음: {fcm_token}")
                raise RuntimeError("토큰을 찾을 수 없습니다")
            return self._ensure_valid_token(token, db)

    def get_fcm_token_by_client_state(self, client_state: str) -> str:
        with SessionLocal() as db:
            token = db.query(OutlookToken).filter_by(client_state=client_state).first()
            if not token:
                logger.error(f"client_state에 대한 fcm_token 없음: {client_state}")
                raise KeyError(f"client_state에 대한 fcm_token을 찾을 수 없습니다: {client_state}")
            return token.fcm_token

    def get_user_email(self, access_token: str) -> str:
        headers = {'Authorization': f'Bearer {access_token}', 'Content-Type': 'application/json'}
        try:
            resp = requests.get('https://graph.microsoft.com/v1.0/me', headers=headers, timeout=10)
            resp.raise_for_status()
            user_info = resp.json()
            return user_info.get('mail') or user_info.get('userPrincipalName')
        except Exception as e:
            logger.error(f"/me 엔드포인트에서 이메일 가져오기 실패: {e}")
            return None

    def watch(self, fcm_token: str, access_token: str, resource: str, change_type: str, notification_url: str, client_state: str):
        headers = {'Authorization': f'Bearer {access_token}', 'Content-Type': 'application/json'}
        expiration_time = datetime.now(timezone.utc) + timedelta(minutes=1)
        expiration_str = expiration_time.replace(microsecond=0).isoformat().replace('+00:00', 'Z')
        body = {
            'changeType': change_type,
            'notificationUrl': notification_url,
            'resource': resource,
            'expirationDateTime': expiration_str,
            'clientState': client_state
        }
        try:
            resp = requests.post('https://graph.microsoft.com/v1.0/subscriptions', headers=headers, json=body, timeout=15)
            resp.raise_for_status()
            subscription = resp.json()
            subscription_id = subscription.get('id')

            with SessionLocal() as db:
                token = db.query(OutlookToken).filter_by(fcm_token=fcm_token).first()
                if not token:
                    token = OutlookToken(fcm_token=fcm_token)
                token.access_token = access_token
                token.client_state = client_state
                token.subscription_id = subscription_id
                token.subscription_exp = datetime.utcnow() + timedelta(minutes=1)
                token.access_token_exp = datetime.utcnow() + timedelta(minutes=1)
                token.email_address = self.get_user_email(access_token)
                db.merge(token)
                db.commit()

            logger.info(f"구독 생성됨: {subscription_id}, fcm_token: {fcm_token}")
            return subscription
        except requests.HTTPError as e:
            logger.error(f"구독 생성 실패: {e}")
            raise

    def renew_subscription(self, fcm_token: str, subscription_id: str):
        logger.info(f"in renew_subscription: {subscription_id}")

        with SessionLocal() as db:
            token = db.query(OutlookToken).filter_by(fcm_token=fcm_token).first()
            if not token:
                logger.error(f"fcm_token에 대한 토큰 없음: {fcm_token}")
                raise RuntimeError("토큰을 찾을 수 없습니다")
            
            access_token = self._ensure_valid_token(token, db)
            headers = {'Authorization': f'Bearer {access_token}', 'Content-Type': 'application/json'}
            expiration_time = datetime.now(timezone.utc) + timedelta(minutes=1)
            expiration_str = expiration_time.replace(microsecond=0).isoformat().replace('+00:00', 'Z')
            body = {
                'expirationDateTime': expiration_str
            }
            try:
                resp = requests.patch(f'https://graph.microsoft.com/v1.0/subscriptions/{subscription_id}', headers=headers, json=body, timeout=15)
                resp.raise_for_status()
                subscription = resp.json()
                logger.info(f"subscription in renew_subscriptionn: {subscription}")

                # API 응답에서 subscription_id와 expirationDateTime 업데이트
                token.subscription_id = subscription.get('id', subscription_id)  # 새로운 ID가 있으면 업데이트
                logger.info(f"token.subscription_id: {token.subscription_id}")

                expiration_datetime = datetime.fromisoformat(subscription.get('expirationDateTime').replace('Z', '+00:00'))
                logger.info(f"expiration_datetime: {expiration_datetime}")

                token.subscription_exp = expiration_datetime
                token.updated_at = datetime.utcnow()
                db.merge(token)
                db.commit()
                logger.info(f"구독 {subscription_id} 갱신됨, fcm_token: {fcm_token}")
            except requests.HTTPError as e:
                logger.error(f"구독 {subscription_id} 갱신 실패: {e}")
                raise