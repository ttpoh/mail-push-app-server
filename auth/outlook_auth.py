import time
import logging
import requests
from datetime import datetime, timedelta, timezone
from urllib.parse import urljoin
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from sqlalchemy.orm import Session
from infra.db import SessionLocal
from models.gmail_users import GmailToken
from models.outlook_users import OutlookToken
from msal import ConfidentialClientApplication

logger = logging.getLogger(__name__)

class OutlookAuth:
    def __init__(self, client_id: str, client_secret: str, tenant: str = 'common', notify_url: str = 'https://mail-push.xtect.net/outlook_webhook'):
        self.CLIENT_ID = client_id
        self.CLIENT_SECRET = client_secret
        self.AUTHORITY = f'https://login.microsoftonline.com/{tenant}'
        self.SCOPES = ['User.Read', 'Mail.Read', 'offline_access']
        self.app = ConfidentialClientApplication(
            self.CLIENT_ID,
            authority=self.AUTHORITY,
            client_credential=self.CLIENT_SECRET
        )
        self.notify_url = notify_url

    def _refresh_token(self, token):
        result = self.app.acquire_token_by_refresh_token(
            token.refresh_token,
            scopes=self.SCOPES
        )
        if 'access_token' not in result:
            raise RuntimeError(f"Token refresh failed: {result.get('error_description', 'Unknown error')}")

        token.access_token = result['access_token']
        if 'expires_in' in result:
            token.expires_at = datetime.utcnow() + timedelta(seconds=result['expires_in'])
        self._save_token(token)
        return token.access_token

    def _save_token(self, token):
        with SessionLocal() as db:
            db.merge(token)
            db.commit()

    def _ensure_valid_token(self, token):
        if not token:
            raise RuntimeError('No tokens stored')
        if token.expires_at and datetime.utcnow() >= token.expires_at:
            return self._refresh_token(token)
        return token.access_token

    def get_valid_token(self, fcm_token: str):
        with SessionLocal() as db:
            token = db.query(OutlookToken).filter_by(fcm_token=fcm_token).first()
            return self._ensure_valid_token(token)

    def get_fcm_token_by_client_state(self, client_state: str) -> str:
        with SessionLocal() as db:
            token = db.query(OutlookToken).filter_by(client_state=client_state).first()
            if not token:
                raise KeyError(f"No fcm_token found for client_state: {client_state}")
            return token.fcm_token

    def get_user_email(self, access_token: str) -> str:
        headers = {'Authorization': f'Bearer {access_token}', 'Content-Type': 'application/json'}
        try:
            resp = requests.get('https://graph.microsoft.com/v1.0/me', headers=headers, timeout=10)
            resp.raise_for_status()
            user_info = resp.json()
            return user_info.get('mail') or user_info.get('userPrincipalName')
        except Exception as e:
            logger.error(f"Failed to get email from /me endpoint: {e}")
            return None
        

    def watch(self, fcm_token, access_token, resource, change_type, notification_url, client_state):
        headers = {'Authorization': f'Bearer {access_token}', 'Content-Type': 'application/json'}
        expiration_time = datetime.now(timezone.utc) + timedelta(hours=1)
        expiration_str = expiration_time.replace(microsecond=0).isoformat().replace('+00:00', 'Z')
        body = {
            'changeType': change_type,
            'notificationUrl': notification_url,
            'resource': resource,
            'expirationDateTime': expiration_str,
            'clientState': client_state
        }
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
            token.resource = resource
            token.expires_at = datetime.utcnow() + timedelta(hours=1)
            db.add(token)
            db.commit()

        return subscription

    def get_message(self, fcm_token: str, message_id: str) -> dict:
        token = self.get_valid_token(fcm_token)
        url = urljoin('https://graph.microsoft.com/v1.0/', f"me/messages/{message_id}")
        headers = {'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'}
        resp = requests.get(url, headers=headers)
        resp.raise_for_status()
        return resp.json()
