import time
import json
import requests
import logging
from datetime import datetime, timedelta, timezone  # timezone 제거from msal import ConfidentialClientApplication
from threading import Lock
from urllib.parse import urljoin
import uuid
from msal import ConfidentialClientApplication
# Logging setup
logging.basicConfig(level=logging.INFO)
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
        self.token_store = {}  # { fcm_token: { access_token, refresh_token, expires_at, email_address, client_state }}
        self.client_state_to_fcm = {}  # {client_state: fcm_token}
        self._lock = Lock()

    def _store_tokens(self, fcm_token: str, result: dict, client_state: str = None, email_address: str = None):
        expires_in = result.get('expires_in', 3600)
        with self._lock:
            self.token_store[fcm_token] = {
                'access_token': result['access_token'],
                'refresh_token': result.get('refresh_token'),
                'client_state': client_state or self.token_store.get(fcm_token, {}).get('client_state'),
                'email_address': email_address or self.token_store.get(fcm_token, {}).get('email_address'),
                'expires_at': time.time() + expires_in - 60  # 60 seconds buffer
            }
            if client_state:
                self.client_state_to_fcm[client_state] = fcm_token
        logger.info(f"Tokens stored for fcm_token: {fcm_token}, client_state: {client_state}, email: {email_address}")

    def _get_token_entry(self, fcm_token: str):
        return self.token_store.get(fcm_token)

    def get_fcm_token_by_client_state(self, client_state: str) -> str:
        """Retrieve fcm_token by client_state from client_state_to_fcm mapping"""
        with self._lock:
            fcm_token = self.client_state_to_fcm.get(client_state)
            if not fcm_token:
                logger.error(f"No fcm_token found for client_state: {client_state}")
                logger.debug(f"Current client_state_to_fcm: {self.client_state_to_fcm}")
                raise KeyError(f"No fcm_token found for client_state: {client_state}")
            logger.debug(f"Found fcm_token {fcm_token} for client_state: {client_state}")
            return fcm_token

    def _refresh_token(self, fcm_token: str):
        """Refresh token using MSAL"""
        entry = self._get_token_entry(fcm_token)
        if not entry or 'refresh_token' not in entry:
            logger.error(f"No refresh token available for fcm_token: {fcm_token}")
            raise RuntimeError("No refresh token available")

        result = self.app.acquire_token_by_refresh_token(
            entry['refresh_token'],
            scopes=self.SCOPES
        )
        if 'access_token' not in result:
            error_desc = result.get('error_description', 'Unknown error')
            logger.error(f"Token refresh failed for fcm_token {fcm_token}: {error_desc}")
            raise RuntimeError(f"Token refresh failed: {error_desc}")

        self._store_tokens(fcm_token, result, entry.get('client_state'), entry.get('email_address'))
        logger.info(f"Token refreshed for fcm_token: {fcm_token}")
        return self.token_store[fcm_token]['access_token']

    def _ensure_valid_token(self, fcm_token: str):
        """Return a valid access token, refreshing if necessary"""
        with self._lock:
            entry = self._get_token_entry(fcm_token)
            if not entry:
                logger.error(f"No token entry for fcm_token: {fcm_token}")
                raise RuntimeError('No tokens stored for this fcm_token')

            if time.time() >= entry['expires_at']:
                logger.info(f"Token expired for fcm_token: {fcm_token}, refreshing")
                return self._refresh_token(fcm_token)

            logger.debug(f"Using existing token for fcm_token: {fcm_token}")
            return entry['access_token']
        
    def get_user_email(self, access_token: str) -> str:
        """Fetch the user's primary email address using the /me endpoint"""
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json'
        }
        try:
            resp = requests.get('https://graph.microsoft.com/v1.0/me', headers=headers, timeout=10)
            resp.raise_for_status()
            user_info = resp.json()
            email = user_info.get('mail') or user_info.get('userPrincipalName')
            if not email:
                raise ValueError("Email address not found in /me response")
            logger.info(f"Fetched email address from /me: {email}")
            return email
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to fetch user email: {str(e)}", exc_info=True)
            raise


    def watch(self, fcm_token, access_token, resource, change_type, notification_url, client_state):
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json'
        }
        expiration_time = datetime.now(timezone.utc) + timedelta(hours=1)
        expiration_str = expiration_time.replace(microsecond=0).isoformat().replace('+00:00', 'Z')
        body = {
            'changeType': change_type,
            'notificationUrl': notification_url,
            'resource': resource,
            'expirationDateTime': expiration_str,
            'clientState': client_state
        }
        try:
            logger.info(f"Creating Outlook subscription for fcm_token: {fcm_token}, resource: {resource}, client_state: {client_state}")
            resp = requests.post(
                'https://graph.microsoft.com/v1.0/subscriptions',
                headers=headers,
                json=body,
                timeout=15
            )
            resp.raise_for_status()
            subscription = resp.json()
            subscription_id = subscription.get('id')
            logger.info(f"Subscription created with ID: {subscription_id}, client_state: {client_state}")
            logger.debug(f"Full Graph API response: {json.dumps(subscription, indent=2)}")

            with self._lock:
                self.client_state_to_fcm[client_state] = fcm_token
                if fcm_token in self.token_store:
                    self.token_store[fcm_token].update({
                        'subscription_id': subscription_id,
                        'resource': resource,
                        'client_state': client_state
                    })
                else:
                    logger.warning(f"fcm_token {fcm_token} not in token_store during watch")
                    self.token_store[fcm_token] = {
                        'access_token': access_token,
                        'refresh_token': None,
                        'client_state': client_state,
                        'subscription_id': subscription_id,
                        'resource': resource,
                        'expires_at': time.time() + 3600 - 60
                    }
                logger.debug(f"Updated client_state_to_fcm: {self.client_state_to_fcm}")

            from app import save_token_stores
            save_token_stores()
            return subscription
        
        except requests.exceptions.Timeout:
            logger.error("Timeout while creating subscription with Microsoft Graph API")
            raise
        except requests.exceptions.HTTPError as e:
            logger.error(f"Microsoft Graph API error: {e.response.status_code} {e.response.text}")
            raise
        except Exception as e:
            logger.error(f"Failed to create Outlook subscription: {e}", exc_info=True)
            raise

    def get_valid_token(self, fcm_token: str) -> str:
        """Return a valid access token for API calls"""
        return self._ensure_valid_token(fcm_token)

    def get_message(self, fcm_token: str, message_id: str) -> dict:
        """Retrieve details of a specific message"""
        token = self.get_valid_token(fcm_token)
        url = urljoin('https://graph.microsoft.com/v1.0/', f"me/messages/{message_id}")
        headers = {'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'}
        try:
            resp = requests.get(url, headers=headers)
            resp.raise_for_status()
            return resp.json()
        except requests.exceptions.HTTPError as e:
            logger.error(f"Message retrieval failed for message_id {message_id}: {e.response.status_code} {e.response.text}")
            raise