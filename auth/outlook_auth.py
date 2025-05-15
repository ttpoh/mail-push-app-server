import time
import json
import requests
import logging
import datetime
from msal import ConfidentialClientApplication
from threading import Lock
from urllib.parse import urljoin
import uuid

# Logging setup
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class OutlookAuth:
    """
    Manages Outlook authentication, token refresh, and Microsoft Graph API subscriptions.
    - token_store: { fcm_token: { 'access_token', 'refresh_token', 'expires_at', 'email_address', 'state_id' } }
    - Uses MSAL ConfidentialClientApplication for token refresh.
    - Creates subscriptions for /me/mailFolders('Inbox')/messages via Graph API.
    """

    def __init__(self,
                 client_id: str,
                 client_secret: str,
                 tenant: str = 'common',
                 notify_url: str = 'https://mail-push.xtect.net/outlook_webhook'):
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
        self.token_store = {}  # { fcm_token: { access_token, refresh_token, expires_at, email_address, state_id } }
        self._lock = Lock()

    def _store_tokens(self, fcm_token: str, result: dict, state_id: str = None, email_address: str = None):
        expires_in = result.get('expires_in', 3600)
        with self._lock:
            self.token_store[fcm_token] = {
                'access_token': result['access_token'],
                'refresh_token': result.get('refresh_token'),
                'expires_at': time.time() + expires_in - 60,  # 60 seconds buffer
                'email_address': email_address or self.token_store.get(fcm_token, {}).get('email_address'),
                'state_id': state_id or self.token_store.get(fcm_token, {}).get('state_id')
            }
        logger.info(f"Tokens stored for fcm_token: {fcm_token}, state_id: {state_id}, email: {email_address}")

    def _get_token_entry(self, fcm_token: str):
        return self.token_store.get(fcm_token)

    def get_fcm_token_by_state_id(self, state_id: str) -> str:
        """Retrieve fcm_token by state_id"""
        with self._lock:
            for fcm_token, entry in self.token_store.items():
                if entry.get('state_id') == state_id:
                    return fcm_token
            logger.error(f"No fcm_token found for state_id: {state_id}")
            raise KeyError(f"No fcm_token found for state_id: {state_id}")

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
        
        self._store_tokens(fcm_token, result, entry.get('state_id'), entry.get('email_address'))
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

    def watch(self, fcm_token: str, access_token: str, refresh_token: str = None):
        """Store tokens and create a Microsoft Graph subscription for inbox messages"""
        # Generate state_id
        state_id = uuid.uuid4().hex
        
        # Fetch email address to store
        headers = {'Authorization': f'Bearer {access_token}'}
        resp = requests.get('https://graph.microsoft.com/v1.0/me', headers=headers)
        if resp.status_code != 200:
            logger.error(f"Failed to fetch Outlook profile: {resp.status_code} {resp.text}")
            raise RuntimeError("Invalid access token")
        profile = resp.json()
        email_address = profile.get('mail') or profile.get('userPrincipalName')
        
        # Store tokens
        self._store_tokens(fcm_token, {
            'access_token': access_token,
            'refresh_token': refresh_token,
            'expires_in': 3600
        }, state_id, email_address)
        
        # Create subscription
        subscription_endpoint = 'https://graph.microsoft.com/v1.0/subscriptions'
        expiration = datetime.datetime.utcnow() + datetime.timedelta(days=3)
        expiration_iso = expiration.isoformat() + 'Z'

        body = {
            "changeType": "created",
            "notificationUrl": self.notify_url,
            "resource": "me/mailFolders('Inbox')/messages",
            "expirationDateTime": expiration_iso,
            "clientState": state_id
        }

        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json'
        }
        try:
            resp = requests.post(subscription_endpoint, headers=headers, json=body)
            resp.raise_for_status()
            subscription = resp.json()
            logger.info(f"Subscription created for fcm_token: {fcm_token}, state_id: {state_id}, sub_id: {subscription.get('id')}")
            return subscription
        except requests.exceptions.HTTPError as e:
            logger.error(f"Subscription creation failed: {e.response.status_code} {e.response.text}")
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