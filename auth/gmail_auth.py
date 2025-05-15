from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
from googleapiclient.errors import HttpError
import requests

class GmailAuth:
    def __init__(self):
        self.SCOPES = ['https://www.googleapis.com/auth/gmail.modify']
        # Flutter에서 사용하는 native 앱용 public client ID
        self.CLIENT_ID = '896564723347-ooift0gpd2idsgmllnoll75gjju646ai.apps.googleusercontent.com'
        # public client에서는 secret 없음
        self.CLIENT_SECRET = None
        self.token_store = {}  # { fcm_token: {'access_token': ..., 'refresh_token': ...} }

    def watch(self, fcm_token: str, access_token: str, refresh_token: str):
        # 토큰 저장
        self.token_store[fcm_token] = {
            'access_token': access_token,
            'refresh_token': refresh_token
        }
        creds = self._get_credentials(fcm_token)
        service = build('gmail', 'v1', credentials=creds)
        body = {'labelIds': ['INBOX'], 'topicName': 'projects/alarm-mail-app/topics/gmail-notifications'}
        try:
            return service.users().watch(userId='me', body=body).execute()
        except HttpError as e:
            print(f"Watch 요청 실패: {e}")
            raise

    def _get_credentials(self, fcm_token: str) -> Credentials:
        tokens = self.token_store[fcm_token]
        creds = Credentials(
            token=tokens['access_token'],
            refresh_token=tokens['refresh_token'],
            token_uri='https://oauth2.googleapis.com/token',
            client_id=self.CLIENT_ID,
            scopes=self.SCOPES
        )
        # expired 시 manual refresh
        if creds.expired and creds.refresh_token:
            new_token = self._manual_refresh(tokens['refresh_token'])
            tokens['access_token'] = new_token
            creds = Credentials(
                token=new_token,
                refresh_token=creds.refresh_token,
                token_uri=creds.token_uri,
                client_id=self.CLIENT_ID,
                scopes=self.SCOPES
            )
        return creds

    def _manual_refresh(self, refresh_token: str) -> str:
        payload = {
            'grant_type': 'refresh_token',
            'refresh_token': refresh_token,
            'client_id': self.CLIENT_ID
        }
        r = requests.post('https://oauth2.googleapis.com/token', data=payload)
        r.raise_for_status()
        return r.json()['access_token']

    def get_valid_token(self, fcm_token):
        creds = self._get_credentials(fcm_token)
        return creds.token

    def get_message_labels(self, fcm_token, message_id):
        try:
            creds = self._get_credentials(fcm_token)
            service = build('gmail', 'v1', credentials=creds)
            message = service.users().messages().get(userId='me', id=message_id).execute()
            labels = message.get('labelIds', [])
            print(f"메시지 {message_id}의 라벨: {labels}")
            return labels
        except Exception as e:
            print(f"메시지 라벨 조회 오류: {e}")
            return []
