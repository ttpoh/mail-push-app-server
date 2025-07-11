import json
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

logger = logging.getLogger(__name__)

class GmailAuth:
    def __init__(self):
        self.SCOPES = ['https://www.googleapis.com/auth/gmail.modify']
        with open('credentials.json') as f:
            creds_data = json.load(f)
            self.CLIENT_ID = creds_data['web']['client_id']
            self.CLIENT_SECRET = creds_data['web']['client_secret']
            self.TOKEN_URI = creds_data['web']['token_uri']

    def _get_credentials(self, token):
        creds = Credentials(
            token=token.access_token,
            refresh_token=token.refresh_token,
            token_uri='https://oauth2.googleapis.com/token',
            client_id=self.CLIENT_ID,
            client_secret=self.CLIENT_SECRET,
            scopes=self.SCOPES
        )
        logger.info(f"creds.expired create in _get_credentials: {creds.expired}")
        logger.info(f"creds.refresh_token create in _get_credentials: {creds.refresh_token}")

        if creds.expired and creds.refresh_token:
            new_token = self._manual_refresh(token.refresh_token)
            token.access_token = new_token
            new_expiry = datetime.utcnow() + timedelta(hours=1)
            token.expired_at = new_expiry
            self._save_token(token)
            creds = Credentials(
                token=new_token,
                refresh_token=token.refresh_token,
                token_uri='https://oauth2.googleapis.com/token',
                client_id=self.CLIENT_ID,
                client_secret=self.CLIENT_SECRET,
                scopes=self.SCOPES
            )
        logger.info(f"creds create in _get_credentials: {creds}")

        return creds

    def _manual_refresh(self, refresh_token: str) -> str:
        payload = {
            'grant_type': 'refresh_token',
            'refresh_token': refresh_token,
            'client_id': self.CLIENT_ID,
            'client_secret': self.CLIENT_SECRET
        }
        r = requests.post('https://oauth2.googleapis.com/token', data=payload)
        r.raise_for_status()
 
        logger.info(f"access_token in _manual_refresh{r.json()['access_token']}")
        return r.json()['access_token']

    def _save_token(self, token):
        with SessionLocal() as db:
            db.merge(token)
            db.commit()

    def watch(self, fcm_token, access_token, refresh_token, email_address):
        db = SessionLocal()
        try:
            logger.info(f"Processing Gmail token for fcm_token: {fcm_token}, email_address: {email_address}")

            # Gmail API 클라이언트 생성
            creds = Credentials(
                token=access_token,
                refresh_token=refresh_token,
                token_uri=self.TOKEN_URI,
                client_id=self.CLIENT_ID,
                client_secret=self.CLIENT_SECRET,
                scopes=self.SCOPES
            )
            service = build('gmail', 'v1', credentials=creds)
            request = {
                'labelIds': ['INBOX'],
                'topicName': 'projects/mail-push-app-815d4/topics/gmail-notifications'
            }
            watch_response = service.users().watch(userId='me', body=request).execute()
            logger.info(f"Set Pub/Sub watch for fcm_token: {fcm_token}, response: {watch_response}")

            # fcm_token으로 기존 토큰 확인
            existing_token = db.query(GmailToken).filter_by(fcm_token=fcm_token).first()

            if existing_token:
                # 동일 fcm_token이면 업데이트
                logger.info(f"Updating existing token for fcm_token: {fcm_token}, email_address: {email_address}")
                existing_token.access_token = access_token
                existing_token.refresh_token = refresh_token
                existing_token.email_address = email_address
                existing_token.last_history_id = watch_response.get('historyId')
                existing_token.expired_at = datetime.utcnow() + timedelta(hours=1)            
                existing_token.updated_at = datetime.utcnow()
            else:
                # 새 fcm_token이면 새 레코드 생성
                logger.info(f"Creating new token for fcm_token: {fcm_token}, email_address: {email_address}")
                new_token = GmailToken(
                    fcm_token=fcm_token,
                    access_token=access_token,
                    refresh_token=refresh_token,
                    email_address=email_address,
                    last_history_id=watch_response.get('historyId'),
                    expired_at=datetime.utcnow() + timedelta(hours=1),
                    created_at=datetime.utcnow(),
                    updated_at=datetime.utcnow()
                )
                db.add(new_token)

            db.commit()
            db.refresh(existing_token if existing_token else new_token)
            logger.info(f"Token committed successfully for fcm_token: {fcm_token}")
            return existing_token if existing_token else new_token
        except HttpError as e:
            db.rollback()
            logger.error(f"Gmail API error: {str(e)}")
            raise Exception(f"Gmail token update failed: {str(e)}")
        except Exception as e:
            db.rollback()
            logger.error(f"Gmail token update failed: {str(e)}")
            raise Exception(f"Gmail token update failed: {str(e)}")
        finally:
            db.close()

    def get_valid_token(self, fcm_token: str):
        with SessionLocal() as db:
            token = db.query(GmailToken).filter_by(fcm_token=fcm_token).first()
            if not token:
                raise RuntimeError("No Gmail token found")
            creds = self._get_credentials(token)
            return creds.token

    def get_message_labels(self, fcm_token, message_id):
        try:
            with SessionLocal() as db:
                token = db.query(GmailToken).filter_by(fcm_token=fcm_token).first()
                if not token:
                    raise RuntimeError("No Gmail token found")
                creds = self._get_credentials(token)
                service = build('gmail', 'v1', credentials=creds)
                message = service.users().messages().get(userId='me', id=message_id).execute()
                labels = message.get('labelIds', [])
                logger.info(f"메시지 {message_id}의 라벨: {labels}")
                return labels
        except Exception as e:
            logger.error(f"메시지 라벨 조회 오류: {e}")
            return []