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
from google.auth.transport.requests import Request
from google.auth.exceptions import RefreshError

logger = logging.getLogger(__name__)

class GmailAuth:
    def __init__(self):
        data = json.load(open('credentials.json'))
        # web 자격증명만 사용
        web = data['web']
        self.CLIENT_ID     = web['client_id']
        self.CLIENT_SECRET = web['client_secret']
        self.TOKEN_URI     = web['token_uri']
        self.SCOPES        = ['https://www.googleapis.com/auth/gmail.modify']
        logger.debug(f"Initialized GmailAuth with client_id: {self.CLIENT_ID}, token_uri: {self.TOKEN_URI}, scopes: {self.SCOPES}")

    def _get_credentials(self, token):
        logger.debug(f"Entering _get_credentials with token: fcm_token={token.fcm_token}, access_token={token.access_token[:10]}..., refresh_token={'present' if token.refresh_token else 'missing'}, expired_at={token.expired_at}")
        
        creds = Credentials(
            token=token.access_token,
            refresh_token=token.refresh_token,
            token_uri=self.TOKEN_URI,
            client_id=self.CLIENT_ID,
            client_secret=self.CLIENT_SECRET,
            scopes=self.SCOPES,
            expiry=token.expired_at,
        )
        logger.info(f"creds.expired in _get_credentials: {creds.expired}")
        logger.info(f"creds._enable_reauth_refresh in _get_credentials: {creds._enable_reauth_refresh}")
        logger.debug(f"Credentials created: client_id={self.CLIENT_ID}, token_uri={self.TOKEN_URI}, scopes={self.SCOPES}, refresh_token={'present' if creds.refresh_token else 'missing'}")

        if creds.expired and creds.refresh_token:
            logger.info("▶ Entered refresh block")
            try:
                logger.debug("Attempting to refresh token using google-auth library")
                creds.refresh(Request())
                logger.info(f"Token refreshed successfully: new_access_token={creds.token[:10]}..., new_expiry={creds.expiry}")
                token.access_token = creds.token
                token.expired_at = creds.expiry
                self._save_token(token)
            except RefreshError as e:
                logger.error(f"라이브러리 refresh 실패: {str(e)}")
                logger.error(f"RefreshError details: args={e.args}")
                # Google 서버 응답이 있는 경우 추가 로깅
                if hasattr(e, 'response') and e.response:
                    try:
                        response_json = e.response.json()
                        logger.error(f"Google API response: {json.dumps(response_json, indent=2)}")
                    except ValueError:
                        logger.error(f"Google API response (non-JSON): {e.response.text}")
                
                # 대체로 _manual_refresh 시도
                logger.info("Attempting manual refresh as fallback")
                try:
                    new_access_token = self._manual_refresh(token.refresh_token)
                    creds.token = new_access_token
                    token.access_token = new_access_token
                    token.expired_at = datetime.utcnow() + timedelta(hours=1)  # 수동 갱신 시 임시 만료 시간 설정
                    self._save_token(token)
                    logger.info(f"Manual refresh successful: new_access_token={new_access_token[:10]}...")
                except Exception as manual_err:
                    logger.error(f"수동 refresh 실패: {str(manual_err)}")
                    # 디버깅 정보 저장
                    debug_info = {
                        "fcm_token": token.fcm_token,
                        "client_id": self.CLIENT_ID,
                        "token_uri": self.TOKEN_URI,
                        "scopes": self.SCOPES,
                        "refresh_token": "present" if token.refresh_token else "missing",
                        "expired_at": str(token.expired_at),
                        "error": str(e),
                        "manual_refresh_error": str(manual_err)
                    }
                    logger.error(f"Debug info: {json.dumps(debug_info, indent=2)}")
                    raise Exception(f"Token refresh failed: library_error={str(e)}, manual_error={str(manual_err)}")
        else:
            logger.debug(f"Token refresh skipped: expired={creds.expired}, refresh_token={'present' if creds.refresh_token else 'missing'}")

        logger.debug(f"Returning creds: access_token={creds.token[:10]}..., expiry={creds.expiry}")
        return creds

    def _manual_refresh(self, refresh_token: str) -> str:
        logger.debug(f"Entering _manual_refresh with refresh_token={'present' if refresh_token else 'missing'}")
        payload = {
            'grant_type': 'refresh_token',
            'refresh_token': refresh_token,
            'client_id': self.CLIENT_ID,
            'client_secret': self.CLIENT_SECRET
        }
        try:
            r = requests.post(self.TOKEN_URI, data=payload)
            r.raise_for_status()
            response_json = r.json()
            logger.info(f"Manual refresh response: access_token={response_json['access_token'][:10]}..., expires_in={response_json.get('expires_in')}")
            return response_json['access_token']
        except requests.exceptions.HTTPError as e:
            logger.error(f"HTTP error in _manual_refresh: {str(e)}")
            if e.response:
                logger.error(f"HTTP response: {e.response.text}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error in _manual_refresh: {str(e)}")
            raise

    def _save_token(self, token):
        with SessionLocal() as db:
            logger.debug(f"Saving token for fcm_token={token.fcm_token}, access_token={token.access_token[:10]}..., expired_at={token.expired_at}")
            db.merge(token)
            db.commit()
            logger.debug("Token saved successfully")

    def watch(self, fcm_token, access_token, refresh_token, email_address):
        db = SessionLocal()
        try:
            logger.info(f"Processing Gmail token for fcm_token: {fcm_token}, email_address: {email_address}")
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

            existing_token = db.query(GmailToken).filter_by(fcm_token=fcm_token).first()
            if existing_token:
                logger.info(f"Updating existing token for fcm_token: {fcm_token}, email_address: {email_address}")
                existing_token.access_token = access_token
                existing_token.refresh_token = refresh_token
                existing_token.email_address = email_address
                existing_token.last_history_id = watch_response.get('historyId')
                existing_token.expired_at = datetime.utcnow() + timedelta(hours=1)
                existing_token.updated_at = datetime.utcnow()
            else:
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
            logger.debug(f"Token committed successfully for fcm_token: {fcm_token}")
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
                logger.error(f"No Gmail token found for fcm_token: {fcm_token}")
                raise RuntimeError("No Gmail token found")
            try:
                creds = self._get_credentials(token)
                logger.debug(f"Returning valid token for fcm_token: {fcm_token}, access_token: {creds.token[:10]}...")
                return creds.token
            except Exception as e:
                logger.error(f"Failed to get valid token for fcm_token {fcm_token}: {str(e)}")
                raise

    def get_message_labels(self, fcm_token, message_id):
        try:
            with SessionLocal() as db:
                token = db.query(GmailToken).filter_by(fcm_token=fcm_token).first()
                if not token:
                    logger.error(f"No Gmail token found for fcm_token: {fcm_token}")
                    raise RuntimeError("No Gmail token found")
                creds = self._get_credentials(token)
                service = build('gmail', 'v1', credentials=creds)
                message = service.users().messages().get(userId='me', id=message_id).execute()
                labels = message.get('labelIds', [])
                logger.info(f"메시지 {message_id}의 라벨: {labels}")
                return labels
        except Exception as e:
            logger.error(f"메시지 라벨 조회 오류: {str(e)}")
            return []