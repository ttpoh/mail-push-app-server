# renew_task.py
import logging
import os
from infra.db import SessionLocal
from models.outlook_users import OutlookToken
from auth.outlook_auth import OutlookAuth
from datetime import datetime, timedelta
from models.gmail_users import GmailToken
from auth.gmail_auth import GmailAuth

logger = logging.getLogger(__name__)

def renew_outlook_subscriptions():
    # 환경 변수에서 OutlookAuth 설정 가져오기
    client_id = os.getenv('OUTLOOK_CLIENT_ID')
    tenant = os.getenv('OUTLOOK_TENANT')  # 기본값으로 'common' 설정
    notify_url = os.getenv('OUTLOOK_NOTIFY_URL', 'https://mail-push.xtect.net/outlook_webhook')

    # 환경 변수 유효성 검사
    if not client_id:
        logger.error("OUTLOOK_CLIENT_ID 환경 변수가 설정되지 않음")
        return

    logger.info(f"Using tenant: {tenant}, notify_url: {notify_url}")  # tenant 및 notify_url 로깅 추가
    try:
        outlook_auth = OutlookAuth(client_id, tenant=tenant, notify_url=notify_url)
    except Exception as e:
        logger.error(f"Failed to initialize OutlookAuth: {e}", exc_info=True)
        return
    
    with SessionLocal() as db:
        # 활성 구독이 있는 모든 OutlookToken 레코드 가져오기
        tokens = db.query(OutlookToken).filter(OutlookToken.subscription_id != None).all()
        # 활성 구독 레코드 로깅
        if not tokens:
            logger.info("활성 구독이 있는 OutlookToken 레코드가 없습니다.")
        else:
            logger.info(f"활성 구독이 있는 OutlookToken 레코드 수: {len(tokens)}")
            for token in tokens:
                logger.info(f"OutlookToken: fcm_token={token.fcm_token}, subscription_id={token.subscription_id}, subscription_exp={token.subscription_exp}")

        for token in tokens:
            try:
                # 구독이 만료되기 직전인지 확인 (예: 1시간 이내)
                if token.subscription_exp and token.subscription_exp <= datetime.utcnow() + timedelta(minutes=1):
                    logger.info(f"fcm_token에 대한 구독 갱신: {token.fcm_token}")
                    outlook_auth.renew_subscription(token.fcm_token, token.subscription_id)
                else:
                    logger.debug(f"fcm_token {token.fcm_token}의 구독은 아직 갱신할 시점이 아님")
            except Exception as e:
                logger.error(f"fcm_token {token.fcm_token}의 구독 갱신 실패: {e}")

def renew_gmail_tokens():
    """
    DB에 저장된 모든 GmailToken 레코드를 순회하면서
    access_token 만료 시 자동으로 refresh하고 DB에 저장합니다.
    """
    gmail_auth = GmailAuth()
    now = datetime.utcnow()

    with SessionLocal() as db:
        tokens = db.query(GmailToken).all()
        if not tokens:
            logger.info("갱신할 GmailToken 레코드가 없습니다.")
            return

        for token in tokens:
            try:
                # _get_credentials 내부에서 만료된 토큰은 자동으로 refresh 후 저장합니다.
                creds = gmail_auth._get_credentials(token)
                
                logger.info(f"Gmail 토큰 갱신 완료: fcm_token={token.fcm_token}, new_access_token={creds.token[:10]}…")
            except Exception as e:
                logger.error(f"Gmail 토큰 갱신 실패: fcm_token={token.fcm_token}, error={e}")