# app.py

import os
from flask import Flask
from firebase_admin import credentials, initialize_app
from routes.token_routes import token_bp
from routes.subscription_routes import subscription_bp, subscription_gmail_bp
from routes.gmail_routes import gmail_bp
from routes.outlook_routes import outlook_bp
from auth.logout_outlook import logout_outlook_bp
from auth.logout_gmail import logout_gmail_bp
from routes.mail_routes import email_bp
from utils.logger import configure_logger
from auth.gmail_auth import GmailAuth
from fcm.fcm_service import FcmService
from infra.redis_client import redis_client
from infra.db_init import initialize_database
import redis

# --- 앱 및 로깅 초기화 ---
app = Flask(__name__)
configure_logger()
redis_client = redis.StrictRedis(host='localhost', port=6379, db=0, decode_responses=True)

# Firebase Admin SDK 초기화
firebase_cred_path = os.getenv('FIREBASE_CREDENTIALS')
if not firebase_cred_path or not os.path.exists(firebase_cred_path):
    raise ValueError("Firebase credentials file not found")
cred = credentials.Certificate(firebase_cred_path)
initialize_app(cred)

if not os.environ.get('INITIALIZED'):
    initialize_database()
    os.environ['INITIALIZED'] = '1'  # 초기화 완료 플래그 설정

# --- 글로벌 서비스 객체 초기화 ---
gmail_auth = GmailAuth()
fcm_service = FcmService()

# --- 라우트 등록 ---
app.register_blueprint(token_bp)
app.register_blueprint(subscription_gmail_bp)
app.register_blueprint(subscription_bp)
app.register_blueprint(gmail_bp)
app.register_blueprint(outlook_bp)
app.register_blueprint(logout_outlook_bp)      # ✅ 이거 빠졌으면 반드시 추가
app.register_blueprint(logout_gmail_bp)
app.register_blueprint(email_bp)

# --- ACME 인증용 파일 라우팅 (Let’s Encrypt 사용 시) ---
@app.route('/.well-known/acme-challenge/<filename>')
def acme_challenge(filename):
    from flask import send_from_directory
    root = os.path.join(app.root_path, 'webroot', '.well-known', 'acme-challenge')
    return send_from_directory(root, filename)

# --- 헬스체크 엔드포인트 ---
@app.route('/')
def health_check():
    return {'status': 'ok'}, 200

# --- 실행 ---
if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    create_gmail_subscription()
    app.run(host='0.0.0.0', port=port)
