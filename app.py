import os
from flask import Flask, request, jsonify, render_template, redirect, url_for
from flask_cors import CORS
from firebase_admin import credentials, initialize_app
from routes.token_routes import token_bp
from routes.subscription_routes import subscription_bp, subscription_gmail_bp
from routes.gmail_routes import gmail_bp
from routes.outlook_routes import outlook_bp
from auth.logout_outlook import logout_outlook_bp
from auth.logout_gmail import logout_gmail_bp
from routes.mail_routes import email_bp
from routes.rule_routes import rule_bp
from utils.logger import configure_logger
from auth.gmail_auth import GmailAuth
from fcm.fcm_service import FcmService
from infra.redis_client import redis_client as infra_redis_client
from infra.db_init import initialize_database
import redis
from flask_apscheduler import APScheduler
from dotenv import load_dotenv  # python-dotenv 임포트
from flask import send_from_directory

load_dotenv()

# --- 스케줄러 설정 ---
class Config:
    SCHEDULER_API_ENABLED = True
    JOBS = [
        {
            'id': 'renew_outlook_subscriptions',
            'func': 'renew_tasks:renew_outlook_subscriptions',
            'trigger': 'interval',
            'minutes': 70  # 매 1분마다 실행
        },
        {
            'id': 'renew_gmail_tokens',
            'func': 'renew_tasks:renew_gmail_tokens',
            'trigger': 'interval',
            'minutes': 60   # 1시간마다, 필요에 따라 minutes=30 등 조정
        },
    ]

# --- 앱 및 로깅 초기화 ---
app = Flask(__name__)

# 스케줄러 설정 적용 및 시작
app.config.from_object(Config())
scheduler = APScheduler()
scheduler.init_app(app)
scheduler.start()

configure_logger()
# Redis 클라이언트 초기화 (infra.redis_client 대신 직접 설정)
redis_client = redis.StrictRedis(host='localhost', port=6379, db=0, decode_responses=True)

# Firebase Admin SDK 초기화
firebase_cred_path = os.getenv('FIREBASE_CREDENTIALS')
if not firebase_cred_path or not os.path.exists(firebase_cred_path):
    raise ValueError("Firebase credentials file not found")
cred = credentials.Certificate(firebase_cred_path)
initialize_app(cred)

# --- 데이터베이스 초기화 (최초 한 번만) ---
if not os.environ.get('INITIALIZED'):
    initialize_database()
    os.environ['INITIALIZED'] = '1'

# --- 글로벌 서비스 객체 초기화 ---
gmail_auth = GmailAuth()
fcm_service = FcmService()

# --- 라우트 등록 ---
app.register_blueprint(token_bp)
app.register_blueprint(subscription_gmail_bp)
app.register_blueprint(subscription_bp)
app.register_blueprint(gmail_bp)
app.register_blueprint(outlook_bp)
app.register_blueprint(logout_outlook_bp)
app.register_blueprint(logout_gmail_bp)
app.register_blueprint(email_bp)
app.register_blueprint(rule_bp)


# --- ACME 인증용 파일 라우팅 ---
@app.route('/.well-known/acme-challenge/<filename>')
def acme_challenge(filename):
    root = os.path.join(app.root_path, 'webroot', '.well-known', 'acme-challenge')
    return send_from_directory(root, filename)

@app.route('/.well-known/apple-app-site-association', methods=['GET'])
def serve_aasa():
    root = os.path.join(app.root_path, '.well-known')
    return send_from_directory(
        directory=root,                 # 실제 디렉토리
        path='apple-app-site-association',  # 파일명 (확장자 없이, 모두 소문자)
        mimetype='application/json'
    )

# --- 헬스체크 엔드포인트 ---
@app.route('/')
def health_check():
    return {'status': 'ok'}, 200

# --- 실행 ---
if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    app.debug = True

    app.run(host='0.0.0.0', port=port)
