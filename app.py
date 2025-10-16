import os
from flask import Flask, request, jsonify, render_template, redirect, url_for, send_from_directory
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
from routes.device_routes import device_bp
from utils.logger import configure_logger
from auth.gmail_auth import GmailAuth
from fcm.fcm_service import FcmService
from infra.redis_client import redis_client as infra_redis_client
from infra.db_init import initialize_database
import redis
from flask_apscheduler import APScheduler
from dotenv import load_dotenv  # python-dotenv 임포트
import logging

load_dotenv()

# --- 스케줄러 설정 ---
class Config:
    SCHEDULER_API_ENABLED = True
    JOBS = [
        {
            'id': 'renew_outlook_subscriptions',
            'func': 'renew_tasks:renew_outlook_subscriptions',
            'trigger': 'interval',
            'minutes': 70
        },
        {
            'id': 'renew_gmail_tokens',
            'func': 'renew_tasks:renew_gmail_tokens',
            'trigger': 'interval',
            'minutes': 60
        },
    ]

# --- 앱 및 로깅 초기화 ---
app = Flask(__name__)

# 스케줄러 설정 적용 및 시작
app.config.from_object(Config())
scheduler = APScheduler()
scheduler.init_app(app)
scheduler.start()

# 0) 기존 프로젝트 로거 초기화 (있다면 유지)
configure_logger()

# 1) ✅ 런타임에서 확실히 DEBUG 적용 (gunicorn 플래그와 무관하게 앱 로거 보장)
def _force_debug_logging():
    # 환경변수로도 제어 가능: LOG_LEVEL=DEBUG/INFO/...
    level_name = os.getenv("LOG_LEVEL", "DEBUG").upper()
    try:
        level = getattr(logging, level_name, logging.DEBUG)
    except Exception:
        level = logging.DEBUG

    root = logging.getLogger()
    root.setLevel(level)

    # 모든 기존 핸들러도 올려준다 (gunicorn 핸들러 포함)
    for h in root.handlers:
        h.setLevel(level)

    # 보기 좋은 포매터
    fmt = "%(asctime)s [%(levelname)s] %(name)s - %(message)s"
    datefmt = "%Y-%m-%d %H:%M:%S"
    for h in root.handlers:
        h.setFormatter(logging.Formatter(fmt, datefmt))

    # 우리가 보고 싶은 모듈 로거들 명시적으로 DEBUG
    logging.getLogger("utils.gmail_util").setLevel(logging.DEBUG)
    logging.getLogger("routes.gmail_routes").setLevel(logging.DEBUG)
    # 전파 보장
    logging.getLogger("utils.gmail_util").propagate = True
    logging.getLogger("routes.gmail_routes").propagate = True

    # 부가: 현재 레벨 로그로 출력해서 눈으로 확인
    root.warning("ROOT level = %s", root.level)
    logging.getLogger("utils.gmail_util").warning(
        "gmail_util level = %s", logging.getLogger("utils.gmail_util").level
    )
    logging.getLogger("routes.gmail_routes").warning(
        "gmail_routes level = %s", logging.getLogger("routes.gmail_routes").level
    )

_force_debug_logging()

# Redis 클라이언트 초기화
redis_client = redis.StrictRedis(host='localhost', port=6379, db=0, decode_responses=True)
# ✅ Flask 앱에 등록해서 current_app.extensions['redis'] 로 접근 가능하게
app.extensions = getattr(app, "extensions", {})
app.extensions["redis"] = redis_client

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
app.url_map.strict_slashes = False  # 슬래시 유연 처리

app.register_blueprint(token_bp, url_prefix="/api")
app.register_blueprint(subscription_gmail_bp)
app.register_blueprint(subscription_bp)
app.register_blueprint(gmail_bp, url_prefix="/api")
app.register_blueprint(outlook_bp)
app.register_blueprint(logout_outlook_bp)
app.register_blueprint(logout_gmail_bp)
app.register_blueprint(email_bp)
app.register_blueprint(rule_bp, url_prefix="/api/rules")
app.register_blueprint(device_bp, url_prefix="/api")

# --- ACME 인증용 파일 라우팅 ---
@app.route('/.well-known/acme-challenge/<filename>')
def acme_challenge(filename):
    root = os.path.join(app.root_path, 'webroot', '.well-known', 'acme-challenge')
    return send_from_directory(root, filename)

@app.route('/.well-known/apple-app-site-association', methods=['GET'])
def serve_aasa():
    root = os.path.join(app.root_path, '.well-known')
    return send_from_directory(
        directory=root,
        path='apple-app-site-association',
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
