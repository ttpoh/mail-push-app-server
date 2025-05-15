import os

# FCM 서비스 계정 키 경로
FCM_CREDENTIALS_PATH = os.path.join(os.path.dirname(__file__), 'fcm-credentials.json')

# Gmail API 스코프
GMAIL_SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

# 서버 설정
HOST = '0.0.0.0'
PORT = 5000
PROJECT_ID = 'alarm-mail-app'