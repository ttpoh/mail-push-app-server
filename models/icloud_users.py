from sqlalchemy import Column, String, DateTime
from infra.db import Base
from datetime import datetime

class ICloudToken(Base):
    __tablename__ = 'icloud_tokens'

    sub = Column(String(64), primary_key=True, index=True)  # Apple 사용자 고유 ID
    email_address = Column(String(256), nullable=False)      # email 최대 길이 254+@ 처리
    fcm_token = Column(String(256), nullable=False)          # FCM 토큰
    access_token = Column(String(2048), nullable=False)      # OAuth 토큰 길이 충분히 길게
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow)
