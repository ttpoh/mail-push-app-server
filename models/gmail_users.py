# models/gmail_token.py
from sqlalchemy import Column, String, Text, DateTime, Integer
from datetime import datetime
from infra.db import Base

class GmailToken(Base):
    __tablename__ = "gmail_users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    fcm_token = Column(String(255), primary_key=True)
    access_token = Column(Text, nullable=False)
    refresh_token = Column(Text, nullable=False)
    email_address = Column(String(255), nullable=False)
    last_history_id = Column(String(255), nullable=True)
    subscription_id = Column(String(255), nullable=True)  # ✅ 구독 ID 저장 컬럼 추가

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
