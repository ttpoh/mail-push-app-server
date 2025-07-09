from sqlalchemy import Column, String, Text, DateTime, Integer
from datetime import datetime
from infra.db import Base
from sqlalchemy.schema import UniqueConstraint

class OutlookToken(Base):
    __tablename__ = 'outlook_users'
    id = Column(Integer, primary_key=True)
    fcm_token = Column(String(255), nullable=False)
    access_token = Column(Text, nullable=False)
    refresh_token = Column(Text, nullable=True)
    email_address = Column(String(255), nullable=False)
    client_state = Column(String(255), nullable=False, unique=True)  # 고유 제약 추가
    subscription_id = Column(String(255), nullable=True)
    subscription_exp = Column(DateTime, nullable=True)  # 구독 만료 시간
    access_token_exp = Column(DateTime, nullable=False)
    __table_args__ = (UniqueConstraint('client_state', name='unique_client_state'),)

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
