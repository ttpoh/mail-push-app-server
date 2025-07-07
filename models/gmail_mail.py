from sqlalchemy import Column, Integer, String, Text, DateTime, Boolean, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import UniqueConstraint
from datetime import datetime
from infra.db import Base

class GmailEmail(Base):
    __tablename__ = 'gmail_emails'

    id = Column(Integer, primary_key=True, autoincrement=True)
    message_id = Column(String(255), nullable=False)
    email_address = Column(String(255), nullable=False)
    sender = Column(String(255))
    subject = Column(String(500))
    body = Column(Text)
    received_at = Column(DateTime, default=datetime.utcnow)
    read = Column(Boolean, default=False)  # ✅ 추가된 컬럼

    __table_args__ = (
        # message_id와 email_address 쌍에 대해 고유 제약 설정
        UniqueConstraint('message_id', 'email_address', name='uq_message_email'),
    )
