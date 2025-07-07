from sqlalchemy import Column, Integer, String, Text, DateTime, Boolean
from datetime import datetime
from infra.db import Base

class OutlookEmail(Base):
    __tablename__ = 'outlook_emails'

    id = Column(Integer, primary_key=True, autoincrement=True)
    message_id = Column(String(255), unique=True, nullable=False)
    email_address = Column(String(255))
    sender = Column(String(255))
    subject = Column(String(500))    
    body = Column(Text)
    received_at = Column(DateTime, default=datetime.utcnow)
    read = Column(Boolean, default=False)  # ✅ 추가된 컬럼
