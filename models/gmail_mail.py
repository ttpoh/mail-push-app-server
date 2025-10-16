# models/gmail_mail.py
from sqlalchemy import Column, Integer, String, Text, DateTime, Boolean
from sqlalchemy import UniqueConstraint
from datetime import datetime
from infra.db import Base

class GmailEmail(Base):
    __tablename__ = 'gmail_emails'

    id = Column(Integer, primary_key=True, autoincrement=True)

    # 원본 메일 키
    message_id = Column(String(255), nullable=False)
    email_address = Column(String(255), nullable=False)

    # 본문 메타
    sender = Column(String(255))
    subject = Column(String(500))
    body = Column(Text)
    received_at = Column(DateTime, default=datetime.utcnow)

    # 읽음 표시
    read = Column(Boolean, default=False)

    # ✅ 알람 관련(서버 판단값을 영속화)
    # - 규칙이 의도한 등급
    rule_alarm = Column(String(10))  # 'normal' | 'critical' | 'until'
    # - 전역 세팅 반영한 실제 등급
    effective_alarm = Column(String(10), default='normal', nullable=False)
    # (선택) 디버그/추적용
    matched_rule_name = Column(String(255))
    rules_version = Column(String(16))

    __table_args__ = (
        # 동일 사용자+메시지 한 번만
        UniqueConstraint('message_id', 'email_address', name='uq_message_email'),
    )
