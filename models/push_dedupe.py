# models/push_dedupe.py
import sqlalchemy as sa
from sqlalchemy import Column, BigInteger, String, DateTime, func
from infra.db import Base

class PushDedupe(Base):
    __tablename__ = "push_dedupe"

    id = Column(BigInteger, primary_key=True, autoincrement=True)

    email_address = Column(String(255), nullable=False, index=True)
    gmail_message_id = Column(String(255), nullable=False, index=True)
    fcm_token = Column(String(512), nullable=False, index=True)

    # 생성 시각
    created_at = Column(DateTime, nullable=False, server_default=func.now())

    # 🔑 결합 해시(고정 32바이트). MySQL 8+: 생성(계산) 컬럼 + UNIQUE 인덱스
    dedupe_key = Column(
        sa.BINARY(32),
        sa.Computed(
            "UNHEX(SHA2(CONCAT_WS('|', email_address, gmail_message_id, fcm_token), 256))",
            persisted=True,  # STORED
        ),
        nullable=False,
        unique=True,
        index=True,
    )
