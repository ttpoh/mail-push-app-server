# models/alarm_settings.py
from sqlalchemy import Column, Integer, String, DateTime, Boolean, Time, func, text
from infra.db import Base

class AlarmSettings(Base):
    __tablename__ = "alarm_settings"

    id = Column(Integer, primary_key=True)

    # ✅ 핵심: device_id를 유니크로
    device_id = Column(String(128), nullable=False, unique=True, index=True)

    # 이메일은 로그인 후 매핑 → NULL 허용, 유니크 금지
    email_address = Column(String(255), nullable=True, index=True)

    # 토큰은 순간적으로 없을 수 있으니 NULL 허용 권장
    fcm_token = Column(String(512), nullable=True, index=True)

    platform = Column(String(16), nullable=True)  # 'ios' | 'android'

    # ✅ 서버 기본값으로 고정 (raw SQL에도 통일되도록)
    normal_on = Column(Boolean, nullable=False, server_default=text("1"))
    critical_on = Column(Boolean, nullable=False, server_default=text("0"))
    critical_until_stopped = Column(Boolean, nullable=False, server_default=text("0"))

    quiet_start = Column(Time, nullable=True)
    quiet_end = Column(Time, nullable=True)
    timezone = Column(String(64), nullable=False, server_default=text("'Asia/Seoul'"))
    version = Column(Integer, nullable=False, server_default=text("1"))
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())
