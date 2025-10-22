from enum import Enum
from sqlalchemy import (
    Column, Integer, String, Boolean, ForeignKey,
    Enum as EnumType
)
from sqlalchemy.orm import relationship
from .init import Base

# =========================
# Enums
# =========================
class ConditionType(Enum):
    SUBJECT_CONTAINS = "subjectContains"
    BODY_CONTAINS = "bodyContains"
    FROM_SENDER = "fromSender"

class LogicType(Enum):
    AND = "and"
    OR = "or"

class AlarmLevel(Enum):
    NORMAL = "normal"     # 일반 알람
    CRITICAL = "critical" # 주의(1회 울림)
    UNTIL = "until"       # 경고(정지 시까지)

# =========================
# MailRule
# =========================
class MailRule(Base):
    __tablename__ = "mail_rules"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    name = Column(String(255), nullable=False)
    owner_email = Column(String(255), nullable=False, index=True)
    enabled = Column(Boolean, default=True, nullable=False)

    # ✅ 규칙별 알람 모드
    alarm = Column(
        EnumType(AlarmLevel, values_callable=lambda x: [e.value for e in AlarmLevel]),
        nullable=False,
        default=AlarmLevel.NORMAL
    )

    # ✅ 추가: 알람 사운드(에셋 경로 또는 식별자). 예: 'assets/sounds/siren.mp3' 또는 'default'
    #    - 기존 데이터 호환을 위해 nullable 허용
    sound = Column(String(512), nullable=True)

    # ✅ 추가: TTS 메시지(사용자 입력)
    #    - 길이가 길 수 있으므로 1024까지 여유를 둠(필요하면 Text로 변경 가능)
    tts = Column(String(1024), nullable=True)

    # position 순 정렬로 children 정렬(선택)
    conditions = relationship(
        "RuleCondition",
        back_populates="rule",
        cascade="all, delete-orphan",
        order_by="RuleCondition.position"
    )

# =========================
# RuleCondition
# =========================
class RuleCondition(Base):
    __tablename__ = "rule_conditions"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    mail_rule_id = Column(
        Integer,
        ForeignKey("mail_rules.id", ondelete="CASCADE"),
        nullable=False
    )
    type = Column(
        EnumType(ConditionType, values_callable=lambda x: [e.value for e in ConditionType]),
        nullable=False
    )
    logic = Column(
        EnumType(LogicType, values_callable=lambda x: [e.value for e in LogicType]),
        nullable=False,
        default=LogicType.OR  # Python 레벨 default
    )
    position = Column(Integer, nullable=False, default=0)

    rule = relationship("MailRule", back_populates="conditions")
    keywords = relationship(
        "ConditionKeyword",
        back_populates="condition",
        cascade="all, delete-orphan",
        order_by="ConditionKeyword.id"
    )

# =========================
# ConditionKeyword
# =========================
class ConditionKeyword(Base):
    __tablename__ = "condition_keywords"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    rule_condition_id = Column(
        Integer,
        ForeignKey("rule_conditions.id", ondelete="CASCADE"),
        nullable=False
    )
    keyword = Column(String(255), nullable=False)

    condition = relationship("RuleCondition", back_populates="keywords")
