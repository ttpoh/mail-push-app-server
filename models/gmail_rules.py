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
    owner_email = Column(String(255), nullable=False)
    enabled = Column(Boolean, default=True, nullable=False)

    # ✅ stop_further_rules 제거
    # stop_further_rules = Column(Boolean, default=False, nullable=False)

    # ✅ 규칙별 알람 모드
    alarm = Column(
        EnumType(AlarmLevel, values_callable=lambda x: [e.value for e in AlarmLevel]),
        nullable=False,
        default=AlarmLevel.NORMAL
    )

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
