from enum import Enum
from sqlalchemy import Column, Integer, String, Boolean, Enum as EnumType, ForeignKey
from sqlalchemy.orm import relationship
from .init import Base

# ConditionType 정의
class ConditionType(Enum):
    SUBJECT_CONTAINS = "subjectContains"
    BODY_CONTAINS = "bodyContains"
    FROM_SENDER = "fromSender"

# MailRule 모델
class MailRule(Base):
    __tablename__ = "mail_rules"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    name = Column(String(255), nullable=False)  # 길이 255로 지정
    owner_email = Column(String(255), nullable=False)  # 길이 255로 지정
    enabled = Column(Boolean, default=True)
    stop_further_rules = Column(Boolean, default=False)

    conditions = relationship("RuleCondition", back_populates="rule", cascade="all, delete-orphan")

# RuleCondition 모델
class RuleCondition(Base):
    __tablename__ = "rule_conditions"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    mail_rule_id = Column(Integer, ForeignKey("mail_rules.id", ondelete="CASCADE"), nullable=False)
    type = Column(EnumType(ConditionType, values_callable=lambda x: [e.value for e in ConditionType]), nullable=False)
    position = Column(Integer, nullable=False)

    rule = relationship("MailRule", back_populates="conditions")
    keywords = relationship("ConditionKeyword", back_populates="condition", cascade="all, delete-orphan")

# ConditionKeyword 모델
class ConditionKeyword(Base):
    __tablename__ = "condition_keywords"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    rule_condition_id = Column(Integer, ForeignKey("rule_conditions.id", ondelete="CASCADE"), nullable=False)
    keyword = Column(String(255), nullable=False)  # 길이 255로 지정

    condition = relationship("RuleCondition", back_populates="keywords")