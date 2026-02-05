import datetime as dt

from sqlalchemy import JSON, Boolean, Column, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import relationship

from server.db.base import Base


class Tenant(Base):
    __tablename__ = "tenants"
    __table_args__ = {"extend_existing": True}

    id = Column(Integer, primary_key=True)
    name = Column(String(120), unique=True, nullable=False)
    created_at = Column(DateTime, default=dt.datetime.utcnow)


class Role(Base):
    __tablename__ = "roles"
    __table_args__ = {"extend_existing": True}

    id = Column(Integer, primary_key=True)
    name = Column(String(50), unique=True, nullable=False)


class User(Base):
    __tablename__ = "users"
    __table_args__ = {"extend_existing": True}

    id = Column(Integer, primary_key=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=False)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    role_id = Column(Integer, ForeignKey("roles.id"), nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=dt.datetime.utcnow)

    role = relationship("Role")
    tenant = relationship("Tenant")


class Agent(Base):
    __tablename__ = "agents"
    __table_args__ = {"extend_existing": True}

    id = Column(Integer, primary_key=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=False)
    agent_uuid = Column(String(64), unique=True, nullable=False, index=True)
    fingerprint = Column(String(256), nullable=False)
    hostname = Column(String(255), nullable=False)
    ip_address = Column(String(64), nullable=False)
    version = Column(String(50), nullable=False)
    status = Column(String(20), default="offline")
    last_heartbeat = Column(DateTime)
    shared_secret = Column(String(128), nullable=False)
    created_at = Column(DateTime, default=dt.datetime.utcnow)

    tenant = relationship("Tenant")
    configs = relationship("AgentConfig", back_populates="agent")


class AgentConfig(Base):
    __tablename__ = "agent_configs"
    __table_args__ = {"extend_existing": True}

    id = Column(Integer, primary_key=True)
    agent_id = Column(Integer, ForeignKey("agents.id"), nullable=False)
    config_version = Column(Integer, nullable=False, default=1)
    config = Column(JSON, nullable=False)
    updated_at = Column(DateTime, default=dt.datetime.utcnow, onupdate=dt.datetime.utcnow)

    agent = relationship("Agent", back_populates="configs")


class UsbDevice(Base):
    __tablename__ = "usb_devices"
    __table_args__ = {"extend_existing": True}

    id = Column(Integer, primary_key=True)
    agent_id = Column(Integer, ForeignKey("agents.id"), nullable=False)
    device_id = Column(String(128), nullable=False)
    vendor = Column(String(128))
    product = Column(String(128))
    serial_number = Column(String(128))
    first_seen = Column(DateTime, default=dt.datetime.utcnow)


class Event(Base):
    __tablename__ = "events"
    __table_args__ = {"extend_existing": True}

    id = Column(Integer, primary_key=True)
    event_id = Column(String(64), unique=True, nullable=False, index=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=False)
    agent_id = Column(Integer, ForeignKey("agents.id"), nullable=False)
    event_type = Column(String(50), nullable=False)
    file_path = Column(Text)
    file_hash = Column(String(128))
    file_size = Column(Integer)
    event_metadata = Column("metadata", JSON)
    user_context = Column(JSON)
    created_at = Column(DateTime, default=dt.datetime.utcnow, index=True)

    agent = relationship("Agent")


class Policy(Base):
    __tablename__ = "policies"
    __table_args__ = {"extend_existing": True}

    id = Column(Integer, primary_key=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=False)
    name = Column(String(200), nullable=False)
    description = Column(Text)
    version = Column(Integer, default=1)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=dt.datetime.utcnow)


class PolicyRule(Base):
    __tablename__ = "policy_rules"
    __table_args__ = {"extend_existing": True}

    id = Column(Integer, primary_key=True)
    policy_id = Column(Integer, ForeignKey("policies.id"), nullable=False)
    rule_type = Column(String(50), nullable=False)
    pattern = Column(Text)
    keywords = Column(JSON)
    hashes = Column(JSON)
    file_extension = Column(String(20))
    min_size = Column(Integer)
    max_size = Column(Integer)
    usb_only = Column(Boolean, default=False)
    action = Column(String(20), nullable=False)
    severity = Column(String(20), default="medium")
    severity_score = Column(Integer, default=0)
    tags = Column(JSON)
    is_whitelist = Column(Boolean, default=False)
    priority = Column(Integer, default=100)
    created_at = Column(DateTime, default=dt.datetime.utcnow)

    policy = relationship("Policy")


class Alert(Base):
    __tablename__ = "alerts"
    __table_args__ = {"extend_existing": True}

    id = Column(Integer, primary_key=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=False)
    event_id = Column(Integer, ForeignKey("events.id"), nullable=False)
    rule_id = Column(Integer, ForeignKey("policy_rules.id"))
    severity = Column(String(20), nullable=False)
    status = Column(String(20), default="open")
    escalated = Column(Boolean, default=False)
    created_at = Column(DateTime, default=dt.datetime.utcnow)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    __table_args__ = {"extend_existing": True}

    id = Column(Integer, primary_key=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"))
    action = Column(String(200), nullable=False)
    details = Column(JSON)
    created_at = Column(DateTime, default=dt.datetime.utcnow)


class LoginHistory(Base):
    __tablename__ = "login_history"
    __table_args__ = {"extend_existing": True}

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    ip_address = Column(String(64))
    success = Column(Boolean, default=True)
    created_at = Column(DateTime, default=dt.datetime.utcnow)


class EnrollmentToken(Base):
    __tablename__ = "enrollment_tokens"
    __table_args__ = {"extend_existing": True}

    id = Column(Integer, primary_key=True)
    tenant_id = Column(Integer, ForeignKey("tenants.id"), nullable=False)
    token_hash = Column(String(128), nullable=False, unique=True, index=True)
    agent_uuid = Column(String(64))
    expires_at = Column(DateTime, nullable=False)
    used_at = Column(DateTime)
    created_at = Column(DateTime, default=dt.datetime.utcnow)


Index("ix_events_agent_created", Event.agent_id, Event.created_at)
