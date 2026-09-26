from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.core.timeutil import utcnow
from app.db.base import Base, UTCDateTime


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ts: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)
    user_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    username: Mapped[str] = mapped_column(String(64), default="")
    action: Mapped[str] = mapped_column(String(48), index=True)
    result: Mapped[str] = mapped_column(String(16))  # SUCCESS | FAILED | DENIED | BLOCKED | INFO
    severity: Mapped[str] = mapped_column(String(8), default="INFO", server_default="INFO",
                                          index=True)  # INFO | WARNING | HIGH | CRITICAL
    target_type: Mapped[str] = mapped_column(String(32), default="")
    target_id: Mapped[str] = mapped_column(String(64), default="")
    target_label: Mapped[str] = mapped_column(String(255), default="")
    mac: Mapped[str] = mapped_column(String(12), default="")
    switch_name: Mapped[str] = mapped_column(String(128), default="")
    port: Mapped[str] = mapped_column(String(32), default="")
    message: Mapped[str] = mapped_column(String(1024), default="")
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    ip: Mapped[str] = mapped_column(String(64), default="")
    # §37 structured audit fields
    role: Mapped[str] = mapped_column(String(16), default="", server_default="")
    operation: Mapped[str] = mapped_column(String(32), default="", server_default="")
    vlan: Mapped[int | None] = mapped_column(Integer, nullable=True)
    profile: Mapped[str] = mapped_column(String(32), default="", server_default="")
    command_fingerprint: Mapped[str] = mapped_column(String(64), default="", server_default="")
    risk_level: Mapped[str] = mapped_column(String(16), default="", server_default="")
    approval: Mapped[str] = mapped_column(String(128), default="", server_default="")
    error: Mapped[str] = mapped_column(String(1024), default="", server_default="")
    before_state: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    after_state: Mapped[dict | None] = mapped_column(JSON, nullable=True)


from app.db.audit_guard import attach as _append_only  # noqa: E402

_append_only(AuditLog.__table__)


class SystemSetting(Base):
    __tablename__ = "system_settings"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[dict] = mapped_column(JSON)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, onupdate=utcnow)
    updated_by: Mapped[str] = mapped_column(String(64), default="system")
