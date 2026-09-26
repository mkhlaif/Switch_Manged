from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.core.timeutil import utcnow
from app.db.base import Base, UTCDateTime


class SshSessionRecord(Base):
    """One row per SSH session opened by the Command Safety Firewall.

    ``commands`` lists every command attempt as {operation, command_key, fingerprint, risk,
    status, reason, at, duration_ms}. The command text itself is not stored here — the
    fingerprint identifies it without duplicating operational data."""

    __tablename__ = "ssh_sessions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    switch_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    switch_name: Mapped[str] = mapped_column(String(128), default="")
    profile_key: Mapped[str] = mapped_column(String(32), default="")
    user_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    username: Mapped[str] = mapped_column(String(64), default="")
    purpose: Mapped[str] = mapped_column(String(32), default="")
    reference: Mapped[str] = mapped_column(String(64), default="")
    operations: Mapped[list] = mapped_column(JSON, default=list)
    started_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)
    ended_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    commands_attempted: Mapped[int] = mapped_column(Integer, default=0)
    commands_executed: Mapped[int] = mapped_column(Integer, default=0)
    commands_blocked: Mapped[int] = mapped_column(Integer, default=0)
    result: Mapped[str] = mapped_column(String(16), default="")
    error: Mapped[str] = mapped_column(Text, default="")
    commands: Mapped[list] = mapped_column(JSON, default=list)


class OperationLock(Base):
    """Database-backed mutual exclusion for state-changing actions.

    scope = "switch" (key = switch id) or "port" (key = switch id + port). A restart holds both:
    one state-changing operation per switch at a time, and never two on the same port."""

    __tablename__ = "operation_locks"
    __table_args__ = (UniqueConstraint("scope", "target_key"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scope: Mapped[str] = mapped_column(String(8))
    target_key: Mapped[str] = mapped_column(String(64))
    switch_id: Mapped[int] = mapped_column(Integer)
    switch_name: Mapped[str] = mapped_column(String(128), default="")
    port: Mapped[str] = mapped_column(String(32), default="")
    operation: Mapped[str] = mapped_column(String(32))
    action_id: Mapped[int] = mapped_column(Integer)
    holder: Mapped[str] = mapped_column(String(64))
    acquired_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime)


class CommandVerification(Base):
    """Administrator lab verification of a command profile capability on one model family and
    AOS version prefix (§9: verified_by / verified_at / evidence).

    capability = "READ" (all read-only profile commands, needed before profile commands run on
    real switches) or a bounce strategy id (needed before any live restart)."""

    __tablename__ = "command_verifications"
    __table_args__ = (UniqueConstraint("profile_key", "capability", "model_family",
                                       "version_prefix"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    profile_key: Mapped[str] = mapped_column(String(32))
    capability: Mapped[str] = mapped_column(String(32))
    model_family: Mapped[str] = mapped_column(String(16))  # e.g. OS6360, or "*" (all supported)
    version_prefix: Mapped[str] = mapped_column(String(32))
    verified_by: Mapped[str] = mapped_column(String(64))
    verified_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    notes: Mapped[str] = mapped_column(Text, default="")
    evidence: Mapped[dict] = mapped_column(JSON, default=dict)


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    kind: Mapped[str] = mapped_column(String(40), index=True)
    severity: Mapped[str] = mapped_column(String(8))  # INFO | WARNING | HIGH | CRITICAL
    title: Mapped[str] = mapped_column(String(200))
    message: Mapped[str] = mapped_column(Text, default="")
    switch_name: Mapped[str] = mapped_column(String(128), default="")
    port: Mapped[str] = mapped_column(String(32), default="")
    mac: Mapped[str] = mapped_column(String(12), default="")
    dedupe_key: Mapped[str] = mapped_column(String(200), default="", index=True)
    occurrences: Mapped[int] = mapped_column(Integer, default=1)
    details: Mapped[dict] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(16), default="open")  # open | acknowledged
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)
    last_seen_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    acknowledged_by: Mapped[str] = mapped_column(String(64), default="")
    acknowledged_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)


class SafetyEvent(Base):
    """Changes of the global safety state: mode changes, kill switch, circuit breaker."""

    __tablename__ = "safety_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ts: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)
    kind: Mapped[str] = mapped_column(String(40))  # MODE_CHANGE | KILL_SWITCH | BREAKER_TRIP | ..
    username: Mapped[str] = mapped_column(String(64), default="system")
    old_value: Mapped[str] = mapped_column(String(64), default="")
    new_value: Mapped[str] = mapped_column(String(64), default="")
    reason: Mapped[str] = mapped_column(Text, default="")
    details: Mapped[dict] = mapped_column(JSON, default=dict)


class PortSnapshot(Base):
    """Structured port state captured around a state-changing operation (§53). Never used to
    change configuration; only for comparison, verification and the change report."""

    __tablename__ = "port_snapshots"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    action_id: Mapped[int] = mapped_column(Integer, index=True)
    phase: Mapped[str] = mapped_column(String(16))  # plan | before | after
    switch_name: Mapped[str] = mapped_column(String(128))
    port: Mapped[str] = mapped_column(String(32))
    data: Mapped[dict] = mapped_column(JSON, default=dict)
    taken_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
