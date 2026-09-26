from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import JSON, Boolean, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.timeutil import utcnow
from app.db.base import Base, UTCDateTime


class PortActionStatus(str, enum.Enum):
    PLANNED = "planned"          # prepared, awaiting confirmation
    EXPIRED = "expired"          # plan not confirmed in time
    DENIED = "denied"            # policy/confirmation check failed at execute time
    DRY_RUN = "dry_run"          # confirmed; commands shown but NOT sent
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    ABORTED = "aborted"          # final re-check did not match the plan; nothing changed
    INTERRUPTED = "interrupted"  # backend stopped mid-action; port state must be checked by hand


class PortAction(Base):
    __tablename__ = "port_actions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    plan_token: Mapped[str] = mapped_column(
        String(36), unique=True, index=True, default=lambda: str(uuid.uuid4())
    )
    action: Mapped[str] = mapped_column(String(32), default="PORT_RESTART")
    method: Mapped[str] = mapped_column(String(16))  # link_bounce | poe_cycle
    strategy: Mapped[str] = mapped_column(String(32), default="")
    profile_key: Mapped[str] = mapped_column(String(32), default="")
    status: Mapped[str] = mapped_column(String(16), default=PortActionStatus.PLANNED.value)

    switch_id: Mapped[int | None] = mapped_column(
        ForeignKey("switches.id", ondelete="SET NULL"), nullable=True
    )
    switch_name: Mapped[str] = mapped_column(String(128))
    switch_host: Mapped[str] = mapped_column(String(255), default="")
    aos_version: Mapped[str] = mapped_column(String(64), default="")
    port: Mapped[str] = mapped_column(String(32))
    mac: Mapped[str] = mapped_column(String(12))
    vlan_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    vlans: Mapped[list] = mapped_column(JSON, default=list)
    classification: Mapped[str] = mapped_column(String(16), default="")
    classification_confidence: Mapped[str] = mapped_column(String(8), default="")
    classification_reasons: Mapped[list] = mapped_column(JSON, default=list)
    risk_level: Mapped[str] = mapped_column(String(16), default="")
    warnings: Mapped[list] = mapped_column(JSON, default=list)
    required_phrases: Mapped[list] = mapped_column(JSON, default=list)
    # available: policy allows the restart and a verified strategy exists (dry run possible).
    # execution_allowed: additionally, the strategy is admin-approved for this AOS version, so
    # the commands may really be sent (when dry-run mode is off).
    available: Mapped[bool] = mapped_column(Boolean, default=False)
    execution_allowed: Mapped[bool] = mapped_column(Boolean, default=False)
    execution_note: Mapped[str] = mapped_column(Text, default="")
    blocked_reason: Mapped[str] = mapped_column(Text, default="")

    commands: Mapped[list] = mapped_column(JSON, default=list)
    commands_executed: Mapped[list] = mapped_column(JSON, default=list)
    steps: Mapped[list] = mapped_column(JSON, default=list)
    verification: Mapped[dict] = mapped_column(JSON, default=dict)
    # COMMAND SAFETY TEST report: what the firewall generated and validated (dry runs) or
    # validated before execution (live runs). Commands shown here were checked, not sent.
    safety_report: Mapped[dict] = mapped_column(JSON, default=dict)
    dry_run: Mapped[bool] = mapped_column(Boolean, default=True)
    trunk_override: Mapped[bool] = mapped_column(Boolean, default=False)
    reason: Mapped[str] = mapped_column(Text, default="")
    result_message: Mapped[str] = mapped_column(Text, default="")
    error_message: Mapped[str] = mapped_column(Text, default="")

    requested_by_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    requested_by: Mapped[str] = mapped_column(String(64))
    search_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    search_result_id: Mapped[int | None] = mapped_column(Integer, nullable=True)

    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)
    expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    confirmed_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
