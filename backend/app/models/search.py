from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import JSON, Boolean, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.timeutil import utcnow
from app.db.base import Base, UTCDateTime


class SearchStatus(str, enum.Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    INTERRUPTED = "interrupted"


class SwitchResultStatus(str, enum.Enum):
    FOUND = "found"
    NOT_FOUND = "not_found"
    TIMEOUT = "timeout"
    AUTH_FAILED = "auth_failed"
    HOSTKEY_ERROR = "hostkey_error"
    CONNECTION_FAILED = "connection_failed"
    COMMAND_FAILED = "command_failed"
    UNSUPPORTED = "unsupported"
    BLOCKED = "blocked"
    UNEXPECTED_OUTPUT = "unexpected_output"
    ERROR = "error"


FAILURE_STATUSES = {
    SwitchResultStatus.BLOCKED.value,
    SwitchResultStatus.UNEXPECTED_OUTPUT.value,
    SwitchResultStatus.AUTH_FAILED.value,
    SwitchResultStatus.HOSTKEY_ERROR.value,
    SwitchResultStatus.CONNECTION_FAILED.value,
    SwitchResultStatus.COMMAND_FAILED.value,
    SwitchResultStatus.UNSUPPORTED.value,
    SwitchResultStatus.ERROR.value,
}


def _uuid() -> str:
    return str(uuid.uuid4())


class MacSearch(Base):
    __tablename__ = "mac_searches"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    mac: Mapped[str] = mapped_column(String(12), index=True)
    requested_by_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    requested_by: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(16), default=SearchStatus.QUEUED.value)
    total_switches: Mapped[int] = mapped_column(Integer, default=0)
    checked: Mapped[int] = mapped_column(Integer, default=0)
    found_count: Mapped[int] = mapped_column(Integer, default=0)
    failed_count: Mapped[int] = mapped_column(Integer, default=0)
    timeout_count: Mapped[int] = mapped_column(Integer, default=0)
    options: Mapped[dict] = mapped_column(JSON, default=dict)
    summary: Mapped[dict] = mapped_column(JSON, default=dict)
    mode: Mapped[str] = mapped_column(String(10), default="STANDARD", server_default="STANDARD")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)
    started_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)

    results: Mapped[list[MacSearchResult]] = relationship(
        back_populates="search", cascade="all, delete-orphan", passive_deletes=True
    )


class MacSearchResult(Base):
    """One row per (switch, MAC-table entry). Switches where the MAC was not found (or that failed)
    get a single row with a non-``found`` status so the full outcome of a search is kept."""

    __tablename__ = "mac_search_results"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    search_id: Mapped[str] = mapped_column(
        ForeignKey("mac_searches.id", ondelete="CASCADE"), index=True
    )
    switch_id: Mapped[int | None] = mapped_column(
        ForeignKey("switches.id", ondelete="SET NULL"), nullable=True
    )
    switch_name: Mapped[str] = mapped_column(String(128))
    switch_host: Mapped[str] = mapped_column(String(255), default="")
    location: Mapped[str] = mapped_column(String(128), default="")
    model: Mapped[str] = mapped_column(String(64), default="")
    aos_version: Mapped[str] = mapped_column(String(64), default="")
    profile_key: Mapped[str] = mapped_column(String(32), default="")
    status: Mapped[str] = mapped_column(String(24))
    error_message: Mapped[str] = mapped_column(Text, default="")

    port: Mapped[str] = mapped_column(String(32), default="")
    interface_raw: Mapped[str] = mapped_column(String(64), default="")
    is_linkagg: Mapped[bool] = mapped_column(Boolean, default=False)
    vlan_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    mac_type: Mapped[str] = mapped_column(String(32), default="")
    operation: Mapped[str] = mapped_column(String(32), default="")

    port_details: Mapped[dict] = mapped_column(JSON, default=dict)
    vlans: Mapped[list] = mapped_column(JSON, default=list)
    tagged_vlans: Mapped[list] = mapped_column(JSON, default=list)
    untagged_vlan: Mapped[int | None] = mapped_column(Integer, nullable=True)
    lldp: Mapped[list] = mapped_column(JSON, default=list)
    mac_count_on_port: Mapped[int | None] = mapped_column(Integer, nullable=True)

    classification: Mapped[str] = mapped_column(String(16), default="")
    classification_confidence: Mapped[str] = mapped_column(String(8), default="")
    classification_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    classification_reasons: Mapped[list] = mapped_column(JSON, default=list)

    commands_executed: Mapped[list] = mapped_column(JSON, default=list)
    warnings: Mapped[list] = mapped_column(JSON, default=list)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)

    search: Mapped[MacSearch] = relationship(back_populates="results")


class MacSighting(Base):
    """Likely edge location of a MAC as seen by a search; used for MAC-move detection."""

    __tablename__ = "mac_sightings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    mac: Mapped[str] = mapped_column(String(12), index=True)
    switch_id: Mapped[int | None] = mapped_column(
        ForeignKey("switches.id", ondelete="SET NULL"), nullable=True
    )
    switch_name: Mapped[str] = mapped_column(String(128))
    port: Mapped[str] = mapped_column(String(32))
    vlan_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    search_id: Mapped[str | None] = mapped_column(
        ForeignKey("mac_searches.id", ondelete="SET NULL"), nullable=True
    )
    seen_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)
    note: Mapped[str] = mapped_column(Text, default="")
