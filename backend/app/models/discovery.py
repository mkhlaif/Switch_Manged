from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import JSON, Boolean, CheckConstraint, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.timeutil import utcnow
from app.db.base import Base, UTCDateTime


class DiscoveryJobStatus(str, enum.Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    INTERRUPTED = "interrupted"


ACTIVE_DISCOVERY_STATUSES = (DiscoveryJobStatus.QUEUED.value, DiscoveryJobStatus.RUNNING.value)
_STATUSES = ", ".join(f"'{s.value}'" for s in DiscoveryJobStatus)


class DiscoveryJob(Base):
    """Background discovery of one or many switches (after import, host-key trust, or on an
    administrator's request): bounded SSH concurrency, progress, cancellation, timeout."""

    __tablename__ = "discovery_jobs"
    __table_args__ = (CheckConstraint(f"status IN ({_STATUSES})", name="status_valid"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True,
                                    default=lambda: str(uuid.uuid4()))
    created_by_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_by: Mapped[str] = mapped_column(String(64))
    source: Mapped[str] = mapped_column(String(16), default="manual")  # manual | import | hostkey
    status: Mapped[str] = mapped_column(String(16), default=DiscoveryJobStatus.QUEUED.value,
                                        index=True)
    switch_ids: Mapped[list] = mapped_column(JSON, default=list)
    total: Mapped[int] = mapped_column(Integer, default=0)
    processed: Mapped[int] = mapped_column(Integer, default=0)
    discovered: Mapped[int] = mapped_column(Integer, default=0)
    failed: Mapped[int] = mapped_column(Integer, default=0)
    mismatched: Mapped[int] = mapped_column(Integer, default=0)
    cancel_requested: Mapped[bool] = mapped_column(Boolean, default=False)
    results: Mapped[list] = mapped_column(JSON, default=list)
    error: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)
    started_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    failed_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
