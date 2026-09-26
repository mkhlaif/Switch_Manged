from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import JSON, Boolean, CheckConstraint, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.core.timeutil import utcnow
from app.db.base import Base, UTCDateTime


class ImportStatus(str, enum.Enum):
    VALIDATED = "validated"        # preview ready, waiting for the administrator's confirmation
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    EXPIRED = "expired"            # preview not confirmed in time
    INTERRUPTED = "interrupted"    # the application stopped while the job was running


ACTIVE_IMPORT_STATUSES = (ImportStatus.QUEUED.value, ImportStatus.RUNNING.value)
_STATUS_LIST = ", ".join(f"'{s.value}'" for s in ImportStatus)


def _uuid() -> str:
    return str(uuid.uuid4())


class ImportJob(Base):
    """A bulk switch import: validated preview → explicit confirmation → background batches.

    ``rows`` holds the normalised rows with their validation result and, after processing, the
    per-row outcome. It never contains credentials: import files reference credentials by name.
    """

    __tablename__ = "import_jobs"
    __table_args__ = (
        CheckConstraint(f"status IN ({_STATUS_LIST})", name="status_valid"),
        CheckConstraint("file_format IN ('csv', 'json')", name="format_valid"),
        CheckConstraint("on_existing IN ('skip', 'update')", name="on_existing_valid"),
        CheckConstraint("mode IN ('atomic', 'per_row')", name="mode_valid"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    created_by_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_by: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(16), default=ImportStatus.VALIDATED.value,
                                        index=True)
    file_format: Mapped[str] = mapped_column(String(8))
    filename: Mapped[str] = mapped_column(String(255), default="")
    file_sha256: Mapped[str] = mapped_column(String(64), default="")
    on_existing: Mapped[str] = mapped_column(String(8), default="skip")
    # atomic (default): the whole file in ONE transaction — any failing row rolls everything
    # back; per_row: only the valid rows, each in its own transaction (explicit choice).
    mode: Mapped[str] = mapped_column(String(8), default="atomic", server_default="atomic")
    skip_invalid: Mapped[bool] = mapped_column(Boolean, default=False)
    discovery_job_id: Mapped[str] = mapped_column(String(36), default="", server_default="")
    cancel_requested: Mapped[bool] = mapped_column(Boolean, default=False)

    # preview counts
    total: Mapped[int] = mapped_column(Integer, default=0)
    valid: Mapped[int] = mapped_column(Integer, default=0)
    invalid: Mapped[int] = mapped_column(Integer, default=0)
    duplicates: Mapped[int] = mapped_column(Integer, default=0)
    warnings: Mapped[int] = mapped_column(Integer, default=0)
    # result counts
    processed: Mapped[int] = mapped_column(Integer, default=0)
    imported: Mapped[int] = mapped_column(Integer, default=0)
    updated: Mapped[int] = mapped_column(Integer, default=0)
    unchanged: Mapped[int] = mapped_column(Integer, default=0)
    skipped: Mapped[int] = mapped_column(Integer, default=0)
    failed: Mapped[int] = mapped_column(Integer, default=0)

    file_errors: Mapped[list] = mapped_column(JSON, default=list)
    rows: Mapped[list] = mapped_column(JSON, default=list)
    error: Mapped[str] = mapped_column(Text, default="")

    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)
    expires_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    confirmed_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    failed_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
