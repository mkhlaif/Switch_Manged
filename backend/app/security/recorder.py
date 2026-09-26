"""Persistence of SSH session records and security events.

Records are queued and written by a single background writer (started in the application
lifespan) so that many concurrent switch sessions never contend for the database. When no writer
is running (CLI scripts), items are written directly.
"""

from __future__ import annotations

import asyncio
import uuid
from dataclasses import dataclass, field
from datetime import datetime

from app.core.logging import get_logger, log_security
from app.core.timeutil import utcnow
from app.security.policy import Severity

log = get_logger("security")


@dataclass
class CommandEvent:
    operation: str
    command_key: str
    fingerprint: str
    risk: str
    status: str  # executed | failed | blocked
    reason: str = ""
    at: str = field(default_factory=lambda: utcnow().isoformat())
    duration_ms: int = 0

    def to_dict(self) -> dict:
        return {
            "operation": self.operation, "command_key": self.command_key,
            "fingerprint": self.fingerprint, "risk": self.risk, "status": self.status,
            "reason": self.reason, "at": self.at, "duration_ms": self.duration_ms,
        }


@dataclass
class SessionRecord:
    switch_id: int | None
    switch_name: str
    user_id: int | None
    username: str
    purpose: str
    reference: str = ""
    profile_key: str = ""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    started_at: datetime = field(default_factory=utcnow)
    ended_at: datetime | None = None
    operations: list[str] = field(default_factory=list)
    events: list[CommandEvent] = field(default_factory=list)
    result: str = ""
    error: str = ""

    @property
    def attempted(self) -> int:
        return len(self.events)

    @property
    def executed(self) -> int:
        return sum(1 for e in self.events if e.status in {"executed", "failed"})

    @property
    def blocked(self) -> int:
        return sum(1 for e in self.events if e.status == "blocked")


@dataclass
class SecurityEvent:
    action: str
    severity: Severity
    reason: str
    user_id: int | None = None
    username: str = ""
    operation: str = ""
    parameter: str = ""
    switch_name: str = ""
    port: str = ""
    mac: str = ""
    ip: str = ""
    details: dict = field(default_factory=dict)


@dataclass
class AlertItem:
    kind: str
    severity: str
    title: str
    message: str = ""
    switch_name: str = ""
    port: str = ""
    mac: str = ""
    dedupe_key: str = ""
    details: dict = field(default_factory=dict)


DEDUPE_MINUTES = 60


class Recorder:
    def __init__(self) -> None:
        self._queue: asyncio.Queue | None = None
        self._worker: asyncio.Task | None = None
        self._direct: set[asyncio.Task] = set()

    # -- lifecycle ---------------------------------------------------------------------------
    async def start(self) -> None:
        self._queue = asyncio.Queue()
        self._worker = asyncio.create_task(self._run(), name="security-recorder")

    async def stop(self) -> None:
        await self.flush()
        if self._worker is not None:
            self._worker.cancel()
            try:
                await self._worker
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
        self._worker = None
        self._queue = None

    async def flush(self) -> None:
        if self._queue is not None and self._worker is not None and not self._worker.done():
            await self._queue.join()
        if self._direct:
            await asyncio.gather(*list(self._direct), return_exceptions=True)

    # -- submission --------------------------------------------------------------------------
    def submit(self, item: SessionRecord | SecurityEvent | AlertItem) -> None:
        if isinstance(item, SecurityEvent):
            log_security(log, "[%s] %s: %s (user=%s op=%s param=%s switch=%s)", item.severity.value,
                         item.action, item.reason, item.username or "-", item.operation or "-",
                         item.parameter or "-", item.switch_name or "-")
        if self._queue is not None and self._worker is not None and not self._worker.done():
            self._queue.put_nowait(item)
            return
        try:
            task = asyncio.get_running_loop().create_task(self._write(item))
        except RuntimeError:  # no loop (should not happen inside the app)
            log.error("Security recorder: no event loop; record dropped: %r", item)
            return
        self._direct.add(task)
        task.add_done_callback(self._direct.discard)

    async def _run(self) -> None:
        assert self._queue is not None
        while True:
            item = await self._queue.get()
            try:
                await self._write(item)
            except Exception:  # noqa: BLE001
                log.exception("Security recorder failed to persist an item")
            finally:
                self._queue.task_done()

    async def _write(self, item: SessionRecord | SecurityEvent | AlertItem) -> None:
        from datetime import timedelta

        from sqlalchemy import select

        from app.db.session import session_factory
        from app.models import Alert, AuditLog, SshSessionRecord

        async with session_factory()() as db:
            if isinstance(item, AlertItem):
                key = item.dedupe_key or f"{item.kind}:{item.switch_name}:{item.port}:{item.mac}"
                existing = (await db.execute(select(Alert).where(
                    Alert.dedupe_key == key, Alert.status == "open",
                    Alert.last_seen_at >= utcnow() - timedelta(minutes=DEDUPE_MINUTES),
                ).order_by(Alert.id.desc()).limit(1))).scalar_one_or_none()
                if existing is not None:
                    existing.occurrences += 1
                    existing.last_seen_at = utcnow()
                else:
                    db.add(Alert(kind=item.kind, severity=item.severity, title=item.title[:200],
                                 message=item.message, switch_name=item.switch_name,
                                 port=item.port, mac=item.mac, dedupe_key=key[:200],
                                 details=item.details))
                await db.commit()
                return
            if isinstance(item, SessionRecord):
                db.add(SshSessionRecord(
                    id=item.id, switch_id=item.switch_id, switch_name=item.switch_name,
                    profile_key=item.profile_key, user_id=item.user_id, username=item.username,
                    purpose=item.purpose, reference=item.reference[:64],
                    operations=sorted(set(item.operations)), started_at=item.started_at,
                    ended_at=item.ended_at or utcnow(), commands_attempted=item.attempted,
                    commands_executed=item.executed, commands_blocked=item.blocked,
                    result=item.result, error=item.error[:2000],
                    commands=[e.to_dict() for e in item.events],
                ))
            else:
                db.add(AuditLog(
                    user_id=item.user_id, username=item.username or "system",
                    action=item.action, result="BLOCKED", severity=item.severity.value,
                    operation=item.operation[:32],
                    target_type="command", switch_name=item.switch_name, port=item.port,
                    mac=item.mac, ip=item.ip, message=item.reason[:1024],
                    details={"operation": item.operation, "parameter": item.parameter,
                             "commands_executed": 0, **item.details},
                ))
            await db.commit()


_recorder = Recorder()


def get_recorder() -> Recorder:
    return _recorder
