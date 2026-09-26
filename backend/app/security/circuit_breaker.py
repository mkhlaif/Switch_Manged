"""Network safety circuit breaker (§24).

Trips into SAFE MODE when, within the configured window:

* N consecutive SSH failures on switches that were previously healthy (default 5) — a success
  resets the count. Switches already known to be offline do not count again, so a permanently
  dead switch in the inventory cannot keep the platform in SAFE MODE;
* N consecutive authentication failures on previously healthy switches (default 3);
* N HIGH/CRITICAL command-validation failures (default 3) — injection attempts, forged or
  dangerous commands, budget violations;
* N unexpected CLI responses (default 3) — output that does not match the command's contract;
* N device identity mismatches (default 3) — discovery found another model / AOS version than
  expected or than before (profile mismatch);
* N failed post-restart verifications (default 3) — restarts whose postcondition could not be
  confirmed.

SAFE MODE is persisted in the database (it survives restarts) and blocks every state-changing
operation. Read-only operations continue. Only an administrator can reset it.
"""

from __future__ import annotations

import asyncio
import time
from collections import deque

from app.core.logging import get_logger, log_security

log = get_logger("security.breaker")

DEFAULTS = {"breaker_ssh_failures": 5, "breaker_auth_failures": 3,
            "breaker_validation_failures": 3, "breaker_unexpected_output": 3,
            "breaker_profile_mismatches": 3, "breaker_verification_failures": 3,
            "breaker_window_minutes": 10}


class CircuitBreaker:
    def __init__(self) -> None:
        self.ssh_failures: deque[float] = deque()
        self.auth_failures: deque[float] = deque()
        self.validation_failures: deque[float] = deque()
        self.unexpected_output: deque[float] = deque()
        self.profile_mismatches: deque[float] = deque()
        self.verification_failures: deque[float] = deque()
        self.last_events: deque[str] = deque(maxlen=20)
        self._tasks: set[asyncio.Task] = set()
        self._tripping = False

    # -------------------------------------------------------------------------- hooks ---
    def record_ssh_success(self) -> None:
        self.ssh_failures.clear()
        self.auth_failures.clear()

    def record_ssh_failure(self, *, switch_name: str, auth: bool, previously_healthy: bool,
                           reason: str = "") -> None:
        if not previously_healthy:
            return
        now = time.monotonic()
        (self.auth_failures if auth else self.ssh_failures).append(now)
        self.last_events.append(f"{'AUTH' if auth else 'SSH'} failure on {switch_name}: {reason}")
        self._schedule()

    def record_validation_failure(self, *, reason: str) -> None:
        self.validation_failures.append(time.monotonic())
        self.last_events.append(f"Validation failure: {reason[:120]}")
        self._schedule()

    def record_unexpected_output(self, *, switch_name: str, detail: str) -> None:
        self.unexpected_output.append(time.monotonic())
        self.last_events.append(f"Unexpected CLI output on {switch_name}: {detail[:120]}")
        self._schedule()

    def record_profile_mismatch(self, *, switch_name: str, detail: str) -> None:
        self.profile_mismatches.append(time.monotonic())
        self.last_events.append(f"Identity mismatch on {switch_name}: {detail[:120]}")
        self._schedule()

    def record_verification_failure(self, *, switch_name: str, detail: str) -> None:
        self.verification_failures.append(time.monotonic())
        self.last_events.append(f"Restart not verified on {switch_name}: {detail[:120]}")
        self._schedule()

    def _queues(self) -> tuple:
        return (self.ssh_failures, self.auth_failures, self.validation_failures,
                self.unexpected_output, self.profile_mismatches, self.verification_failures)

    def reset(self) -> None:
        for q in self._queues():
            q.clear()
        self._tripping = False

    def counters(self) -> dict:
        return {"ssh_failures": len(self.ssh_failures), "auth_failures": len(self.auth_failures),
                "validation_failures": len(self.validation_failures),
                "unexpected_output": len(self.unexpected_output),
                "profile_mismatches": len(self.profile_mismatches),
                "verification_failures": len(self.verification_failures),
                "recent_events": list(self.last_events)}

    async def flush(self) -> None:
        if self._tasks:
            await asyncio.gather(*list(self._tasks), return_exceptions=True)

    # ---------------------------------------------------------------------- evaluation ---
    def _schedule(self) -> None:
        try:
            task = asyncio.get_running_loop().create_task(self._evaluate())
        except RuntimeError:
            return
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _thresholds(self) -> dict:
        from app.db.session import session_factory
        from app.services import system_settings

        try:
            async with session_factory()() as db:
                values = await system_settings.get_all(db)
            return {k: int(values.get(k, v)) for k, v in DEFAULTS.items()}
        except Exception:  # noqa: BLE001 - use safe defaults
            return dict(DEFAULTS)

    async def _evaluate(self) -> None:
        if self._tripping:
            return
        t = await self._thresholds()
        window = t["breaker_window_minutes"] * 60
        now = time.monotonic()
        for q in self._queues():
            while q and now - q[0] > window:
                q.popleft()
        reason = None
        if len(self.ssh_failures) >= t["breaker_ssh_failures"]:
            reason = f"{len(self.ssh_failures)} consecutive SSH failures on healthy switches"
        elif len(self.auth_failures) >= t["breaker_auth_failures"]:
            reason = f"{len(self.auth_failures)} consecutive SSH authentication failures"
        elif len(self.validation_failures) >= t["breaker_validation_failures"]:
            reason = f"{len(self.validation_failures)} command validation failures"
        elif len(self.unexpected_output) >= t["breaker_unexpected_output"]:
            reason = f"{len(self.unexpected_output)} unexpected CLI responses"
        elif len(self.profile_mismatches) >= t["breaker_profile_mismatches"]:
            reason = f"{len(self.profile_mismatches)} device identity (profile) mismatches"
        elif len(self.verification_failures) >= t["breaker_verification_failures"]:
            reason = f"{len(self.verification_failures)} restarts could not be verified"
        if reason:
            self._tripping = True
            await trip(reason, list(self.last_events))


async def trip(reason: str, events: list[str], username: str = "system") -> bool:
    """Persist SAFE MODE (idempotent). Returns True when this call activated it."""
    from app.db.session import session_factory
    from app.models import AuditLog, SafetyEvent
    from app.security.recorder import AlertItem, get_recorder
    from app.services import system_settings

    try:
        async with session_factory()() as db:
            values = await system_settings.get_all(db)
            if values.get("safe_mode") is True:
                return False
            await system_settings.set_internal(db, "safe_mode", True, username)
            await system_settings.set_internal(db, "safe_mode_reason", reason, username)
            db.add(SafetyEvent(kind="BREAKER_TRIP", username=username, old_value="normal",
                               new_value="SAFE_MODE", reason=reason, details={"events": events}))
            db.add(AuditLog(username=username, action="CIRCUIT_BREAKER_TRIP", result="BLOCKED",
                            severity="CRITICAL", target_type="safety",
                            message=f"SAFE MODE activated: {reason}",
                            details={"events": events}))
            await db.commit()
    except Exception:  # noqa: BLE001
        log.exception("Circuit breaker could not persist SAFE MODE")
        return False
    log_security(log, "CRITICAL: circuit breaker tripped, SAFE MODE active: %s", reason)
    get_recorder().submit(AlertItem(kind="CIRCUIT_BREAKER", severity="CRITICAL",
                                    title="Circuit breaker activated: SAFE MODE",
                                    message=f"{reason}. State-changing operations are blocked "
                                            "until an administrator resets SAFE MODE.",
                                    dedupe_key="circuit-breaker", details={"events": events}))
    return True


_breaker = CircuitBreaker()


def get_breaker() -> CircuitBreaker:
    return _breaker


def init_breaker() -> CircuitBreaker:
    global _breaker
    _breaker = CircuitBreaker()
    return _breaker
