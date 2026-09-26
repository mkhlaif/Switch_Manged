"""Background task registry.

Search jobs and port actions run as asyncio tasks inside the API process. Keeping a strong
reference prevents premature garbage collection, and shutdown can wait for / cancel them.
Port actions are shielded: once a port has been taken down, the "up" command must still be sent
even if the HTTP client disconnects.
"""

from __future__ import annotations

import asyncio
from collections.abc import Coroutine
from typing import Any

from app.core.logging import get_logger

log = get_logger("tasks")
_tasks: set[asyncio.Task] = set()


def spawn(coro: Coroutine[Any, Any, Any], name: str) -> asyncio.Task:
    task = asyncio.create_task(coro, name=name)
    _tasks.add(task)

    def _done(t: asyncio.Task) -> None:
        _tasks.discard(t)
        if not t.cancelled() and t.exception() is not None:
            log.error("Background task %s failed: %r", name, t.exception())

    task.add_done_callback(_done)
    return task


def running() -> list[asyncio.Task]:
    return [t for t in _tasks if not t.done()]


async def drain(timeout: float = 30.0) -> None:
    """Give running tasks (especially port actions) a chance to finish before shutdown."""
    pending = running()
    if not pending:
        return
    log.warning("Waiting up to %.0fs for %d background task(s) to finish", timeout, len(pending))
    done, still = await asyncio.wait(pending, timeout=timeout)
    for task in still:
        log.error("Cancelling unfinished background task %s", task.get_name())
        task.cancel()
