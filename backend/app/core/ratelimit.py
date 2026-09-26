"""Small in-process sliding-window rate limiter.

The backend runs as a single process (see README, "Why no Redis"), so an in-memory limiter is
sufficient. Keys are arbitrary strings such as ``login:<ip>:<username>``.
"""

from __future__ import annotations

import time
from collections import defaultdict, deque

from app.core.errors import RateLimitedError


class RateLimiter:
    def __init__(self) -> None:
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def hit(self, key: str, limit: int, window_seconds: float) -> None:
        now = time.monotonic()
        bucket = self._hits[key]
        while bucket and now - bucket[0] > window_seconds:
            bucket.popleft()
        if len(bucket) >= limit:
            retry = int(window_seconds - (now - bucket[0])) + 1
            raise RateLimitedError(
                f"Too many requests. Try again in {retry} seconds.",
                action="Wait and retry",
                details={"retry_after_seconds": retry},
            )
        bucket.append(now)

    def reset(self, key: str | None = None) -> None:
        if key is None:
            self._hits.clear()
        else:
            self._hits.pop(key, None)


limiter = RateLimiter()
