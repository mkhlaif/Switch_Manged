"""In-memory pub/sub for live search progress (consumed by the SSE endpoint)."""

from __future__ import annotations

import asyncio
from collections import defaultdict


class ProgressBroker:
    def __init__(self) -> None:
        self._subscribers: dict[str, set[asyncio.Queue]] = defaultdict(set)

    def subscribe(self, search_id: str) -> asyncio.Queue:
        queue: asyncio.Queue = asyncio.Queue(maxsize=1000)
        self._subscribers[search_id].add(queue)
        return queue

    def unsubscribe(self, search_id: str, queue: asyncio.Queue) -> None:
        subs = self._subscribers.get(search_id)
        if subs is not None:
            subs.discard(queue)
            if not subs:
                self._subscribers.pop(search_id, None)

    def publish(self, search_id: str, event: dict) -> None:
        for queue in list(self._subscribers.get(search_id, ())):
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:  # a stalled client must not block the search
                pass


broker = ProgressBroker()
