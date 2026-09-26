from __future__ import annotations

import asyncio
import json

from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.permissions import Permission
from app.api.deps import client_ip, require
from app.core.errors import NotFoundError
from app.core.ratelimit import limiter
from app.db.session import get_db, session_factory
from app.models import MacSearch, MacSearchResult, SearchStatus, User
from app.parsers.common import format_mac
from app.schemas.common import MacSearchOut, MacSearchRequest, MacSearchResultOut
from app.services import system_settings
from app.services.mac_search.progress import broker
from app.services.mac_search.service import start_search

router = APIRouter(prefix="/api/mac", tags=["mac"])

FINAL_STATES = {SearchStatus.COMPLETED.value, SearchStatus.FAILED.value,
                SearchStatus.INTERRUPTED.value}


def _search_dict(search: MacSearch) -> dict:
    data = MacSearchOut.model_validate(search).model_dump(mode="json")
    data["mac_display"] = format_mac(search.mac)
    return data


@router.post("/search", status_code=202)
async def create_search(body: MacSearchRequest, request: Request,
                        user: User = Depends(require(Permission.MAC_SEARCH)),
                        db: AsyncSession = Depends(get_db)) -> dict:
    per_minute = int(await system_settings.get_value(db, "max_mac_searches_per_minute"))
    limiter.hit(f"search:{user.id}", limit=per_minute, window_seconds=60)
    search = await start_search(db, user, body.mac, body.switch_ids, ip=client_ip(request),
                                mode=body.mode)
    return _search_dict(search)


@router.get("/search/{search_id}")
async def get_search(search_id: str, _: User = Depends(require(Permission.MAC_SEARCH)),
                     db: AsyncSession = Depends(get_db)) -> dict:
    search = await db.get(MacSearch, search_id)
    if search is None:
        raise NotFoundError("Search not found.")
    return _search_dict(search)


@router.get("/search/{search_id}/path")
async def get_path(search_id: str, _: User = Depends(require(Permission.MAC_SEARCH)),
                   db: AsyncSession = Depends(get_db)) -> dict:
    """§17 network path, derived from the search's own evidence (no commands are sent)."""
    from app.models import Switch
    from app.services.mac_search.path import build_path

    if await db.get(MacSearch, search_id) is None:
        raise NotFoundError("Search not found.")
    rows = (await db.execute(select(MacSearchResult).where(
        MacSearchResult.search_id == search_id))).scalars().all()
    roles = {s.name: s.role or "unknown" for s in (await db.execute(select(Switch))).scalars()}
    return build_path(rows, roles)


@router.get("/search/{search_id}/results", response_model=list[MacSearchResultOut])
async def get_results(search_id: str, _: User = Depends(require(Permission.MAC_SEARCH)),
                      db: AsyncSession = Depends(get_db)):
    if await db.get(MacSearch, search_id) is None:
        raise NotFoundError("Search not found.")
    return (await db.execute(
        select(MacSearchResult).where(MacSearchResult.search_id == search_id)
        .order_by(MacSearchResult.status != "found", MacSearchResult.switch_name,
                  MacSearchResult.id)
    )).scalars().all()


@router.get("/search/{search_id}/events")
async def search_events(search_id: str, request: Request, _: User = Depends(require(Permission.MAC_SEARCH))):
    """Server-Sent Events stream of search progress."""
    queue = broker.subscribe(search_id)

    async def snapshot() -> dict | None:
        async with session_factory()() as db:
            search = await db.get(MacSearch, search_id)
            return _search_dict(search) if search else None

    async def stream():
        try:
            current = await snapshot()
            if current is None:
                yield f"event: error\ndata: {json.dumps({'message': 'not found'})}\n\n"
                return
            yield f"data: {json.dumps({'type': 'snapshot', 'search': current})}\n\n"
            if current["status"] in FINAL_STATES:
                yield f"data: {json.dumps({'type': 'done', 'search_id': search_id})}\n\n"
                return
            while True:
                if await request.is_disconnected():
                    return
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=15)
                except asyncio.TimeoutError:
                    yield ": keepalive\n\n"
                    continue
                yield f"data: {json.dumps(event, default=str)}\n\n"
                if event.get("type") == "done":
                    return
        finally:
            broker.unsubscribe(search_id, queue)

    return StreamingResponse(stream(), media_type="text/event-stream", headers={
        "Cache-Control": "no-cache", "X-Accel-Buffering": "no", "Connection": "keep-alive",
    })
