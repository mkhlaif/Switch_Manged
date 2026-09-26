from __future__ import annotations

import csv
import io
from datetime import datetime

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.csv_safe import csv_cell
from app.core.permissions import Permission
from app.core.ratelimit import limiter
from app.api.deps import require
from app.core.errors import ValidationFailedError
from app.db.session import get_db
from app.models import MacSearch, MacSearchResult, User
from app.parsers.common import InvalidMacError, format_mac, normalize_mac

router = APIRouter(prefix="/api/search-history", tags=["history"])


def _filters(query, mac: str | None, user: str | None, since: datetime | None,
             until: datetime | None):
    if mac:
        try:
            query = query.where(MacSearch.mac == normalize_mac(mac))
        except InvalidMacError as exc:
            raise ValidationFailedError(str(exc)) from exc
    if user:
        query = query.where(MacSearch.requested_by == user.lower())
    if since:
        query = query.where(MacSearch.created_at >= since)
    if until:
        query = query.where(MacSearch.created_at <= until)
    return query


async def _rows(db: AsyncSession, searches: list[MacSearch]) -> list[dict]:
    ids = [s.id for s in searches]
    found: dict[str, list[MacSearchResult]] = {i: [] for i in ids}
    if ids:
        for r in (await db.execute(select(MacSearchResult).where(
            MacSearchResult.search_id.in_(ids), MacSearchResult.status == "found"
        ).order_by(MacSearchResult.id))).scalars():
            found[r.search_id].append(r)
    rows = []
    for s in searches:
        hits = found[s.id]
        edge = (s.summary or {}).get("likely_edge") or {}
        first = hits[0] if hits else None
        if s.status != "completed":
            result = s.status.upper()
        else:
            result = "FOUND" if hits else ("NOT_FOUND" if not s.failed_count and not s.timeout_count
                                           else "NOT_FOUND_WITH_ERRORS")
        rows.append({
            "id": s.id,
            "time": s.created_at.isoformat(),
            "user": s.requested_by,
            "mac": format_mac(s.mac),
            "switch": edge.get("switch_name") or (first.switch_name if first else ""),
            "port": edge.get("port") or (first.port or first.interface_raw if first else ""),
            "vlan": edge.get("vlan_id") or (first.vlan_id if first else None),
            "locations": len(hits),
            "result": result,
            "status": s.status,
            "checked": s.checked,
            "total": s.total_switches,
            "failed": s.failed_count + s.timeout_count,
            "duration_ms": s.duration_ms,
            "mac_move": bool((s.summary or {}).get("mac_move")),
        })
    return rows


@router.get("")
async def history(mac: str | None = None, user: str | None = None,
                  since: datetime | None = None, until: datetime | None = None,
                  limit: int = Query(default=50, ge=1, le=500), offset: int = Query(default=0, ge=0),
                  _: User = Depends(require(Permission.VIEW_HISTORY)), db: AsyncSession = Depends(get_db)) -> dict:
    base = _filters(select(MacSearch), mac, user, since, until)
    total = (await db.execute(select(func.count()).select_from(base.subquery()))).scalar_one()
    searches = (await db.execute(base.order_by(MacSearch.created_at.desc())
                                 .limit(limit).offset(offset))).scalars().all()
    return {"total": total, "items": await _rows(db, list(searches))}


@router.get("/export")
async def export_history(mac: str | None = None, user: str | None = None,
                         since: datetime | None = None, until: datetime | None = None,
                         viewer: User = Depends(require(Permission.VIEW_HISTORY)), db: AsyncSession = Depends(get_db)):
    limiter.hit(f"history-export:{viewer.id}", limit=5, window_seconds=60)
    base = _filters(select(MacSearch), mac, user, since, until)
    searches = (await db.execute(base.order_by(MacSearch.created_at.desc()).limit(10000)
                                 )).scalars().all()
    rows = await _rows(db, list(searches))
    buf = io.StringIO()
    fields = ["time", "user", "mac", "switch", "port", "vlan", "locations", "result", "checked",
              "total", "failed", "duration_ms", "mac_move", "id"]
    writer = csv.DictWriter(buf, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        writer.writerow({k: csv_cell(v) for k, v in row.items()})
    return StreamingResponse(iter([buf.getvalue()]), media_type="text/csv", headers={
        "Content-Disposition": "attachment; filename=mac-search-history.csv"})
