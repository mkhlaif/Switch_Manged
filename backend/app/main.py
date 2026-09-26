"""FastAPI application factory."""

from __future__ import annotations

import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import func, select, text
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.api.routes import (
    alerts,
    audit,
    auth,
    credentials,
    dashboard,
    history,
    integrations,
    mac,
    operations,
    ports,
    profiles,
    safety,
    settings,
    simple,
    switch_transfer,
    switches,
    topology,
    users,
)
from app.core.config import get_settings
from app.core.crypto import check_key_configured
from app.core.errors import AppError
from app.core.logging import configure_logging, get_logger, log_security
from app.core.security import hash_password, validate_password_strength
from app.db.session import dispose_engine, init_engine, session_factory
from app.models import Role, User
from app.security.circuit_breaker import init_breaker
from app.security.firewall import get_firewall, init_firewall
from app.security.recorder import get_recorder
from app.security.request_guard import BodySizeLimit, CommandFieldGuard
from app.services.alcatel.registry import sync_builtin_profiles
from app.services.inventory.bulk import mark_interrupted_imports
from app.services.mac_search.service import mark_interrupted_searches
from app.services.port_control.service import mark_interrupted_actions
from app.services.ssh.manager import init_connector
from app.workers import tasks

log = get_logger("app")


async def _bootstrap_admin() -> None:
    s = get_settings()
    async with session_factory()() as db:
        users = (await db.execute(select(func.count()).select_from(User))).scalar_one()
        if users:
            return
        if not (s.initial_admin_username and s.initial_admin_password):
            log.warning("No users exist. Create an administrator with: "
                        "python -m app.cli create-user --role admin <username>")
            return
        problem = validate_password_strength(s.initial_admin_password)
        if problem:
            log.error("INITIAL_ADMIN_PASSWORD rejected: %s", problem)
            return
        db.add(User(username=s.initial_admin_username.lower(), full_name="Administrator",
                    role=Role.ADMIN.value, password_hash=hash_password(s.initial_admin_password)))
        await db.commit()
        log_security(log, "Bootstrap administrator '%s' created from environment; remove "
                     "INITIAL_ADMIN_PASSWORD from the environment now.", s.initial_admin_username)


@asynccontextmanager
async def lifespan(app: FastAPI):
    s = get_settings()
    configure_logging(s.log_level, s.log_format)
    check_key_configured()
    init_engine(s.database_url)
    init_connector(s)
    breaker = init_breaker()
    firewall = init_firewall(breaker=breaker)
    await get_recorder().start()
    if firewall.ready:
        log.info("Command Safety Firewall ready (policy digest %s)", firewall.digest[:16])
    if s.read_only_mode:
        log.warning("READ_ONLY_MODE=true: all state-changing operations are blocked")
    if s.network_command_execution.strip().upper() != "ENABLED":
        log.warning("NETWORK_COMMAND_EXECUTION=%r (not ENABLED): kill switch forced by the "
                    "environment", s.network_command_execution)
    async with session_factory()() as db:
        await sync_builtin_profiles(db)
        n_searches = await mark_interrupted_searches(db)
        n_actions = await mark_interrupted_actions(db)
        n_imports = await mark_interrupted_imports(db)
        if n_searches or n_actions or n_imports:
            log.warning("Marked %d search(es), %d port action(s) and %d import(s) as "
                        "interrupted", n_searches, n_actions, n_imports)
    await _bootstrap_admin()
    if s.ssh_allow_unknown_host_keys:
        log_security(log, "SSH_ALLOW_UNKNOWN_HOST_KEYS is ON: host-key verification is disabled "
                     "for switches without a trusted key. Lab use only.")
    if s.enable_simulator:
        log.warning("Lab mode: simulator transport enabled (ENABLE_SIMULATOR=true)")
    log.info("%s started (max %d concurrent switch connections)", s.app_name,
             s.max_concurrent_switch_connections)
    yield
    await tasks.drain(timeout=60)
    await breaker.flush()
    await get_recorder().stop()
    await dispose_engine()


def _error(status: int, code: str, title: str, message: str, **extra) -> JSONResponse:
    body = {"code": code, "title": title, "message": message, **extra}
    return JSONResponse(status_code=status, content={"error": body})


def create_app() -> FastAPI:
    s = get_settings()
    app = FastAPI(title=s.app_name, version="1.0.0", lifespan=lifespan,
                  docs_url="/api/docs" if s.environment != "production" else None,
                  redoc_url=None, openapi_url="/api/openapi.json"
                  if s.environment != "production" else None)

    # Rejects any request body that carries a command-like field (see security/request_guard).
    app.add_middleware(CommandFieldGuard)
    # Outermost of the two: oversized bodies are refused before anything reads them.
    app.add_middleware(BodySizeLimit)

    if s.cors_origin_list:
        app.add_middleware(CORSMiddleware, allow_origins=s.cors_origin_list,
                           allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Cache-Control", "no-store")
        response.headers.setdefault("Content-Security-Policy",
                                    "default-src 'none'; frame-ancestors 'none'")
        if s.cookie_secure:
            response.headers.setdefault("Strict-Transport-Security",
                                        "max-age=31536000; includeSubDomains")
        return response

    @app.exception_handler(AppError)
    async def app_error(_: Request, exc: AppError):
        return JSONResponse(status_code=exc.status_code, content=exc.to_dict())

    @app.exception_handler(RequestValidationError)
    async def validation_error(_: Request, exc: RequestValidationError):
        problems = []
        for err in exc.errors():
            loc = ".".join(str(p) for p in err.get("loc", ()) if p not in ("body", "query", "path"))
            problems.append(f"{loc}: {err.get('msg')}" if loc else err.get("msg"))
        return _error(422, "VALIDATION_FAILED", "Invalid input", "; ".join(problems))

    @app.exception_handler(StarletteHTTPException)
    async def http_error(_: Request, exc: StarletteHTTPException):
        return _error(exc.status_code, "HTTP_ERROR", "Request failed", str(exc.detail))

    @app.exception_handler(Exception)
    async def unexpected(request: Request, exc: Exception):
        ref = uuid.uuid4().hex[:12]
        log.exception("Unhandled error ref=%s on %s %s", ref, request.method, request.url.path)
        return _error(500, "INTERNAL_ERROR", "Unexpected error",
                      f"An unexpected error occurred. Reference: {ref}. No configuration "
                      "changes were made by this request.", reference=ref)

    @app.get("/api/health", tags=["health"])
    @app.get("/health", tags=["health"], include_in_schema=False)
    async def health(response: Response) -> dict:
        """Liveness/readiness without authentication. Never returns connection strings,
        credentials or configuration values."""
        database = "ok"
        try:
            async with session_factory()() as db:
                await db.execute(text("SELECT 1"))
        except Exception:  # noqa: BLE001 - reported as unavailable, details only in the log
            log.exception("Health check: database unavailable")
            database = "unavailable"
        firewall = get_firewall()
        if database != "ok":
            status = "unhealthy"
            response.status_code = 503
        else:
            status = "healthy" if firewall.ready else "degraded"
        return {"status": status, "database": database,
                "safety_firewall": "ok" if firewall.ready else "failed",
                "policy_digest": firewall.digest[:16],
                "running_tasks": len(tasks.running())}

    # switch_transfer before switches: /api/switches/import must not match /{switch_id}.
    for module in (auth, users, credentials, switch_transfer, switches, mac, history, ports,
                   audit, settings, profiles, dashboard, operations, safety, alerts,
                   integrations, simple, topology):
        app.include_router(module.router)
    return app


app = create_app()
