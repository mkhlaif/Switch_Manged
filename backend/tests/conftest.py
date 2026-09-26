"""Test harness.

No test ever touches a real switch: every switch is either the in-process simulator or the lab
SSH server bound to 127.0.0.1 on an ephemeral port.
"""

from __future__ import annotations

import os
from pathlib import Path

from cryptography.fernet import Fernet

# Must be set before app modules read settings.
os.environ.update({
    "ENVIRONMENT": "test",
    "CREDENTIAL_ENCRYPTION_KEY": Fernet.generate_key().decode(),
    "COOKIE_SECURE": "false",
    "ENABLE_SIMULATOR": "true",
    "SSH_CONNECT_TIMEOUT": "3",
    "SSH_LOGIN_TIMEOUT": "4",
    "SSH_COMMAND_TIMEOUT": "2",
    "SSH_CONNECT_RETRIES": "0",
    "SSH_SWITCH_BUDGET_SECONDS": "20",
    "INITIAL_ADMIN_USERNAME": "",
    "INITIAL_ADMIN_PASSWORD": "",
    "LOG_LEVEL": "INFO",
})

import asyncio  # noqa: E402

import httpx  # noqa: E402
import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402

from app.core.config import get_settings  # noqa: E402
from app.core.crypto import encrypt_secret  # noqa: E402
from app.core.ratelimit import limiter  # noqa: E402
from app.core.security import hash_password  # noqa: E402
from app.db.base import Base  # noqa: E402
from app.db.session import dispose_engine, init_engine, session_factory  # noqa: E402
from app.models import CommandVerification, Credential, Role, Switch, User  # noqa: E402
from app.simulator import session as sim_session  # noqa: E402
from app.simulator.scenarios import SIM_PASSWORD, SIM_USERNAME, build_lab  # noqa: E402

FIXTURES = Path(__file__).parent / "fixtures"
PASSWORDS = {
    "admin": "Admin-Passw0rd!",
    "operator": "Operator-Passw0rd!",
    "reader": "Reader-Passw0rd!",
    "macop": "MacOperator-Passw0rd!",
}


def fixture_text(relative: str) -> str:
    return (FIXTURES / relative).read_text(encoding="utf-8")


@pytest.fixture
def lab():
    """A fresh simulated lab with fast MAC relearning."""
    switches = build_lab(relearn_delay=0.2)
    sim_session.set_registry(switches)
    yield switches
    sim_session.reset_registry()


@pytest_asyncio.fixture
async def db_url(tmp_path):
    settings = get_settings()
    url = f"sqlite+aiosqlite:///{(tmp_path / 'test.db').as_posix()}"
    settings.database_url = url
    engine = init_engine(url)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    await dispose_engine()
    limiter.reset()
    yield url


@pytest_asyncio.fixture
async def app(db_url, lab):
    from app.main import create_app

    application = create_app()
    async with application.router.lifespan_context(application):
        async with session_factory()() as db:
            for username, role in (("admin", Role.ADMIN), ("operator", Role.OPERATOR),
                                   ("reader", Role.READONLY), ("macop", Role.MAC_OPERATOR)):
                db.add(User(username=username, full_name=username.title(), role=role.value,
                            password_hash=hash_password(PASSWORDS[username])))
            await db.commit()
        yield application


class Api:
    """Logged-in HTTP client helper."""

    def __init__(self, client: httpx.AsyncClient):
        self.client = client

    async def login(self, username: str, password: str | None = None) -> httpx.Response:
        resp = await self.client.post("/api/auth/login", json={
            "username": username, "password": password or PASSWORDS[username]})
        if resp.status_code == 200:
            self.client.headers["X-CSRF-Token"] = resp.json()["csrf_token"]
        return resp

    def __getattr__(self, name):
        return getattr(self.client, name)


@pytest_asyncio.fixture
async def make_client(app):
    clients: list[httpx.AsyncClient] = []

    async def _make(username: str | None = None) -> Api:
        client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                   base_url="http://testserver")
        clients.append(client)
        api = Api(client)
        if username:
            resp = await api.login(username)
            assert resp.status_code == 200, resp.text
        return api

    yield _make
    for c in clients:
        await c.aclose()


@pytest_asyncio.fixture
async def admin(make_client) -> Api:
    return await make_client("admin")


@pytest_asyncio.fixture
async def operator(make_client) -> Api:
    return await make_client("operator")


@pytest_asyncio.fixture
async def reader(make_client) -> Api:
    return await make_client("reader")


@pytest_asyncio.fixture
async def macop(make_client) -> Api:
    return await make_client("macop")


async def set_setting(key: str, value) -> None:
    """Write a runtime setting directly (tests only; the API routes mode changes through the
    audited safety endpoints)."""
    from app.services import system_settings

    async with session_factory()() as db:
        if key in system_settings.INTERNAL_KEYS:
            await system_settings.set_internal(db, key, value, "test")
        else:
            await system_settings.set_value(db, key, value, "test")
        await db.commit()


async def set_mode(mode: str) -> None:
    await set_setting("operation_mode", mode)


@pytest_asyncio.fixture
async def maintenance(app) -> None:
    """State-changing operations require MAINTENANCE mode (NORMAL is read-only)."""
    await set_mode("MAINTENANCE")


async def seed_lab_switches(names: list[str] | None = None, *, unknown_version: tuple[str, ...] = (),
                            uplinks: dict[str, list[str]] | None = None,
                            roles: dict[str, str] | None = None) -> dict[str, int]:
    """Insert simulated switches into the inventory; returns name -> id."""
    lab_switches = sim_session.registry()
    ids: dict[str, int] = {}
    async with session_factory()() as db:
        cred = Credential(name="lab", username=SIM_USERNAME,
                          password_encrypted=encrypt_secret(SIM_PASSWORD))
        db.add(cred)
        await db.flush()
        for key, sim in lab_switches.items():
            if names and sim.name not in names:
                continue
            sw = Switch(name=sim.name, host=sim.name, transport="simulator",
                        model="" if sim.name in unknown_version else sim.model,
                        aos_version="" if sim.name in unknown_version else sim.version,
                        location=sim.location, credential_id=cred.id,
                        uplink_ports=(uplinks or {}).get(sim.name, []),
                        role=(roles or {}).get(sim.name, "unknown"))
            db.add(sw)
            await db.flush()
            ids[sim.name] = sw.id
        await db.commit()
    return ids


async def verify(profile_key: str, capability: str, prefix: str,
                 model_family: str = "*") -> None:
    """Record an administrator lab verification (capability = "READ" or a strategy id)."""
    async with session_factory()() as db:
        db.add(CommandVerification(profile_key=profile_key, capability=capability,
                                   model_family=model_family, version_prefix=prefix,
                                   verified_by="test-admin"))
        await db.commit()


approve = verify  # restart strategies are lab-verified per model family / AOS version


async def wait_for_search(api: Api, search_id: str, timeout: float = 30.0) -> dict:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        data = (await api.get(f"/api/mac/search/{search_id}")).json()
        if data["status"] in {"completed", "failed", "interrupted"}:
            return data
        await asyncio.sleep(0.05)
    raise AssertionError(f"search {search_id} did not finish")


async def wait_for_action(api: Api, action_id: int, timeout: float = 30.0) -> dict:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        data = (await api.get(f"/api/ports/actions/{action_id}")).json()
        if data["status"] not in {"running", "planned"}:
            return data
        await asyncio.sleep(0.05)
    raise AssertionError(f"action {action_id} did not finish")
