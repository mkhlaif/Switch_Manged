"""Session security audit: a captured session cookie stops working after logout, disabling,
role change, password change or forced logout; wrong passwords, brute force and expired
sessions are handled; a stolen cookie cannot be replayed without the CSRF token."""

from __future__ import annotations

from datetime import timedelta

from sqlalchemy import select

from app.core.timeutil import utcnow
from app.db.session import session_factory
from app.models import User, UserSession
from tests.conftest import PASSWORDS


async def user_id(api, username: str) -> int:
    users = (await api.get("/api/users")).json()
    return next(u["id"] for u in users if u["username"] == username)


async def test_disabled_user_loses_existing_session(admin, make_client):
    victim = await make_client("operator")
    assert (await victim.get("/api/auth/me")).status_code == 200
    uid = await user_id(admin, "operator")
    assert (await admin.patch(f"/api/users/{uid}", json={"is_active": False})).status_code == 200
    assert (await victim.get("/api/auth/me")).status_code == 401
    relogin = await (await make_client()).login("operator")
    assert relogin.status_code == 401


async def test_role_change_ends_sessions(admin, make_client):
    victim = await make_client("reader")
    uid = await user_id(admin, "reader")
    assert (await admin.patch(f"/api/users/{uid}", json={"role": "operator"})).status_code == 200
    assert (await victim.get("/api/auth/me")).status_code == 401


async def test_forced_logout_ends_all_sessions_of_the_user(admin, make_client):
    first = await make_client("operator")
    second = await make_client("operator")
    uid = await user_id(admin, "operator")
    assert (await admin.post(f"/api/users/{uid}/logout")).status_code == 200
    assert (await first.get("/api/auth/me")).status_code == 401
    assert (await second.get("/api/auth/me")).status_code == 401


async def test_password_change_ends_other_sessions(make_client):
    stolen = await make_client("operator")      # e.g. a session captured by an attacker
    owner = await make_client("operator")
    resp = await owner.post("/api/auth/change-password", json={
        "current_password": PASSWORDS["operator"], "new_password": "Brand-New-Passw0rd!"})
    assert resp.status_code == 200
    assert (await stolen.get("/api/auth/me")).status_code == 401
    assert (await owner.get("/api/auth/me")).status_code == 200


async def test_expired_session_is_rejected(make_client):
    api = await make_client("reader")
    async with session_factory()() as db:
        for s in (await db.execute(select(UserSession))).scalars():
            s.expires_at = utcnow() - timedelta(seconds=1)
        await db.commit()
    assert (await api.get("/api/auth/me")).status_code == 401


async def test_stolen_cookie_without_csrf_token_cannot_change_anything(make_client):
    api = await make_client("admin")
    cookie = api.client.cookies.get("netops_session")
    attacker = await make_client()
    attacker.client.cookies.set("netops_session", cookie)
    # Reading with the stolen cookie works (the reason for HttpOnly + SameSite=strict: a
    # browser never sends it cross-site and scripts cannot read it) ...
    assert (await attacker.get("/api/auth/me")).status_code == 200
    # ... but no state change is possible without the per-session CSRF token.
    resp = await attacker.post("/api/users", json={"username": "evil", "password": "x",
                                                    "role": "admin"})
    assert resp.status_code == 403
    async with session_factory()() as db:
        assert (await db.execute(select(User).where(User.username == "evil"))
                ).scalar_one_or_none() is None


async def test_brute_force_is_locked_out_and_rate_limited(make_client):
    api = await make_client()
    codes = [(await api.login("reader", "wrong-password")).status_code for _ in range(12)]
    assert codes[0] == 401
    assert 429 in codes or codes[-1] == 401
    # Even the correct password is refused while the account is locked / rate limited.
    assert (await api.login("reader")).status_code in (401, 429)


async def test_duplicate_user_creation_is_a_conflict(admin):
    body = {"username": "dup-user", "password": "Dup-User-Passw0rd!", "role": "readonly"}
    assert (await admin.post("/api/users", json=body)).status_code == 201
    assert (await admin.post("/api/users", json=body)).status_code == 409
