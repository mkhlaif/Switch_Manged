"""Authentication, CSRF, role-based authorization and secret handling."""

from sqlalchemy import select

from app.db.session import session_factory
from app.models import AuditLog, Credential


async def test_login_success_sets_http_only_cookie(make_client):
    api = await make_client()
    resp = await api.login("admin")
    assert resp.status_code == 200
    body = resp.json()
    assert body["user"]["role"] == "admin" and "password_hash" not in body["user"]
    cookie_header = ",".join(resp.headers.get_list("set-cookie"))
    assert "netops_session=" in cookie_header and "HttpOnly" in cookie_header
    assert "SameSite=strict" in cookie_header
    me = await api.get("/api/auth/me")
    assert me.status_code == 200 and me.json()["user"]["username"] == "admin"


async def test_login_failure_and_lockout(make_client):
    api = await make_client()
    for _ in range(5):
        resp = await api.login("operator", "wrong-password")
        assert resp.status_code == 401
        assert resp.json()["error"]["code"] == "INVALID_CREDENTIALS"
    locked = await api.login("operator")  # correct password, but locked now
    assert locked.status_code == 401 and locked.json()["error"]["code"] == "ACCOUNT_LOCKED"


async def test_unknown_user_gives_same_error(make_client):
    api = await make_client()
    resp = await api.login("nobody", "Whatever-Passw0rd!")
    assert resp.status_code == 401 and resp.json()["error"]["code"] == "INVALID_CREDENTIALS"


async def test_unauthenticated_requests_rejected(make_client):
    api = await make_client()
    for path in ("/api/switches", "/api/dashboard", "/api/audit", "/api/search-history"):
        resp = await api.get(path)
        assert resp.status_code == 401
        assert set(resp.json()["error"]) >= {"code", "title", "message"}


async def test_csrf_required_for_state_changes(admin):
    token = admin.client.headers.pop("X-CSRF-Token")
    resp = await admin.post("/api/credentials", json={"name": "c", "username": "u",
                                                       "password": "p"})
    assert resp.status_code == 403 and resp.json()["error"]["code"] == "CSRF_FAILED"
    admin.client.headers["X-CSRF-Token"] = "forged"
    resp = await admin.post("/api/credentials", json={"name": "c", "username": "u",
                                                       "password": "p"})
    assert resp.status_code == 403
    admin.client.headers["X-CSRF-Token"] = token
    resp = await admin.post("/api/credentials", json={"name": "c", "username": "u",
                                                       "password": "p"})
    assert resp.status_code == 201


async def test_readonly_permissions(reader):
    assert (await reader.get("/api/switches")).status_code == 200
    assert (await reader.get("/api/search-history")).status_code == 200
    assert (await reader.post("/api/switches", json={"name": "x", "host": "10.0.0.1"})
            ).status_code == 403
    assert (await reader.get("/api/credentials")).status_code == 403
    assert (await reader.get("/api/users")).status_code == 403
    assert (await reader.post("/api/ports/restart/prepare", json={
        "switch_id": 1, "port": "1/1/26", "mac": "001122334455"})).status_code == 403
    assert (await reader.put("/api/settings", json={"values": {"dry_run_mode": False}})
            ).status_code == 403


async def test_operator_cannot_manage_inventory_or_settings(operator):
    assert (await operator.post("/api/switches", json={"name": "x", "host": "10.0.0.1"})
            ).status_code == 403
    assert (await operator.put("/api/settings", json={"values": {"dry_run_mode": False}})
            ).status_code == 403
    assert (await operator.post("/api/profiles/verifications", json={
        "profile_key": "AOS8", "capability": "INTERFACE_ADMIN_STATE", "model_family": "*",
        "version_prefix": "8.10"})).status_code == 403
    assert (await operator.post("/api/safety/mode", json={
        "mode": "MAINTENANCE", "reason": "operator attempt"})).status_code == 403


async def test_credential_password_is_encrypted_and_never_returned(admin):
    resp = await admin.post("/api/credentials", json={
        "name": "core", "username": "netops", "password": "S3cret-Switch-Pass"})
    assert resp.status_code == 201
    assert "S3cret" not in resp.text and "password" not in resp.json()
    listing = await admin.get("/api/credentials")
    assert "S3cret" not in listing.text
    async with session_factory()() as db:
        cred = (await db.execute(select(Credential))).scalar_one()
        assert "S3cret" not in cred.password_encrypted
        audit = (await db.execute(select(AuditLog))).scalars().all()
        assert all("S3cret" not in str(a.details) for a in audit)


async def test_user_management_rules(admin):
    weak = await admin.post("/api/users", json={"username": "bob", "password": "short",
                                                 "role": "operator"})
    assert weak.status_code == 422
    ok = await admin.post("/api/users", json={"username": "bob", "password": "Bob-Passw0rd-123",
                                               "role": "operator"})
    assert ok.status_code == 201
    me = (await admin.get("/api/auth/me")).json()["user"]
    assert (await admin.delete(f"/api/users/{me['id']}")).status_code == 422
    demote = await admin.patch(f"/api/users/{me['id']}", json={"role": "readonly"})
    assert demote.status_code == 422  # last admin


async def test_logout_invalidates_session(make_client):
    api = await make_client("operator")
    assert (await api.post("/api/auth/logout")).status_code == 200
    assert (await api.get("/api/auth/me")).status_code == 401


async def test_errors_never_expose_python_exceptions(admin):
    resp = await admin.get("/api/mac/search/does-not-exist")
    assert resp.status_code == 404
    assert "Traceback" not in resp.text and resp.json()["error"]["title"] == "Not found"
    bad = await admin.post("/api/mac/search", json={"mac": "zz:zz:zz:zz:zz:zz"})
    assert bad.status_code == 422 and "Invalid MAC" in bad.json()["error"]["message"]
