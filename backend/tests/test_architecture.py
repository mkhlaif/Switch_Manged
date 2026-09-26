"""Static checks that there is NO bypass path around the Command Safety Firewall."""

import ast
import re
from pathlib import Path

APP = Path(__file__).resolve().parents[1] / "app"
FRONTEND = Path(__file__).resolve().parents[2] / "frontend" / "src"

TRANSPORTS = {"services/ssh/asyncssh_session.py", "simulator/session.py"}


def sources():
    for path in APP.rglob("*.py"):
        yield path.relative_to(APP).as_posix(), path.read_text(encoding="utf-8")


def test_only_transports_send_text_to_the_cli():
    for rel, text in sources():
        if re.search(r"\bcli\.run\(", text):
            assert rel in TRANSPORTS, f"{rel} sends raw text to the CLI driver"


def test_only_the_firewall_calls_run_approved():
    for rel, text in sources():
        calls = re.findall(r"\.run_approved\(", text)
        if calls:
            assert rel == "security/firewall.py", f"{rel} calls run_approved directly"


def test_transports_verify_the_firewall_seal():
    for rel in TRANSPORTS:
        text = (APP / rel).read_text(encoding="utf-8")
        assert "assert_sealed(request)" in text
        tree = ast.parse(text)
        methods = {n.name for n in ast.walk(tree) if isinstance(n, ast.AsyncFunctionDef)}
        assert "run" not in methods, f"{rel} exposes a raw run() method"


def test_transports_are_only_opened_by_the_manager():
    for rel, text in sources():
        if "AsyncSshCliSession.open(" in text or "open_simulated_session(" in text:
            assert rel in {"services/ssh/manager.py", "simulator/session.py"}, rel
        assert "_open_transport" not in text or rel == "services/ssh/manager.py", rel


def test_no_legacy_guard_or_raw_session_api():
    for rel, text in sources():
        for name in ("GuardedSession", "open_raw", "SessionMode", "allowed_write_commands",
                     "read_system_info", "render_bounce"):
            assert name not in text, f"{rel} still references {name}"


def test_no_ai_or_llm_component_has_ssh_access():
    for rel, text in sources():
        for sdk in ("openai", "anthropic", "langchain", "llama", "transformers"):
            assert not re.search(rf"^\s*(from|import)\s+{sdk}\b", text, re.M), \
                f"{rel} imports {sdk}"


def test_no_api_request_model_accepts_command_text():
    from app.main import create_app

    app = create_app()
    forbidden = {"command", "commands", "cmd", "cli", "exec", "shell", "script", "raw"}
    for route in app.routes:
        path = getattr(route, "path", "")
        body = getattr(getattr(route, "body_field", None), "type_", None)
        if body is None or path.startswith("/api/profiles"):
            continue  # profile editor: admin-only, templates validated against the allowlist
        fields = set(getattr(body, "model_fields", {}))
        assert not fields & forbidden, f"{path} accepts {fields & forbidden}"


def test_frontend_has_no_terminal_or_command_console():
    text = "\n".join(p.read_text(encoding="utf-8") for p in FRONTEND.rglob("*.ts*"))
    for needle in ("SSH Terminal", "Command Shell", "Execute Command", "CLI Console",
                   "/api/exec", "xterm"):
        assert needle not in text


def test_integrations_are_read_only_by_construction():
    netbox = (APP / "services/integrations/netbox.py").read_text(encoding="utf-8")
    assert re.findall(r'\.request\("(\w+)"', netbox) == ["GET"]
    assert not re.search(r"\.(post|put|patch|delete)\(", netbox)
    zabbix = (APP / "services/integrations/zabbix.py").read_text(encoding="utf-8")
    allow = re.search(r"ALLOWED_METHODS = frozenset\(\{([^}]*)\}\)", zabbix).group(1)
    methods = set(re.findall(r'"([\w.]+)"', allow))
    assert methods == {"apiinfo.version", "host.get", "problem.get"}
    assert all(m.endswith(".get") or m == "apiinfo.version" for m in methods)
    for rel, text in sources():
        if rel.startswith("services/integrations/"):
            continue
        assert "httpx" not in text or rel.startswith("api/routes/integrations"), rel


def test_simple_api_has_no_direct_switch_access():
    text = (APP / "api/routes/simple.py").read_text(encoding="utf-8")
    for forbidden in ("app.services.ssh", "app.security.firewall", "get_connector",
                      "AlcatelAdapter", "FirewallSession", "switch_id", "confirmations=body"):
        assert forbidden not in text, forbidden
    # The only way it reaches a switch is the normal, fully checked restart pipeline.
    assert "prepare_restart(" in text and "execute_restart(" in text


def test_every_api_route_is_authenticated_and_permission_checked():
    public = {("POST", "/api/auth/login"), ("GET", "/api/health"), ("GET", "/health")}
    from app.main import create_app

    for route in create_app().routes:
        methods = getattr(route, "methods", None) or set()
        path = getattr(route, "path", "")
        if not path.startswith("/api/") or path.startswith("/api/docs") or \
                path == "/api/openapi.json":
            continue
        for method in methods - {"HEAD", "OPTIONS"}:
            if (method, path) in public:
                continue
            deps = {getattr(d.call, "__qualname__", "") for d in route.dependant.dependencies}
            nested = {getattr(sub.call, "__qualname__", "")
                      for d in route.dependant.dependencies for sub in d.dependencies}
            assert deps & {"get_current_user", "require.<locals>._dep"} or \
                nested & {"get_current_user"}, f"{method} {path} is not authenticated"
