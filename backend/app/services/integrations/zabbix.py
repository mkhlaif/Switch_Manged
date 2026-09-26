"""Zabbix (monitoring) — read-only JSON-RPC client (§19).

Only the documented read methods on the allowlist can be called:

* ``apiinfo.version`` — API version (no authentication)
* ``host.get``        — host lookup by technical name
* ``problem.get``     — current problems of a host

Authentication: ``Authorization: Bearer <API token>`` (Zabbix 6.4 or later). A token of a user
with read-only permissions is recommended. The application never changes Zabbix configuration.
"""

from __future__ import annotations

import itertools
import re
from dataclasses import dataclass, field

import httpx

from app.core.config import get_settings
from app.core.logging import get_logger
from app.services.integrations.netbox import IntegrationError, IntegrationNotConfigured

log = get_logger("integrations.zabbix")

ALLOWED_METHODS = frozenset({"apiinfo.version", "host.get", "problem.get"})
_NAME_RE = re.compile(r"^[A-Za-z0-9._\- ]{1,128}$")
SEVERITIES = {"0": "Not classified", "1": "Information", "2": "Warning", "3": "Average",
              "4": "High", "5": "Disaster"}


@dataclass
class ZabbixClient:
    url: str
    token: str
    verify_tls: bool = True
    timeout: float = 10.0
    transport: httpx.AsyncBaseTransport | None = None
    _ids: itertools.count = field(default_factory=lambda: itertools.count(1), repr=False)

    def __repr__(self) -> str:
        return f"ZabbixClient(url={self.url!r})"

    async def _call(self, method: str, params: dict | list) -> object:
        if method not in ALLOWED_METHODS or not (method.endswith(".get")
                                                 or method == "apiinfo.version"):
            raise IntegrationError(f"Zabbix method {method!r} is not on the read-only "
                                   "allowlist.")
        headers = {"Content-Type": "application/json-rpc"}
        if method != "apiinfo.version":
            headers["Authorization"] = f"Bearer {self.token}"
        body = {"jsonrpc": "2.0", "method": method, "params": params, "id": next(self._ids)}
        endpoint = self.url.rstrip("/")
        if not endpoint.endswith("api_jsonrpc.php"):
            endpoint += "/api_jsonrpc.php"
        try:
            async with httpx.AsyncClient(verify=self.verify_tls, timeout=self.timeout,
                                         transport=self.transport) as client:
                response = await client.post(endpoint, json=body, headers=headers)
        except httpx.HTTPError as exc:
            raise IntegrationError(f"Zabbix unreachable ({exc.__class__.__name__}).") from exc
        if response.status_code != 200:
            raise IntegrationError(f"Zabbix returned HTTP {response.status_code}.")
        try:
            data = response.json()
        except ValueError as exc:
            raise IntegrationError("Zabbix returned a non-JSON response.") from exc
        if not isinstance(data, dict):
            raise IntegrationError("Unexpected Zabbix response format.")
        if "error" in data:
            err = data["error"] or {}
            raise IntegrationError(f"Zabbix API error: {str(err.get('data') or err.get('message'))[:200]}")
        return data.get("result")

    async def version(self) -> str:
        return str(await self._call("apiinfo.version", []))

    async def host(self, name: str) -> dict | None:
        if not _NAME_RE.match(name or ""):
            raise IntegrationError("Invalid host name.")
        result = await self._call("host.get", {
            "output": ["hostid", "host", "name", "status"],
            "filter": {"host": [name]},
            "selectInterfaces": ["ip", "type", "available"],
        })
        if not isinstance(result, list) or len(result) != 1:
            return None
        h = result[0]
        return {"hostid": h.get("hostid"), "host": h.get("host"), "name": h.get("name"),
                "monitored": str(h.get("status")) == "0",
                "interfaces": [{"ip": i.get("ip"), "available": i.get("available")}
                               for i in h.get("interfaces") or []]}

    async def problems(self, hostid: str, limit: int = 20) -> list[dict]:
        if not re.match(r"^\d{1,20}$", str(hostid)):
            raise IntegrationError("Invalid host id.")
        result = await self._call("problem.get", {
            "output": ["eventid", "name", "severity", "clock", "acknowledged"],
            "hostids": [str(hostid)], "sortfield": ["eventid"], "sortorder": "DESC",
            "limit": max(1, min(limit, 100)),
        })
        return [{"eventid": p.get("eventid"), "name": p.get("name"),
                 "severity": SEVERITIES.get(str(p.get("severity")), str(p.get("severity"))),
                 "clock": p.get("clock"), "acknowledged": str(p.get("acknowledged")) == "1"}
                for p in (result if isinstance(result, list) else [])]


def get_zabbix() -> ZabbixClient:
    s = get_settings()
    if not (s.zabbix_url and s.zabbix_token):
        raise IntegrationNotConfigured("Zabbix is not configured (ZABBIX_URL / ZABBIX_TOKEN).")
    return ZabbixClient(s.zabbix_url, s.zabbix_token, s.zabbix_verify_tls,
                        float(s.integration_timeout))
