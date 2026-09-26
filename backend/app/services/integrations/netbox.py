"""NetBox (source of truth) — read-only client and reconciliation (§18).

Only HTTP GET on an allowlist of REST endpoints is possible. Documented NetBox REST API:

* ``GET /api/status/``                       — NetBox version / health
* ``GET /api/dcim/devices/?name=<name>``     — device (model, role, site, status, primary IP)
* ``GET /api/dcim/interfaces/?device=<name>&name=<ifname>`` — interface (mode, VLANs, enabled)

Authentication: ``Authorization: Token <token>`` (a read-only API token is recommended).
The application never creates, changes or deletes anything in NetBox; differences are reported
as mismatches (and alerts) for a human to resolve.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

import httpx

from app.core.config import get_settings
from app.core.logging import get_logger

log = get_logger("integrations.netbox")

ALLOWED_PATHS = ("/api/status/", "/api/dcim/devices/", "/api/dcim/interfaces/")
_NAME_RE = re.compile(r"^[A-Za-z0-9._/:\- ]{1,128}$")


class IntegrationError(Exception):
    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class IntegrationNotConfigured(IntegrationError):
    pass


@dataclass
class NetBoxClient:
    url: str
    token: str
    verify_tls: bool = True
    timeout: float = 10.0
    transport: httpx.AsyncBaseTransport | None = None  # injectable for tests

    def __repr__(self) -> str:  # never print the token
        return f"NetBoxClient(url={self.url!r})"

    async def _get(self, path: str, params: dict | None = None) -> dict:
        if path not in ALLOWED_PATHS:
            raise IntegrationError(f"NetBox path {path!r} is not on the read-only allowlist.")
        for value in (params or {}).values():
            if not _NAME_RE.match(str(value)):
                raise IntegrationError("Invalid NetBox query parameter.")
        headers = {"Authorization": f"Token {self.token}", "Accept": "application/json"}
        try:
            async with httpx.AsyncClient(base_url=self.url.rstrip("/"), headers=headers,
                                         verify=self.verify_tls, timeout=self.timeout,
                                         transport=self.transport) as client:
                response = await client.request("GET", path, params=params)
        except httpx.HTTPError as exc:
            raise IntegrationError(f"NetBox unreachable ({exc.__class__.__name__}).") from exc
        if response.status_code in (401, 403):
            raise IntegrationError("NetBox rejected the API token.")
        if response.status_code != 200:
            raise IntegrationError(f"NetBox returned HTTP {response.status_code}.")
        try:
            data = response.json()
        except ValueError as exc:
            raise IntegrationError("NetBox returned a non-JSON response.") from exc
        if not isinstance(data, dict):
            raise IntegrationError("Unexpected NetBox response format.")
        return data

    async def status(self) -> dict:
        data = await self._get("/api/status/")
        return {"netbox_version": str(data.get("netbox-version") or "")}

    async def device(self, name: str) -> dict | None:
        data = await self._get("/api/dcim/devices/", {"name": name})
        results = data.get("results") or []
        return _device(results[0]) if len(results) == 1 else None

    async def interface(self, device: str, name: str) -> dict | None:
        data = await self._get("/api/dcim/interfaces/", {"device": device, "name": name})
        results = data.get("results") or []
        return _interface(results[0]) if len(results) == 1 else None


def _name(obj) -> str:
    if isinstance(obj, dict):
        return str(obj.get("slug") or obj.get("name") or obj.get("model") or obj.get("value")
                   or "")
    return str(obj or "")


def _device(d: dict) -> dict:
    ip = (d.get("primary_ip4") or d.get("primary_ip") or {}) or {}
    return {
        "id": d.get("id"), "name": d.get("name"),
        "model": _name((d.get("device_type") or {}).get("model")
                       if isinstance(d.get("device_type"), dict) else d.get("device_type")),
        "role": _name(d.get("role") or d.get("device_role")),
        "site": _name(d.get("site")), "status": _name(d.get("status")),
        "primary_ip": str(ip.get("address") or "").split("/")[0] if isinstance(ip, dict) else "",
        "platform": _name(d.get("platform")),
    }


def _interface(i: dict) -> dict:
    untagged = i.get("untagged_vlan") or {}
    return {
        "id": i.get("id"), "name": i.get("name"), "enabled": i.get("enabled"),
        "description": i.get("description") or "",
        "mode": _name(i.get("mode")),
        "untagged_vlan": untagged.get("vid") if isinstance(untagged, dict) else None,
        "tagged_vlans": sorted(v.get("vid") for v in i.get("tagged_vlans") or []
                               if isinstance(v, dict) and v.get("vid") is not None),
    }


def get_netbox() -> NetBoxClient:
    s = get_settings()
    if not (s.netbox_url and s.netbox_token):
        raise IntegrationNotConfigured("NetBox is not configured (NETBOX_URL / NETBOX_TOKEN).")
    return NetBoxClient(s.netbox_url, s.netbox_token, s.netbox_verify_tls,
                        float(s.integration_timeout))


# ------------------------------------------------------------------------ reconciliation ---
_ROLE_MAP = {"access": "access", "access-switch": "access", "distribution": "distribution",
             "distribution-switch": "distribution", "core": "core", "core-switch": "core"}


def compare_device(switch, nb: dict | None) -> list[dict]:
    """Differences between the inventory switch and its NetBox device."""
    if nb is None:
        return [{"field": "device", "inventory": switch.name, "netbox": None,
                 "message": "Switch not found in NetBox (or the name is ambiguous)."}]
    out = []

    def diff(field: str, ours, theirs, message: str) -> None:
        if ours and theirs and str(ours).strip().lower() != str(theirs).strip().lower():
            out.append({"field": field, "inventory": ours, "netbox": theirs, "message": message})

    diff("management_ip", switch.host, nb.get("primary_ip"), "Management IP differs.")
    if switch.model and nb.get("model") and not str(nb["model"]).upper().startswith(
            switch.model.upper().split("-")[0]):
        out.append({"field": "model", "inventory": switch.model, "netbox": nb.get("model"),
                    "message": "Model differs."})
    nb_role = _ROLE_MAP.get(str(nb.get("role") or "").lower())
    if nb_role and switch.role and switch.role != "unknown" and nb_role != switch.role:
        out.append({"field": "role", "inventory": switch.role, "netbox": nb.get("role"),
                    "message": "Topology role differs."})
    return out


def compare_interface(live: dict, nb: dict | None) -> list[dict]:
    """Differences between the live port data (from the switch) and the NetBox interface."""
    if nb is None:
        return [{"field": "interface", "live": live.get("port"), "netbox": None,
                 "message": "Interface not found in NetBox."}]
    out = []
    live_untagged = live.get("untagged_vlan")
    live_tagged = sorted(live.get("tagged_vlans") or [])
    if nb.get("untagged_vlan") is not None and live_untagged is not None and \
            nb["untagged_vlan"] != live_untagged:
        out.append({"field": "untagged_vlan", "live": live_untagged,
                    "netbox": nb["untagged_vlan"], "message": "Untagged VLAN differs."})
    if nb.get("mode") in {"tagged", "access"} and nb.get("tagged_vlans") != live_tagged and \
            (nb.get("tagged_vlans") or live_tagged):
        out.append({"field": "tagged_vlans", "live": live_tagged,
                    "netbox": nb.get("tagged_vlans"), "message": "Tagged VLANs differ."})
    if nb.get("mode") == "access" and live_tagged:
        out.append({"field": "mode", "live": "tagged VLANs present", "netbox": "access",
                    "message": "NetBox documents an access port, the switch carries tagged "
                               "VLANs."})
    if nb.get("enabled") is False and live.get("admin_status") == "enabled":
        out.append({"field": "enabled", "live": "enabled", "netbox": "disabled",
                    "message": "NetBox documents the interface as disabled."})
    return out
