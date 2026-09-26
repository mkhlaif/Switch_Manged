"""Validation of switch inventory fields, shared by the switch API and the bulk importer.

Every function returns the normalised value or raises ``ValueError`` with a message that is safe
to show to an administrator. Values that could act as spreadsheet formulas, carry control
characters or shell/CLI metacharacters are rejected, not silently cleaned.
"""

from __future__ import annotations

import ipaddress
import re

CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")
FORMULA_PREFIXES = ("=", "+", "-", "@")
NAME_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._\- ]{0,126}[A-Za-z0-9._\-])?$")
HOSTNAME_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
# Free text (site, location, description, port location labels): letters of any script, digits,
# spaces and ordinary punctuation. No ; | ` $ < > \ " { } that could be abused downstream.
FREE_TEXT_RE = re.compile(r"^[\w .,:/()#'&+\-]*$")
MODEL_RE = re.compile(r"^OS\d{3,5}[A-Z0-9\-]{0,20}$")
VERSION_RE = re.compile(r"^\d{1,2}(?:\.\d{1,4}){1,4}(?:\.?R\d{1,3})?$")
PORT_RE = re.compile(r"^\d{1,2}/\d{1,3}(?:/\d{1,3}[A-Z]?)?$")
SWITCH_ROLE_VALUES = ("access", "distribution", "core", "unknown")
MAX_PORT_LOCATIONS = 1024


def _plain(value: str, field: str) -> str:
    if CONTROL_CHARS.search(value):
        raise ValueError(f"{field} contains control characters (newline, tab, ...).")
    return value.strip()


def _no_formula(value: str, field: str) -> None:
    if value.startswith(FORMULA_PREFIXES):
        raise ValueError(f"{field} must not start with {value[0]!r} (spreadsheet formula "
                         "injection).")


def switch_name(value: str) -> str:
    value = _plain(value, "name")
    if not value:
        raise ValueError("name is required.")
    if not NAME_RE.match(value):
        raise ValueError("name may contain letters, digits, '.', '_', '-' and spaces (1-128 "
                         "characters, starting with a letter or digit).")
    return value


def hostname(value: str) -> str:
    value = _plain(value, "hostname").rstrip(".")
    if not value:
        return ""
    if len(value) > 253 or not all(HOSTNAME_LABEL.match(p) for p in value.split(".")):
        raise ValueError(f"hostname {value!r} is not a valid DNS host name.")
    return value.lower()


def management_ip(value: str) -> tuple[str, list[str]]:
    """Returns (normalised address, warnings)."""
    value = _plain(value, "management_ip")
    if not value:
        raise ValueError("management_ip is required.")
    try:
        ip = ipaddress.ip_address(value)
    except ValueError as exc:
        raise ValueError(f"management_ip {value!r} is not a valid IPv4/IPv6 address.") from exc
    if ip.is_unspecified or ip.is_multicast or (ip.version == 4 and str(ip) == "255.255.255.255"):
        raise ValueError(f"management_ip {ip} cannot be a switch address.")
    warnings = []
    if ip.is_loopback or ip.is_link_local:
        warnings.append(f"management_ip {ip} is a loopback/link-local address (lab only?).")
    return str(ip), warnings


def free_text(value: str, field: str, max_len: int) -> str:
    value = _plain(value, field)
    if len(value) > max_len:
        raise ValueError(f"{field} is longer than {max_len} characters.")
    _no_formula(value, field)
    if not FREE_TEXT_RE.match(value):
        raise ValueError(f"{field} contains characters that are not allowed "
                         "(allowed: letters, digits, spaces and . , : / ( ) # ' & + -).")
    return value


def model(value: str) -> str:
    value = _plain(value, "model").upper()
    if not value:
        raise ValueError("model is required.")
    if not MODEL_RE.match(value):
        raise ValueError(f"model {value!r} is not an OmniSwitch model name (e.g. OS6360, "
                         "OS6860E-P24).")
    return value


def aos_version(value: str) -> str:
    value = _plain(value, "aos_version").upper()
    if not value:
        raise ValueError("aos_version is required.")
    if not VERSION_RE.match(value):
        raise ValueError(f"aos_version {value!r} is not an AOS version (e.g. 8.10R1, 6.7.1).")
    return value


def switch_role(value: str) -> str:
    value = _plain(value, "role").lower() or "unknown"
    if value not in SWITCH_ROLE_VALUES:
        raise ValueError(f"role {value!r} must be one of {', '.join(SWITCH_ROLE_VALUES)}.")
    return value


def ssh_port(value: str | int) -> int:
    text = str(value).strip()
    if text == "":
        return 22
    if not text.isdigit():
        raise ValueError(f"ssh_port {text!r} is not a number.")
    port = int(text)
    if not 1 <= port <= 65535:
        raise ValueError(f"ssh_port {port} is outside 1-65535.")
    return port


_TRUE = {"true", "yes", "y", "1"}
_FALSE = {"false", "no", "n", "0"}


def boolean(value: str | bool, field: str, default: bool = True) -> bool:
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text == "":
        return default
    if text in _TRUE:
        return True
    if text in _FALSE:
        return False
    raise ValueError(f"{field} {value!r} must be true or false.")


def port(value: str) -> str:
    value = _plain(value, "port")
    if not PORT_RE.match(value):
        raise ValueError(f"port {value!r} is not an OmniSwitch port (1/26 or 1/1/26).")
    return value


def port_list(values: list[str]) -> list[str]:
    return sorted({port(v) for v in values if str(v).strip()})


def port_locations(values: dict) -> dict[str, str]:
    if not isinstance(values, dict):
        raise ValueError("port_locations must be an object of port → location.")
    if len(values) > MAX_PORT_LOCATIONS:
        raise ValueError(f"at most {MAX_PORT_LOCATIONS} port locations per switch.")
    out: dict[str, str] = {}
    for key, label in values.items():
        label = free_text(str(label), f"location of port {key}", 128)
        if label:
            out[port(str(key))] = label
    return dict(sorted(out.items()))
