"""Strict parameter validators.

Values are never "cleaned up" and then used: anything outside the exact expected shape is
rejected. Characters that could chain, redirect or inject commands raise a HIGH severity
rejection; merely malformed values raise INFO.
"""

from __future__ import annotations

import re

from app.parsers.common import InvalidMacError, format_mac, normalize_mac
from app.security.policy import Severity

# Characters never valid in any parameter of this application.
INJECTION_CHARS = frozenset(";&|`$(){}<>\"'\\\n\r\t\x00")


class ParameterRejected(ValueError):
    def __init__(self, parameter: str, reason: str, severity: Severity = Severity.INFO,
                 value: object = None) -> None:
        super().__init__(f"Invalid parameter '{parameter}': {reason}")
        self.parameter = parameter
        self.reason = reason
        self.severity = severity
        self.value_preview = preview(value)


def preview(value: object, limit: int = 60) -> str:
    """Safe, printable representation of a rejected value for logs (never executed)."""
    text = repr(value)
    return text if len(text) <= limit else text[:limit] + "…"


def _reject_injection(parameter: str, value: object) -> str:
    if not isinstance(value, str):
        raise ParameterRejected(parameter, "must be a string", Severity.INFO, value)
    if len(value) > 64:
        raise ParameterRejected(parameter, "value too long", Severity.HIGH, value)
    bad = {c for c in value if c in INJECTION_CHARS or ord(c) < 32 or ord(c) == 127}
    if bad:
        raise ParameterRejected(
            parameter, "contains characters that could inject or chain commands",
            Severity.HIGH, value,
        )
    if re.search(r"(?i)\b(reload|reboot|write|copy|delete|erase|configure|shutdown)\b", value):
        raise ParameterRejected(parameter, "contains a command keyword", Severity.HIGH, value)
    return value


class MacAddressValidator:
    @staticmethod
    def validate(value: object) -> str:
        """Return the normalized 12-hex MAC."""
        text = _reject_injection("mac", value)
        try:
            return normalize_mac(text)
        except InvalidMacError as exc:
            raise ParameterRejected("mac", str(exc), Severity.INFO, value) from exc

    @staticmethod
    def to_aos(normalized: str) -> str:
        return format_mac(normalized)


_PORT_AOS6 = re.compile(r"^(\d{1,2})/(\d{1,3})$")
_PORT_AOS8 = re.compile(r"^(\d{1,2})/(\d{1,2})/(\d{1,3})([A-Z]?)$")


class PortValidator:
    """Single physical port in the profile family's format (no ranges)."""

    @staticmethod
    def validate(value: object, family: str) -> str:
        text = _reject_injection("port", value).strip()
        if family == "AOS6":
            m = _PORT_AOS6.match(text)
            if not m:
                raise ParameterRejected("port", "expected slot/port, e.g. 1/26", Severity.INFO,
                                        value)
            slot, port = int(m.group(1)), int(m.group(2))
            if not (1 <= slot <= 99 and 1 <= port <= 999):
                raise ParameterRejected("port", "slot/port out of range", Severity.INFO, value)
            return f"{slot}/{port}"
        if family in {"AOS8", "AOS7"}:
            m = _PORT_AOS8.match(text)
            if not m:
                raise ParameterRejected("port", "expected chassis/slot/port, e.g. 1/1/26",
                                        Severity.INFO, value)
            chassis, slot, port = int(m.group(1)), int(m.group(2)), int(m.group(3))
            if not (1 <= chassis <= 99 and 1 <= slot <= 99 and 1 <= port <= 999):
                raise ParameterRejected("port", "chassis/slot/port out of range", Severity.INFO,
                                        value)
            return f"{chassis}/{slot}/{port}{m.group(4)}"
        raise ParameterRejected("port", f"unknown profile family {family!r}", Severity.WARNING,
                                value)

    @staticmethod
    def validate_any(value: object) -> str:
        """For inputs not yet bound to a profile (e.g. uplink port lists)."""
        text = _reject_injection("port", value).strip()
        for family in ("AOS8", "AOS6"):
            try:
                return PortValidator.validate(text, family)
            except ParameterRejected:
                continue
        raise ParameterRejected("port", "expected 1/26 or 1/1/26", Severity.INFO, value)


class LinkAggValidator:
    @staticmethod
    def validate(value: object) -> str:
        if isinstance(value, bool):
            raise ParameterRejected("agg", "must be an integer", Severity.INFO, value)
        if isinstance(value, str):
            _reject_injection("agg", value)
            if not re.fullmatch(r"\d{1,3}", value):
                raise ParameterRejected("agg", "must be an integer", Severity.INFO, value)
            value = int(value)
        if not isinstance(value, int) or not 0 <= value <= 255:
            raise ParameterRejected("agg", "link aggregate id must be 0-255", Severity.INFO, value)
        return str(value)


class SwitchIdValidator:
    @staticmethod
    def validate(value: object) -> int:
        if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value < 2**31:
            raise ParameterRejected("switch_id", "must be a positive integer", Severity.INFO, value)
        return value


class VlanIdValidator:
    @staticmethod
    def validate(value: object) -> int:
        if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 4094:
            raise ParameterRejected("vlan", "VLAN id must be 1-4094", Severity.INFO, value)
        return value


_AOS_VERSION = re.compile(r"^\d{1,2}\.\d{1,2}\.\d{1,4}(?:\.\d{1,4})?\.R\d{1,2}$")


class AosVersionValidator:
    @staticmethod
    def validate(value: object) -> str:
        text = _reject_injection("aos_version", value).strip()
        if not _AOS_VERSION.match(text):
            raise ParameterRejected("aos_version", "expected e.g. 8.10.94.R03 or 6.7.2.191.R08",
                                    Severity.INFO, value)
        return text

    @staticmethod
    def is_valid(value: object) -> bool:
        try:
            AosVersionValidator.validate(value)
            return True
        except ParameterRejected:
            return False
