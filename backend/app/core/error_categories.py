"""Safe error categories.

Every failure of a network operation is reported to users as one of these categories plus a
plain message; technical details (exception text, CLI output) stay in the server log and the
audit log. MAC operators never see even the category — only a generic sentence.
"""

from __future__ import annotations

import enum


class ErrorCategory(str, enum.Enum):
    DEVICE_UNREACHABLE = "DEVICE_UNREACHABLE"
    AUTHENTICATION_FAILED = "AUTHENTICATION_FAILED"
    HOST_KEY_UNTRUSTED = "HOST_KEY_UNTRUSTED"
    DISCOVERY_FAILED = "DISCOVERY_FAILED"
    PROFILE_NOT_FOUND = "PROFILE_NOT_FOUND"
    PROFILE_NOT_VERIFIED = "PROFILE_NOT_VERIFIED"
    OPERATION_BLOCKED = "OPERATION_BLOCKED"
    SAFETY_CHECK_FAILED = "SAFETY_CHECK_FAILED"
    VERIFICATION_FAILED = "VERIFICATION_FAILED"
    TIMEOUT = "TIMEOUT"
    NETWORK_ERROR = "NETWORK_ERROR"
    UNEXPECTED_OUTPUT = "UNEXPECTED_OUTPUT"
    COMMAND_REJECTED = "COMMAND_REJECTED"
    CONFIGURATION_ERROR = "CONFIGURATION_ERROR"
    INTERNAL_ERROR = "INTERNAL_ERROR"


# SwitchError.status / search result status → category
_BY_STATUS = {
    "timeout": ErrorCategory.TIMEOUT,
    "connection_failed": ErrorCategory.DEVICE_UNREACHABLE,
    "auth_failed": ErrorCategory.AUTHENTICATION_FAILED,
    "hostkey_error": ErrorCategory.HOST_KEY_UNTRUSTED,
    "command_failed": ErrorCategory.COMMAND_REJECTED,
    "unexpected_output": ErrorCategory.UNEXPECTED_OUTPUT,
    "unsupported": ErrorCategory.PROFILE_NOT_FOUND,
    "blocked": ErrorCategory.OPERATION_BLOCKED,
    "discovery_failed": ErrorCategory.DISCOVERY_FAILED,
    "session_closed": ErrorCategory.NETWORK_ERROR,
    "error": ErrorCategory.INTERNAL_ERROR,
}
# Firewall events that are about missing verification rather than a blocked operation.
_PROFILE_EVENTS = {"PROFILE_NOT_LAB_VERIFIED", "PROFILE_UNAVAILABLE", "STRATEGY_NOT_VERIFIED",
                   "PROFILE_REJECTED"}


def category_for_status(status: str | None, event: str | None = None) -> str:
    """Category for a switch-level status (``""`` for success statuses)."""
    if not status or status in {"found", "not_found", "online", "success", "discovered"}:
        return ""
    if status == "blocked" and event in _PROFILE_EVENTS:
        return (ErrorCategory.PROFILE_NOT_FOUND if event == "PROFILE_UNAVAILABLE"
                else ErrorCategory.PROFILE_NOT_VERIFIED).value
    if status == "blocked" and event == "DEVICE_NOT_DISCOVERED":
        return ErrorCategory.DISCOVERY_FAILED.value
    return _BY_STATUS.get(status, ErrorCategory.NETWORK_ERROR).value


# AppError codes → category (API error bodies carry it as "category").
_BY_CODE = {
    "NO_PROFILE": ErrorCategory.PROFILE_NOT_FOUND,
    "SWITCH_DISABLED": ErrorCategory.OPERATION_BLOCKED,
    "COMMAND_BLOCKED": ErrorCategory.OPERATION_BLOCKED,
    "CONFIRMATION_MISMATCH": ErrorCategory.SAFETY_CHECK_FAILED,
    "PORT_LOCKED": ErrorCategory.OPERATION_BLOCKED,
    "SWITCH_LOCKED": ErrorCategory.OPERATION_BLOCKED,
    "RATE_LIMITED": ErrorCategory.OPERATION_BLOCKED,
    "MISSING_CREDENTIAL": ErrorCategory.CONFIGURATION_ERROR,
    "CREDENTIAL_ERROR": ErrorCategory.CONFIGURATION_ERROR,
    "HOSTKEY_MISMATCH": ErrorCategory.HOST_KEY_UNTRUSTED,
    "DISCOVERY_REQUIRED": ErrorCategory.DISCOVERY_FAILED,
    "INTERNAL_ERROR": ErrorCategory.INTERNAL_ERROR,
}


def category_for_code(code: str | None) -> str:
    return _BY_CODE.get(code or "", ErrorCategory.OPERATION_BLOCKED if code else
                        ErrorCategory.INTERNAL_ERROR).value
