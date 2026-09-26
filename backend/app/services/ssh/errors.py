"""SSH/CLI error hierarchy. Each error carries a short, user-presentable reason."""

from __future__ import annotations


class SwitchError(Exception):
    """Base class. ``status`` maps onto SwitchResultStatus / SwitchStatus values."""

    status = "error"
    title = "SWITCH ERROR"

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class ConnectionFailed(SwitchError):
    status = "connection_failed"
    title = "SSH CONNECTION FAILED"


class ConnectTimeout(ConnectionFailed):
    status = "timeout"


class AuthenticationFailed(SwitchError):
    status = "auth_failed"
    title = "SSH AUTHENTICATION FAILED"


class HostKeyError(SwitchError):
    status = "hostkey_error"
    title = "SSH HOST KEY NOT TRUSTED"


class CommandTimeout(SwitchError):
    status = "timeout"
    title = "COMMAND TIMEOUT"


class CommandFailed(SwitchError):
    """The switch rejected the command (``ERROR: ...``)."""

    status = "command_failed"
    title = "COMMAND FAILED"

    def __init__(self, reason: str, command: str = "", output: str = "") -> None:
        super().__init__(reason)
        self.command = command
        self.output = output


class CommandNotAllowed(SwitchError):
    """Raised by the guard before anything is sent: the command is outside the allowlist."""

    status = "error"
    title = "COMMAND BLOCKED"


class SessionClosed(SwitchError):
    status = "connection_failed"
    title = "SSH SESSION CLOSED"


class UnsupportedSwitch(SwitchError):
    status = "unsupported"
    title = "NO VERIFIED COMMAND PROFILE"
