"""Logging setup.

Adds two custom levels on top of the standard ones:

* ``AUDIT`` (25): administrative actions (also persisted in the audit_logs table).
* ``SECURITY`` (35): authentication failures, host-key problems, blocked actions.

A redaction filter scrubs anything that looks like a secret before a record is emitted, so a
careless ``log.info("%s", payload)`` can never leak a password into the logs.
"""

from __future__ import annotations

import json
import logging
import re
import sys
from datetime import datetime, timezone

AUDIT = 25
SECURITY = 35
logging.addLevelName(AUDIT, "AUDIT")
logging.addLevelName(SECURITY, "SECURITY")

_SECRET_KEYS = r"(?:password|passwd|secret|token|credential_encryption_key|authorization|cookie)"
_KV_PATTERN = re.compile(
    rf"""(?ix)
    (['"]?{_SECRET_KEYS}['"]?\s*[:=]\s*)   # key and separator
    (?:'[^']*'|"[^"]*"|[^\s,;}}]+)          # value
    """
)
REDACTED = "***REDACTED***"


def redact(text: str) -> str:
    return _KV_PATTERN.sub(lambda m: m.group(1) + REDACTED, text)


class RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:  # pragma: no cover - malformed record; let logging report it
            return True
        cleaned = redact(message)
        if cleaned != message:
            record.msg = cleaned
            record.args = None
        return True


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload)


def configure_logging(level: str = "INFO", fmt: str = "text") -> None:
    root = logging.getLogger()
    root.setLevel(level)
    for handler in list(root.handlers):
        root.removeHandler(handler)
    # Never lose a log line (e.g. a security event) because the console cannot encode a
    # character: non-UTF-8 consoles (Windows cp1252) get an escaped representation instead.
    reconfigure = getattr(sys.stdout, "reconfigure", None)
    if reconfigure is not None:
        try:
            reconfigure(errors="backslashreplace")
        except (ValueError, OSError):
            pass
    handler = logging.StreamHandler(sys.stdout)
    handler.addFilter(RedactingFilter())
    if fmt == "json":
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)-8s %(name)s %(message)s"))
    root.addHandler(handler)
    # asyncssh logs every channel open/close at INFO; keep it quieter.
    logging.getLogger("asyncssh").setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(f"netops.{name}")


def log_security(logger: logging.Logger, msg: str, *args: object) -> None:
    logger.log(SECURITY, msg, *args)


def log_audit(logger: logging.Logger, msg: str, *args: object) -> None:
    logger.log(AUDIT, msg, *args)
