"""Risk classification of final command text.

Primary defence is the allowlist (a command must match an allowlisted template exactly).
The dangerous-pattern scan below is a second layer that catches anything destructive even if a
bug somewhere produced unexpected text.
"""

from __future__ import annotations

import re

from app.security.policy import (
    MAX_COMMAND_LENGTH,
    Risk,
    matches_read_allowlist,
    matches_state_allowlist,
)
from app.security.validators import INJECTION_CHARS

# Words/phrases that indicate configuration changes or destructive actions on AOS (and generic
# network OSes). Matched as whole words, case-insensitive.
DANGEROUS_WORDS = (
    "reload", "reboot", "restart", "shutdown", "halt", "write", "copy", "delete", "erase",
    "format", "rm", "mv", "rmdir", "mkdir", "configure", "configuration", "install", "upgrade",
    "takeover", "flush", "clear", "reset", "password", "passwd", "user", "aaa", "snmp",
    "spantree", "spanning-tree", "ip", "ipv6", "route", "static-route", "vlan", "linkagg",
    "lanpower", "interfaces", "admin", "admin-state", "no", "debug", "system", "session",
    "certify", "rls", "issu", "save", "commit", "boot", "image",
)
_DANGEROUS_RE = re.compile(r"(?i)(?<![\w-])(" + "|".join(re.escape(w) for w in DANGEROUS_WORDS)
                           + r")(?![\w-])")
# Destructive regardless of context (a "show" prefix does not make these harmless).
DESTRUCTIVE_WORDS = (
    "reload", "reboot", "restart", "shutdown", "halt", "write", "copy", "delete", "erase",
    "format", "rm", "mv", "install", "upgrade", "takeover", "flush", "clear", "reset", "commit",
    "save", "boot",
)
_DESTRUCTIVE_RE = re.compile(r"(?i)(?<![\w-])(" + "|".join(re.escape(w) for w in DESTRUCTIVE_WORDS)
                             + r")(?![\w-])")


def has_injection(text: str) -> bool:
    return any(c in INJECTION_CHARS or ord(c) < 32 or ord(c) == 127 for c in text)


def dangerous_hits(text: str) -> list[str]:
    return sorted({m.group(1).lower() for m in _DANGEROUS_RE.finditer(text)})


def classify_command(text: str) -> Risk:
    """Classify a final command string.

    READ_ONLY       exactly matches an allowlisted read template (with valid parameters)
    STATE_CHANGING  exactly matches an allowlisted port-bounce template
    DANGEROUS       contains injection characters or destructive/configuration keywords
    UNKNOWN         anything else (including harmless-looking but un-allowlisted commands)
    """
    if not isinstance(text, str) or not text or len(text) > MAX_COMMAND_LENGTH:
        return Risk.DANGEROUS if isinstance(text, str) and len(text) > MAX_COMMAND_LENGTH \
            else Risk.UNKNOWN
    if has_injection(text) or text != text.strip() or "  " in text:
        return Risk.DANGEROUS
    if matches_read_allowlist(text):
        return Risk.READ_ONLY
    if matches_state_allowlist(text):
        return Risk.STATE_CHANGING
    # "show …" text that is not allowlisted is UNKNOWN (e.g. "show configuration snapshot"):
    # read-only in spirit, but not an approved command. Still blocked.
    if text.lower().startswith("show "):
        return Risk.DANGEROUS if _DESTRUCTIVE_RE.search(text) else Risk.UNKNOWN
    if dangerous_hits(text):
        return Risk.DANGEROUS
    return Risk.UNKNOWN
