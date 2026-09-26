"""Helpers shared by all AOS output parsers.

AOS output must never be parsed by fixed column offsets: column widths differ between releases and
models, and long values shift everything. Parsers here work on tokens and regular expressions.
"""

from __future__ import annotations

import re

HEX = "0123456789abcdef"

# Accepts 00:11:22:33:44:55, 00-11-22-33-44-55, 0011.2233.4455, 001122334455 (any case).
_MAC_INPUT_PATTERNS = [
    re.compile(r"^[0-9a-f]{2}([:-])[0-9a-f]{2}(\1[0-9a-f]{2}){4}$"),
    re.compile(r"^[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}$"),
    re.compile(r"^[0-9a-f]{12}$"),
]

# A MAC address as printed by AOS (colon separated), possibly followed by * (invalid) or & (dup).
MAC_IN_OUTPUT = re.compile(r"(?<![0-9A-Fa-f:])([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})([*&]?)")

ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b[()][A-Za-z0-9]|\x1b[=>]")
# AOS 6 pager prompt (more mode) and generic pagers.
PAGER_PATTERNS = [
    re.compile(r"More\?\s*\[next screen <sp>, next line <cr>, filter pattern </>, quit </>\]"),
    re.compile(r"-+\s*More\s*-+(?:\s*\(\d+%\))?"),
    re.compile(r"More\?"),
    re.compile(r"Press any key to continue(?: \(Q to quit\))?", re.IGNORECASE),
]


class InvalidMacError(ValueError):
    pass


def normalize_mac(value: str) -> str:
    """Normalize user input to 12 lowercase hex digits. Raises InvalidMacError."""
    if value is None:
        raise InvalidMacError("MAC address is required.")
    candidate = value.strip().lower()
    if not any(p.match(candidate) for p in _MAC_INPUT_PATTERNS):
        raise InvalidMacError(
            "Invalid MAC address. Accepted formats: 00:11:22:33:44:55, 00-11-22-33-44-55, "
            "0011.2233.4455, 001122334455."
        )
    return re.sub(r"[^0-9a-f]", "", candidate)


def format_mac(normalized: str, sep: str = ":") -> str:
    """001122334455 -> 00:11:22:33:44:55 (the form AOS expects on the CLI)."""
    if len(normalized) != 12 or any(c not in HEX for c in normalized):
        raise InvalidMacError(f"Not a normalized MAC: {normalized!r}")
    return sep.join(normalized[i : i + 2] for i in range(0, 12, 2))


def mac_from_output(token: str) -> str:
    return token.replace(":", "").lower()


def is_multicast(normalized: str) -> bool:
    return bool(int(normalized[0:2], 16) & 0x01)


def _apply_backspaces(text: str) -> str:
    out: list[str] = []
    for ch in text:
        if ch == "\b":
            if out and out[-1] != "\n":
                out.pop()
        else:
            out.append(ch)
    return "".join(out)


def clean_output(text: str) -> str:
    """Strip ANSI escapes, pager prompts, backspace-erase sequences and carriage returns."""
    text = ANSI_ESCAPE.sub("", text)
    # Pagers erase their prompt with backspaces ("\b \b"); apply them like a terminal would.
    if "\b" in text:
        text = _apply_backspaces(text)
    for pattern in PAGER_PATTERNS:
        text = pattern.sub("", text)
    text = text.replace("\r\n", "\n")
    if "\r" in text:
        # A bare CR returns to column 0 (pagers use it to redraw the line): keep the last
        # non-blank segment of each line, as a terminal would display it.
        fixed = []
        for line in text.split("\n"):
            if "\r" in line:
                segments = [s for s in line.split("\r") if s.strip()]
                line = segments[-1] if segments else ""
            fixed.append(line)
        text = "\n".join(fixed)
    return text


def lines(text: str) -> list[str]:
    return [ln.rstrip() for ln in clean_output(text).split("\n")]


def is_separator(line: str) -> bool:
    stripped = line.strip()
    return bool(stripped) and set(stripped) <= set("-+=| ")


PORT_AOS8 = re.compile(r"^\d{1,2}/\d{1,2}/\d{1,3}[A-Z]?$")
PORT_AOS6 = re.compile(r"^\d{1,2}/\d{1,3}$")


def normalize_interface(raw: str) -> str:
    """AOS 6 sometimes pads the port number inside an interface: '8/ 1' -> '8/1'."""
    return re.sub(r"(\d+)/\s+(\d+)", r"\1/\2", raw.strip())


def null_if_empty(value: str | None) -> str | None:
    if value is None:
        return None
    v = value.strip().strip(",").strip()
    if v in {"", "(null)", "(none)", "N/A", "-", '""'}:
        return None
    return v
