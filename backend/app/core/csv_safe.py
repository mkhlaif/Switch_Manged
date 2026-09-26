"""CSV export helpers.

Exported cells can contain attacker-controlled text (for example the username of a failed login,
switch descriptions or LLDP names). Spreadsheet programs execute cells that start with a formula
character, so such cells are prefixed with an apostrophe, which spreadsheets display as text
(OWASP "CSV injection").
"""

from __future__ import annotations

from typing import Any

_FORMULA_START = ("=", "+", "-", "@", "\t", "\r", "\n")


def csv_cell(value: Any) -> Any:
    if isinstance(value, str) and value.startswith(_FORMULA_START):
        return "'" + value
    return value


def csv_row(values: list[Any]) -> list[Any]:
    return [csv_cell(v) for v in values]
