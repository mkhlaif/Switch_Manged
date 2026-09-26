"""Parser for ``show system`` — the read-only command used to detect model and AOS version.

AOS 8 [A8 p.61-56]::

    System:
      Description:  Alcatel-Lucent Enterprise OS6900-X40 8.3.1.313.R01 GA, August 31,
    2016.,
      Name:         (none),

AOS 6 [A6 p.2-31]::

    System:
      Description:  Alcatel-Lucent OS6250-24 6.6.2.63.R02 February 21, 2010.,
      Name:         OmniSwitch 6250,
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass

from app.parsers.common import lines, null_if_empty

_MODEL = re.compile(r"\b(OS\d{4,5}[A-Z]?(?:-[A-Z0-9]+)*)\b")
_VERSION = re.compile(r"\b(\d{1,2}\.\d{1,2}\.\d{1,4}(?:\.\d{1,4})?\.R\d{1,2})\b")
_FIELD = re.compile(r"^\s*([A-Za-z &]+?)\s*:\s*(.*)$")
_OID = re.compile(r"^\d+(?:\.\d+){3,40}$")
_ALE_DESCRIPTION = re.compile(r"^Alcatel-Lucent(?: Enterprise)? OS\d")
ALE_ENTERPRISE_OID = "1.3.6.1.4.1.6486"  # IANA private enterprise number of Alcatel-Lucent


@dataclass
class SystemInfo:
    description: str | None
    model: str | None
    version: str | None
    name: str | None
    location: str | None
    contact: str | None
    uptime: str | None
    object_id: str | None = None
    vendor: str | None = None

    @property
    def major(self) -> int | None:
        if not self.version:
            return None
        return int(self.version.split(".", 1)[0])

    def to_dict(self) -> dict:
        data = asdict(self)
        data["major"] = self.major
        return data


def parse_show_system(output: str) -> SystemInfo:
    fields: dict[str, str] = {}
    current: str | None = None
    for line in lines(output):
        m = _FIELD.match(line)
        if m and m.group(1).strip().lower() in {
            "description", "object id", "up time", "contact", "name", "location", "services",
            "date & time",
        }:
            current = m.group(1).strip().lower()
            fields[current] = m.group(2).strip()
        elif current == "description" and line.strip():
            fields[current] += " " + line.strip()  # wrapped description line
        else:
            current = None if not line.strip() else current

    description = null_if_empty(fields.get("description", "").rstrip(",").rstrip("."))
    model = version = None
    if description:
        mm = _MODEL.search(description)
        vm = _VERSION.search(description)
        model = mm.group(1) if mm else None
        version = vm.group(1) if vm else None
    object_id = null_if_empty(fields.get("object id", "").rstrip(","))
    object_id = object_id if object_id and _OID.match(object_id) else None
    return SystemInfo(
        description=description,
        model=model,
        version=version,
        name=null_if_empty(fields.get("name")),
        location=null_if_empty(fields.get("location")),
        contact=null_if_empty(fields.get("contact")),
        uptime=null_if_empty(fields.get("up time")),
        object_id=object_id,
        vendor=detect_vendor(description, object_id),
    )


def detect_vendor(description: str | None, object_id: str | None) -> str | None:
    """"ALE" only when BOTH documented signals agree: the description names Alcatel-Lucent
    (AOS 6: "Alcatel-Lucent OS…", AOS 8: "Alcatel-Lucent Enterprise OS…") and the system object
    id lies under ALE's enterprise number 6486. Anything else is not identified."""
    if not description or not object_id:
        return None
    if _ALE_DESCRIPTION.match(description) and object_id.startswith(ALE_ENTERPRISE_OID + "."):
        return "ALE"
    return None
