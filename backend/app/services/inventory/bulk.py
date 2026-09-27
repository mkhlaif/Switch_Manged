"""Bulk switch import (CSV / JSON) and export.

A row describes HOW to reach a switch (name, management IP, credential reference, optionally
the SSH host-key fingerprint obtained out of band). WHAT the switch is (vendor, model, AOS
version) is never taken from the file: it is discovered automatically after the import. A
``model`` / ``aos_version`` (or ``expected_model`` / ``expected_aos_version``) column is optional
EXPECTED METADATA that discovery compares with the device (a difference = MISMATCH, which
blocks state-changing operations).

Import workflow — nothing is written to the inventory before the administrator confirms:

1. ``validate_upload``: parse the file, validate every row, compare it with the inventory and
   store an :class:`ImportJob` with the preview (status ``validated``, expires after 30 min).
2. ``confirm_import``: the administrator chooses what happens to switches that already exist
   (``skip`` — default — or ``update``) and the mode:

   * ``atomic`` (default): the file must be fully valid; every row is applied in ONE
     transaction — any failure rolls the whole import back (nothing is imported);
   * ``per_row`` (explicit opt-in): invalid rows are skipped (must be acknowledged) and each row
     is applied in its own short transaction, so one failing row is reported as *failed*
     without affecting the others.

   Only one import runs at a time.
3. ``run_import`` (background task): every row is re-checked against the current inventory,
   cancellation and a global timeout are checked after every batch of ``BATCH_SIZE`` rows.
   Re-importing the same file changes nothing (idempotent): identical switches are *unchanged*.
4. Automatic discovery of the created / changed switches (a background discovery job), for
   switches whose SSH host key can be trusted without guessing (fingerprint in the file or a
   key already enrolled).

Credentials are never imported: a row references an existing credential by name only.
Export never contains passwords, keys or tokens (the public host-key fingerprint is exported so
that the file can be re-imported securely).
"""

from __future__ import annotations

import asyncio
import csv
import hashlib
import io
import json
import time
from dataclasses import dataclass
from datetime import timedelta

from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import inventory_fields as fields
from app.core.csv_safe import csv_cell
from app.core.errors import ConflictError, NotFoundError, ValidationFailedError
from app.core.logging import get_logger
from app.core.timeutil import utcnow
from app.db.session import session_factory
from app.models import (
    ACTIVE_IMPORT_STATUSES,
    Credential,
    ImportJob,
    ImportStatus,
    Switch,
    User,
)
from app.services.alcatel.profiles import model_family, version_matches_prefix
from app.services.alcatel.registry import load_profiles
from app.services.audit.service import record

log = get_logger("inventory.bulk")

MAX_FILE_BYTES = 5_000_000
MAX_ROWS = 5000
MAX_EXPORT_ROWS = 20000
BATCH_SIZE = 100
PREVIEW_TTL = timedelta(minutes=30)
JOB_TIMEOUT_SECONDS = 900
FINISHED_ROWS_KEPT = 50  # finished jobs whose row details are kept (older ones keep counts only)

REQUIRED = ("name", "management_ip")
OPTIONAL = ("hostname", "site", "location", "description", "role", "environment", "ssh_port",
            "enabled", "credential", "expected_model", "expected_aos_version",
            "ssh_host_key_fingerprint", "uplink_ports")
# Alternative column names (e.g. files written for older versions) -> canonical column.
ALIASES = {"model": "expected_model", "aos_version": "expected_aos_version",
           "credential_reference": "credential"}
JSON_ONLY = ("port_locations",)
# Present in exports (discovered facts / state); ignored on import.
EXPORT_ONLY = ("vendor", "discovered_model", "discovered_aos_version", "discovery_status",
               "status", "created_at", "updated_at")
SECRET_LIKE = ("password", "passwd", "pass", "secret", "token", "key", "private_key", "ssh_key",
               "community", "enable_password", "api_key", "credential_password")
EXPORT_FIELDS = ("name", "hostname", "management_ip", "ssh_port", "credential_reference",
                 "ssh_host_key_fingerprint", "expected_model", "expected_aos_version", "site",
                 "location", "description", "role", "environment", "enabled", "uplink_ports",
                 "vendor", "discovered_model", "discovered_aos_version", "discovery_status",
                 "status", "created_at", "updated_at")
# Fields compared with an existing switch (what an import can set).
COMPARED = ("hostname", "host", "ssh_port", "expected_model", "expected_aos_version",
            "expected_host_key_fingerprint", "environment", "site", "location", "description",
            "role", "enabled", "credential_id", "uplink_ports", "port_locations")
MODES = ("atomic", "per_row")


class FileRejected(Exception):
    """The whole file is unusable (format, size, header, secrets)."""


# ------------------------------------------------------------------------------ parsing ---
def _column(name: str) -> str:
    return name.strip().lower().replace(" ", "_").replace("-", "_")


def _canonical_columns(columns: list[str]) -> list[str]:
    """Map alias columns to their canonical name; a column and its alias together is ambiguous."""
    out = [ALIASES.get(c, c) for c in columns]
    for alias, canonical in ALIASES.items():
        if alias in columns and canonical in columns:
            raise FileRejected(f"Columns {alias!r} and {canonical!r} mean the same thing; use "
                               f"only {canonical!r}.")
    return out


def _check_header(columns: list[str]) -> None:
    if not columns or not any(columns):
        raise FileRejected("The file has no header row.")
    seen = set()
    for col in columns:
        if col in seen:
            raise FileRejected(f"Column {col!r} appears more than once.")
        seen.add(col)
    secret = [c for c in columns if c in SECRET_LIKE or c.endswith(("_password", "_secret",
                                                                      "_token"))]
    if secret:
        raise FileRejected(
            f"The file contains secret-like column(s) {', '.join(secret)}. Passwords, keys and "
            "tokens must never be put into import files: create the SSH credential under "
            "Settings → Credentials and reference it by name in a 'credential' column.")
    allowed = set(REQUIRED) | set(OPTIONAL) | set(EXPORT_ONLY) | set(JSON_ONLY)
    unknown = [c for c in columns if c not in allowed]
    if unknown:
        raise FileRejected(f"Unexpected column(s): {', '.join(unknown)}. Allowed: "
                           f"{', '.join(REQUIRED + OPTIONAL)}.")
    missing = [c for c in REQUIRED if c not in columns]
    if missing:
        raise FileRejected(f"Missing required column(s): {', '.join(missing)}.")


def parse_file(content: str, file_format: str) -> list[tuple[int, dict | None, str]]:
    """Return [(line, raw_row or None, error)] or raise FileRejected."""
    if len(content.encode("utf-8")) > MAX_FILE_BYTES:
        raise FileRejected(f"The file is larger than {MAX_FILE_BYTES // 1_000_000} MB.")
    if "\x00" in content:
        raise FileRejected("The file contains NUL bytes (not a text file).")
    content = content.lstrip("\ufeff")
    if file_format == "csv":
        return _parse_csv(content)
    if file_format == "json":
        return _parse_json(content)
    raise FileRejected("Unsupported format (use csv or json).")


def _parse_csv(content: str) -> list[tuple[int, dict | None, str]]:
    first = content.split("\n", 1)[0]
    delimiter = ";" if first.count(";") > first.count(",") else ","
    reader = csv.reader(io.StringIO(content, newline=""), delimiter=delimiter, strict=True)
    try:
        header = next(reader)
    except StopIteration:
        raise FileRejected("The file is empty.") from None
    except csv.Error as exc:
        raise FileRejected(f"The header row cannot be parsed: {exc}.") from exc
    columns = _canonical_columns([_column(c) for c in header])
    _check_header(columns)
    rows: list[tuple[int, dict | None, str]] = []
    while True:
        try:
            record_ = next(reader)
        except StopIteration:
            break
        except csv.Error as exc:
            rows.append((reader.line_num, None, f"Malformed CSV: {exc}."))
            break  # the parser cannot resynchronise reliably after a quoting error
        if not any(cell.strip() for cell in record_):
            continue
        if len(rows) >= MAX_ROWS:
            raise FileRejected(f"The file has more than {MAX_ROWS} rows; split it.")
        if len(record_) != len(columns):
            rows.append((reader.line_num, None, f"Malformed row: {len(record_)} fields, the "
                                                f"header has {len(columns)}."))
            continue
        rows.append((reader.line_num, dict(zip(columns, record_, strict=True)), ""))
    return rows


def _parse_json(content: str) -> list[tuple[int, dict | None, str]]:
    try:
        data = json.loads(content)
    except (ValueError, RecursionError) as exc:
        raise FileRejected(f"Invalid JSON: {str(exc)[:120]}.") from exc
    if isinstance(data, dict):
        data = data.get("switches")
    if not isinstance(data, list):
        raise FileRejected("JSON must be a list of switches or an object with a 'switches' "
                           "list.")
    if len(data) > MAX_ROWS:
        raise FileRejected(f"The file has more than {MAX_ROWS} switches; split it.")
    columns: set[str] = set()
    rows: list[tuple[int, dict | None, str]] = []
    for index, item in enumerate(data, start=1):
        if not isinstance(item, dict):
            rows.append((index, None, "Each switch must be a JSON object."))
            continue
        row: dict = {}
        problem = ""
        try:
            keys = _canonical_columns([_column(str(k)) for k in item])
        except FileRejected as exc:
            rows.append((index, None, str(exc)))
            continue
        for col, value in zip(keys, item.values(), strict=True):
            if col == "uplink_ports" and isinstance(value, list) and all(
                    isinstance(v, str) for v in value):
                row[col] = ";".join(value)
            elif col == "port_locations" and isinstance(value, dict):
                row[col] = value
            elif isinstance(value, (str, int, float, bool)) or value is None:
                row[col] = "" if value is None else (
                    ("true" if value else "false") if isinstance(value, bool) else str(value))
            else:
                problem = f"Field {col!r} has an unsupported value type."
        columns.update(row)
        rows.append((index, None if problem else row, problem))
    if columns:
        _check_header(sorted(columns))
    return rows


# ---------------------------------------------------------------------------- validation ---
@dataclass
class Inventory:
    by_name: dict[str, Switch]
    by_address: dict[tuple[str, int], Switch]
    by_hostname: dict[str, Switch]
    credentials: dict[str, int]
    credential_names: dict[int, str]
    profiles: dict


async def load_inventory(db: AsyncSession) -> Inventory:
    switches = (await db.execute(select(Switch))).scalars().all()
    creds = (await db.execute(select(Credential))).scalars().all()
    return Inventory(
        by_name={s.name.lower(): s for s in switches},
        by_address={(s.host.lower(), s.ssh_port): s for s in switches},
        by_hostname={s.hostname.lower(): s for s in switches if s.hostname},
        credentials={c.name: c.id for c in creds},
        credential_names={c.id: c.name for c in creds},
        profiles=await load_profiles(db),
    )


def _preview(value, limit: int = 80) -> str:
    text = str(value)
    text = fields.CONTROL_CHARS.sub("?", text)
    return text[:limit]


def validate_row(raw: dict, inv: Inventory) -> tuple[dict, list[str], list[str]]:
    """Normalise one row. Returns (data, errors, warnings); data is only usable without errors."""
    errors: list[str] = []
    warnings: list[str] = []
    data: dict = {}

    def take(key: str, fn, *args):
        try:
            data[key] = fn(*args)
        except ValueError as exc:
            errors.append(str(exc))

    get = lambda k: raw.get(k) if raw.get(k) is not None else ""  # noqa: E731
    take("name", fields.switch_name, get("name"))
    take("hostname", fields.hostname, get("hostname"))
    try:
        data["host"], ip_warnings = fields.management_ip(get("management_ip"))
        warnings.extend(ip_warnings)
    except ValueError as exc:
        errors.append(str(exc))
    take("expected_model", fields.expected_model, get("expected_model"))
    take("expected_aos_version", fields.expected_aos_version, get("expected_aos_version"))
    take("expected_host_key_fingerprint", fields.host_key_fingerprint,
         get("ssh_host_key_fingerprint"))
    take("environment", fields.environment, get("environment"))
    take("site", fields.free_text, get("site"), "site", 128)
    take("location", fields.free_text, get("location"), "location", 128)
    take("description", fields.free_text, get("description"), "description", 255)
    take("role", fields.switch_role, get("role"))
    take("ssh_port", fields.ssh_port, get("ssh_port"))
    take("enabled", fields.boolean, get("enabled"), "enabled", True)
    uplinks = str(get("uplink_ports")).replace(",", ";").replace(" ", ";")
    take("uplink_ports", fields.port_list, [p for p in uplinks.split(";") if p.strip()])
    if isinstance(raw.get("port_locations"), dict):
        take("port_locations", fields.port_locations, raw["port_locations"])
    elif raw.get("port_locations"):
        errors.append("port_locations must be an object (JSON import only).")

    credential = fields.CONTROL_CHARS.sub("", str(get("credential"))).strip()
    if credential:
        if credential not in inv.credentials:
            errors.append(f"credential {credential[:64]!r} does not exist (create it under "
                          "Settings → Credentials first).")
        else:
            data["credential_id"] = inv.credentials[credential]
    else:
        data["credential_id"] = None
        warnings.append("No credential referenced: the switch cannot be queried until an "
                        "SSH credential is assigned.")

    if not errors:
        coverage = _coverage_warning(data["expected_model"], data["expected_aos_version"],
                                     inv.profiles)
        if coverage:
            warnings.append(coverage)
        if not data["expected_host_key_fingerprint"]:
            warnings.append("No ssh_host_key_fingerprint: automatic discovery starts after an "
                            "administrator has verified and trusted the SSH host key on the "
                            "switch page.")
        if data["role"] == "unknown":
            warnings.append("Role is 'unknown': MAC_OPERATOR restarts are only possible on "
                            "switches with role 'access'.")
    return data, errors, warnings


def _coverage_warning(model: str, version: str, profiles: dict) -> str | None:
    """Expected metadata is not trusted, but tell the administrator early when no command
    profile would cover it (the switch would be discovered but not operable)."""
    if not model and not version:
        return None
    family = model_family(model) if model else None
    for profile in profiles.values():
        if not profile.enabled:
            continue
        if model and family not in profile.supported_models:
            continue
        if version and not any(version_matches_prefix(version, v) or version.startswith(v)
                               for v in profile.version_prefixes):
            continue
        return None
    return (f"No command profile covers the expected {model or ''} {version or ''}".rstrip()
            + ": after discovery the switch will be identified but no operation will be "
              "available.")


def _current(sw: Switch, key: str):
    if key == "expected_host_key_fingerprint":
        # An enrolled key counts: exporting it and importing it again changes nothing.
        return sw.expected_host_key_fingerprint or sw.host_key_fingerprint
    return getattr(sw, key)


def _existing_diff(sw: Switch, data: dict) -> list[str]:
    diff = []
    for key in COMPARED:
        if key not in data:
            continue
        if key == "expected_host_key_fingerprint" and not data[key]:
            continue  # not given: an import never removes a fingerprint
        current = _current(sw, key)
        new = data[key]
        if key == "host":
            current, new = (current or "").lower(), (new or "").lower()
        if key in ("uplink_ports",):
            current, new = sorted(current or []), sorted(new or [])
        if key == "port_locations":
            current, new = dict(current or {}), dict(new or {})
        if current != new:
            diff.append(key)
    return diff


def evaluate_rows(parsed: list[tuple[int, dict | None, str]], inv: Inventory) -> list[dict]:
    """Validate all rows and classify them against the file itself and the inventory."""
    out: list[dict] = []
    first_by_name: dict[str, int] = {}
    first_by_address: dict[tuple[str, int], int] = {}
    first_by_hostname: dict[str, int] = {}
    seen_rows: dict[str, int] = {}
    for line, raw, problem in parsed:
        entry = {"line": line, "name": "", "management_ip": "", "status": "invalid",
                 "action": "", "errors": [], "warnings": [], "diff": [], "data": {},
                 "result": "", "message": ""}
        if raw is None:
            entry["errors"] = [problem]
            out.append(entry)
            continue
        entry["name"] = _preview(raw.get("name") or "")
        entry["management_ip"] = _preview(raw.get("management_ip") or "", 64)
        data, errors, warnings = validate_row(raw, inv)
        if not errors:
            fingerprint = json.dumps(data, sort_keys=True)
            name_key = data["name"].lower()
            address = (data["host"].lower(), data["ssh_port"])
            if fingerprint in seen_rows:
                entry.update(status="duplicate", action="skip",
                             warnings=[f"Identical to line {seen_rows[fingerprint]}; skipped."])
                out.append(entry)
                continue
            seen_rows[fingerprint] = line
            if name_key in first_by_name:
                errors.append(f"Duplicate name: already used on line {first_by_name[name_key]}.")
            if address in first_by_address:
                errors.append(f"Duplicate management address {data['host']}:{data['ssh_port']}: "
                              f"already used on line {first_by_address[address]}.")
            if data["hostname"] and data["hostname"] in first_by_hostname:
                errors.append(f"Duplicate hostname: already used on line "
                              f"{first_by_hostname[data['hostname']]}.")
            first_by_name.setdefault(name_key, line)
            first_by_address.setdefault(address, line)
            if data["hostname"]:
                first_by_hostname.setdefault(data["hostname"], line)
        if not errors:
            existing = inv.by_name.get(data["name"].lower())
            other = inv.by_address.get((data["host"].lower(), data["ssh_port"]))
            if other is not None and (existing is None or other.id != existing.id):
                errors.append(f"Management address {data['host']}:{data['ssh_port']} already "
                              f"belongs to switch {other.name!r}.")
            owner = inv.by_hostname.get(data["hostname"]) if data["hostname"] else None
            if owner is not None and (existing is None or owner.id != existing.id):
                errors.append(f"Hostname {data['hostname']!r} already belongs to switch "
                              f"{owner.name!r}.")
            if existing is not None and existing.host_key_fingerprint and \
                    data["expected_host_key_fingerprint"] and \
                    data["expected_host_key_fingerprint"] != existing.host_key_fingerprint:
                errors.append(f"ssh_host_key_fingerprint differs from the host key already "
                              f"trusted for switch {existing.name!r}. Nothing is trusted "
                              "automatically: clear the trusted key on the switch page first "
                              "if the switch was really replaced.")
            if not errors:
                if existing is None:
                    entry["action"] = "create"
                else:
                    diff = _existing_diff(existing, data)
                    entry["diff"] = diff
                    entry["action"] = "update" if diff else "unchanged"
                    if diff:
                        warnings.append(f"Switch {existing.name!r} already exists with different "
                                        f"values ({', '.join(diff)}); it is only changed if you "
                                        "choose 'update existing switches'.")
        entry["errors"] = errors
        entry["warnings"] = warnings
        if not errors:
            entry["status"] = "valid"
            entry["data"] = data
        out.append(entry)
    return out


def summarize(rows: list[dict]) -> dict:
    return {
        "total": len(rows),
        "valid": sum(r["status"] == "valid" for r in rows),
        "invalid": sum(r["status"] == "invalid" for r in rows),
        "duplicates": sum(r["status"] == "duplicate" for r in rows),
        "warnings": sum(bool(r["warnings"]) for r in rows),
        "new": sum(r["action"] == "create" for r in rows),
        "existing_changed": sum(r["action"] == "update" for r in rows),
        "existing_unchanged": sum(r["action"] == "unchanged" for r in rows),
    }


# --------------------------------------------------------------------------- job control ---
async def expire_previews(db: AsyncSession) -> None:
    """Expire unconfirmed previews and drop row details of old finished jobs (bounded storage)."""
    now = utcnow()
    await db.execute(update(ImportJob).where(
        ImportJob.status == ImportStatus.VALIDATED.value, ImportJob.expires_at < now,
    ).values(status=ImportStatus.EXPIRED.value, rows=[]))
    finished = (await db.execute(select(ImportJob.id).where(
        ImportJob.status.not_in([ImportStatus.VALIDATED.value, *ACTIVE_IMPORT_STATUSES])
    ).order_by(ImportJob.created_at.desc()).offset(FINISHED_ROWS_KEPT))).scalars().all()
    if finished:
        await db.execute(update(ImportJob).where(ImportJob.id.in_(finished)).values(rows=[]))
    await db.commit()


async def validate_upload(db: AsyncSession, user: User, *, content: str, file_format: str,
                          filename: str, ip: str) -> ImportJob:
    await expire_previews(db)
    job = ImportJob(created_by_id=user.id, created_by=user.username, file_format=file_format,
                    filename=_preview(filename, 255), expires_at=utcnow() + PREVIEW_TTL,
                    file_sha256=hashlib.sha256(content.encode("utf-8")).hexdigest())
    try:
        parsed = parse_file(content, file_format)
        rows = evaluate_rows(parsed, await load_inventory(db))
    except FileRejected as exc:
        job.status = ImportStatus.FAILED.value
        job.file_errors = [str(exc)]
        job.failed_at = utcnow()
        job.error = str(exc)
        rows = []
    job.rows = rows
    counts = summarize(rows)
    for key in ("total", "valid", "invalid", "duplicates", "warnings"):
        setattr(job, key, counts[key])
    db.add(job)
    await db.commit()
    await record(db, action="SWITCH_IMPORT_VALIDATE",
                 result="SUCCESS" if not job.file_errors else "FAILED", user=user, ip=ip,
                 target_type="import_job", target_id=job.id, target_label=job.filename,
                 message=job.error or f"Import preview: {counts['valid']} valid, "
                                      f"{counts['invalid']} invalid, {counts['duplicates']} "
                                      "duplicate",
                 details={**counts, "format": file_format, "sha256": job.file_sha256})
    return job


async def get_job(db: AsyncSession, job_id: str) -> ImportJob:
    job = await db.get(ImportJob, job_id)
    if job is None:
        raise NotFoundError("Import job not found.")
    return job


async def confirm_import(db: AsyncSession, user: User, job_id: str, *, on_existing: str,
                         skip_invalid: bool, ip: str, mode: str = "atomic") -> ImportJob:
    job = await get_job(db, job_id)
    if job.created_by_id != user.id:
        raise ConflictError("An import can only be confirmed by the administrator who "
                            "uploaded it.")
    if job.status != ImportStatus.VALIDATED.value:
        raise ConflictError(f"This import is {job.status} and cannot be started. Upload the "
                            "file again.")
    if job.expires_at and utcnow() > job.expires_at:
        job.status, job.rows = ImportStatus.EXPIRED.value, []
        await db.commit()
        raise ConflictError("The preview expired. Upload the file again.")
    if job.valid == 0:
        raise ValidationFailedError("The file contains no valid rows; nothing can be imported.")
    if mode not in MODES:
        raise ValidationFailedError("mode must be 'atomic' or 'per_row'.")
    if mode == "atomic" and job.invalid:
        raise ValidationFailedError(
            f"{job.invalid} row(s) are invalid. An atomic import imports every row or none: "
            "fix the file and upload it again, or choose the per-row mode to skip invalid "
            "rows.", code="INVALID_ROWS_ATOMIC")
    if (job.invalid or job.duplicates) and not skip_invalid:
        raise ValidationFailedError(
            f"{job.invalid} invalid and {job.duplicates} duplicate row(s) would be skipped. "
            "Confirm that they may be skipped, or fix the file and upload it again.",
            code="INVALID_ROWS_NOT_ACKNOWLEDGED")
    active = (await db.execute(select(func.count()).select_from(ImportJob).where(
        ImportJob.status.in_(ACTIVE_IMPORT_STATUSES)))).scalar_one()
    if active:
        raise ConflictError("Another switch import is running. Wait until it has finished.",
                            code="IMPORT_RUNNING")
    job.on_existing = on_existing
    job.skip_invalid = skip_invalid
    job.mode = mode
    job.status = ImportStatus.QUEUED.value
    job.confirmed_at = utcnow()
    await db.commit()
    await record(db, action="SWITCH_IMPORT_START", result="INFO", user=user, ip=ip,
                 target_type="import_job", target_id=job.id, target_label=job.filename,
                 message=f"Switch import confirmed ({job.valid} valid rows, existing switches: "
                         f"{on_existing}, mode: {mode})",
                 details={"on_existing": on_existing, "skip_invalid": skip_invalid,
                          "mode": mode})
    return job


async def cancel_import(db: AsyncSession, user: User, job_id: str, ip: str) -> ImportJob:
    job = await get_job(db, job_id)
    if job.status in (ImportStatus.VALIDATED.value, ImportStatus.QUEUED.value):
        job.status = ImportStatus.CANCELLED.value
        job.completed_at = utcnow()
    elif job.status == ImportStatus.RUNNING.value and job.mode == "atomic":
        # The running transaction may hold the database write lock (SQLite): signal in memory;
        # the import stops after the current batch and rolls back completely.
        _ATOMIC_CANCEL.add(job.id)
    elif job.status == ImportStatus.RUNNING.value:
        job.cancel_requested = True  # stops after the current batch (already-imported rows stay)
    else:
        raise ConflictError(f"This import is {job.status}; nothing to cancel.")
    if job.id not in _ATOMIC_CANCEL:
        await db.commit()
    await record(db, action="SWITCH_IMPORT_CANCEL", result="INFO", user=user, ip=ip,
                 target_type="import_job", target_id=job.id, target_label=job.filename,
                 message=f"Import cancel requested (status {job.status})")
    return job


_ATOMIC_CANCEL: set[str] = set()


def _apply(sw: Switch, data: dict) -> bool:
    """Apply import data to a switch. Returns True if the SSH endpoint changed."""
    endpoint_changed = (sw.host or "").lower() != data["host"].lower() or \
        sw.ssh_port != data["ssh_port"]
    for key in COMPARED:
        if key == "expected_host_key_fingerprint" and not data.get(key):
            continue
        if key in data:
            setattr(sw, key, data[key])
    if endpoint_changed:
        sw.host_key, sw.host_key_fingerprint = "", ""  # new endpoint: re-enrol the host key
        # Possibly another device: its identity must be discovered again.
        sw.discovery_status = "not_discovered"
        sw.discovery_error = "Management address changed by an import: rediscovery required."
    return endpoint_changed


async def _process_row(db: AsyncSession, row: dict, on_existing: str) -> None:
    """Re-check one valid row against the current inventory and apply it (inside a savepoint)."""
    data = row["data"]
    existing = (await db.execute(select(Switch).where(
        func.lower(Switch.name) == data["name"].lower()))).scalar_one_or_none()
    conflict = (await db.execute(select(Switch).where(
        func.lower(Switch.host) == data["host"].lower(), Switch.ssh_port == data["ssh_port"],
    ))).scalar_one_or_none()
    if conflict is not None and (existing is None or conflict.id != existing.id):
        row["result"], row["message"] = "failed", (
            f"Management address now belongs to switch {conflict.name!r}.")
        return
    if data.get("credential_id") and await db.get(Credential, data["credential_id"]) is None:
        row["result"], row["message"] = "failed", "The referenced credential was deleted."
        return
    if existing is None:
        sw = Switch(**dict(data.items()), transport="ssh")
        db.add(sw)
        await db.flush()
        row["result"], row["message"], row["switch_id"] = "imported", "Created.", sw.id
        return
    diff = _existing_diff(existing, data)
    if not diff:
        row["result"], row["message"] = "unchanged", "Already up to date."
    elif on_existing == "update":
        endpoint = _apply(existing, data)
        await db.flush()
        row["result"], row["switch_id"] = "updated", existing.id
        row["message"] = f"Updated: {', '.join(diff)}" + (
            " (host key cleared: new SSH endpoint)" if endpoint else "")
    else:
        row["result"], row["message"] = "skipped", (
            f"Exists with different values ({', '.join(diff)}); not changed.")


class _AtomicAbort(Exception):
    """Stops an atomic import; everything done so far is rolled back."""


async def _run_per_row(db: AsyncSession, job_id: str, todo: list[dict], on_existing: str,
                       counts: dict, processed: int, started: float) -> tuple[ImportStatus, str,
                                                                                int]:
    """Each row in its own short transaction (explicit opt-in)."""
    outcome, error = ImportStatus.COMPLETED, ""
    for start in range(0, len(todo), BATCH_SIZE):
        if time.monotonic() - started > JOB_TIMEOUT_SECONDS:
            return ImportStatus.FAILED, (
                f"Import stopped after {JOB_TIMEOUT_SECONDS}s (timeout); the rows processed so "
                "far were imported. Run the import again to continue (already imported "
                "switches are reported as unchanged)."), processed
        cancel = (await db.execute(select(ImportJob.cancel_requested).where(
            ImportJob.id == job_id))).scalar_one()
        if cancel:
            return ImportStatus.CANCELLED, (
                "Cancelled by an administrator; the rows processed before the cancellation "
                "were imported."), processed
        for row in todo[start:start + BATCH_SIZE]:
            try:
                await _process_row(db, row, on_existing)
                await db.commit()  # one short transaction per row
            except IntegrityError as exc:
                await db.rollback()
                row["result"] = "failed"
                row["message"] = ("Rejected by a database constraint (the name, address or "
                                  "hostname was taken concurrently).")
                log.warning("Import %s line %s rejected: %s", job_id, row["line"],
                            exc.__class__.__name__)
            counts[row["result"] if row["result"] in counts else "failed"] += 1
            processed += 1
        await db.execute(update(ImportJob).where(ImportJob.id == job_id).values(
            processed=processed, **counts))
        await db.commit()
        await asyncio.sleep(0)
    return outcome, error, processed


async def _run_atomic(db: AsyncSession, job_id: str, todo: list[dict], on_existing: str,
                      counts: dict, processed: int, started: float) -> tuple[ImportStatus, str,
                                                                               int]:
    """Every row in ONE transaction: all rows are imported, or none (any failure, the timeout
    or a cancellation rolls everything back). Progress is not written while the transaction is
    open (it would wait for its own write lock on SQLite)."""
    done = dict.fromkeys(counts, 0)
    try:
        for start in range(0, len(todo), BATCH_SIZE):
            if time.monotonic() - started > JOB_TIMEOUT_SECONDS:
                raise _AtomicAbort(f"Import stopped after {JOB_TIMEOUT_SECONDS}s (timeout).")
            if job_id in _ATOMIC_CANCEL:
                raise _AtomicAbort("Cancelled by an administrator.")
            for row in todo[start:start + BATCH_SIZE]:
                await _process_row(db, row, on_existing)
                if row["result"] == "failed":
                    raise _AtomicAbort(f"Line {row['line']}: {row['message']}")
                done[row["result"]] += 1
            await asyncio.sleep(0)
        await db.commit()
    except (_AtomicAbort, IntegrityError) as exc:
        await db.rollback()
        reason = str(exc) if isinstance(exc, _AtomicAbort) else (
            "a row was rejected by a database constraint (name, address or hostname taken "
            "concurrently)")
        for row in todo:
            if row.get("result") in ("imported", "updated"):
                row["message"] = "Rolled back (atomic import)."
            row["result"] = "rolled_back" if row.get("result") else "not_processed"
        counts["failed"] = len(todo)
        status = ImportStatus.CANCELLED if job_id in _ATOMIC_CANCEL else ImportStatus.FAILED
        return status, (f"Atomic import rolled back: {reason} Nothing was imported; the "
                        "inventory is unchanged."), processed
    finally:
        _ATOMIC_CANCEL.discard(job_id)
    for key, value in done.items():
        counts[key] += value
    return ImportStatus.COMPLETED, "", processed + len(todo)


async def run_import(job_id: str) -> None:
    started = time.monotonic()
    async with session_factory()() as db:
        job = await db.get(ImportJob, job_id)
        if job is None or job.status != ImportStatus.QUEUED.value:
            return
        job.status = ImportStatus.RUNNING.value
        job.started_at = utcnow()
        await db.commit()
        on_existing, created_by, filename = job.on_existing, job.created_by, job.filename
        mode, creator_id = job.mode or "atomic", job.created_by_id
        rows = [dict(r) for r in job.rows or []]
        for r in rows:
            if r["status"] != "valid":
                r["result"] = "skipped"
                r["message"] = "; ".join(r["errors"] or r["warnings"]) or "Skipped."
        todo = [r for r in rows if r["status"] == "valid"]
        counts = {"imported": 0, "updated": 0, "unchanged": 0, "failed": 0,
                  "skipped": len(rows) - len(todo)}
        processed = len(rows) - len(todo)
        runner = _run_atomic if mode == "atomic" else _run_per_row
        try:
            outcome, error, processed = await runner(db, job_id, todo, on_existing, counts,
                                                     processed, started)
        except Exception as exc:  # noqa: BLE001 - the job must end in a final state
            log.exception("Import %s crashed", job_id)
            await db.rollback()
            outcome, error = ImportStatus.FAILED, (
                f"Internal error ({exc.__class__.__name__}); "
                + ("nothing was imported (atomic import rolled back)." if mode == "atomic" else
                   "rows committed before the error remain imported. Run the import again to "
                   "continue."))
            if mode == "atomic":
                for r in todo:
                    r["result"] = "rolled_back" if r.get("result") else "not_processed"
        for r in rows:
            if not r.get("result"):
                r["result"], r["message"] = "not_processed", "Not processed."
        changed_ids = [r["switch_id"] for r in rows if r.get("result") in ("imported", "updated")
                       and r.get("switch_id")]
        # Started BEFORE the import is marked final, so a client that sees "completed" also
        # sees the discovery job.
        discovery_job_id = await _discover_imported(db, creator_id, changed_ids)
        now = utcnow()
        await db.execute(update(ImportJob).where(ImportJob.id == job_id).values(
            discovery_job_id=discovery_job_id,
            rows=rows, processed=processed, status=outcome.value, error=error,
            failed_at=now if outcome is ImportStatus.FAILED else None,
            completed_at=None if outcome is ImportStatus.FAILED else now, **counts))
        await db.commit()
        names = [r["name"] for r in rows if r.get("result") in ("imported", "updated")]
        await record(db, action="SWITCH_IMPORT", result="SUCCESS" if outcome is
                     ImportStatus.COMPLETED and not counts["failed"] else "FAILED",
                     username=created_by, role="admin", target_type="import_job",
                     target_id=job_id, target_label=filename,
                     message=f"Switch import ({mode}) {outcome.value}: {counts['imported']} "
                             f"imported, {counts['updated']} updated, {counts['unchanged']} "
                             f"unchanged, {counts['skipped']} skipped, {counts['failed']} failed"
                             + (f" — {error}" if error else ""),
                     details={**counts, "mode": mode, "changed_switches": names[:2000]})


async def _discover_imported(db: AsyncSession, creator_id: int | None,
                             switch_ids: list[int]) -> str:
    """Automatic discovery after the import, for the switches that can be reached without
    trusting an unverified host key. Returns the discovery job id ("" when none)."""
    from app.services.discovery.service import can_discover, create_job

    if not switch_ids or creator_id is None:
        return ""
    user = await db.get(User, creator_id)
    if user is None:
        return ""
    switches = (await db.execute(select(Switch).where(Switch.id.in_(switch_ids)))).scalars()
    ids = [sw.id for sw in switches if can_discover(sw)]
    if not ids:
        return ""
    try:
        return (await create_job(db, user, ids, source="import")).id
    except Exception:  # noqa: BLE001 - the import itself is done; discovery can be re-run
        log.exception("Could not start the discovery of imported switches")
        await db.rollback()
        return ""


async def mark_interrupted_imports(db: AsyncSession) -> int:
    rows = (await db.execute(select(ImportJob).where(
        ImportJob.status.in_(ACTIVE_IMPORT_STATUSES)))).scalars().all()
    for job in rows:
        job.status = ImportStatus.INTERRUPTED.value
        job.failed_at = utcnow()
        job.error = ("The application stopped while this import was running. Rows committed "
                     "before the stop remain imported; run the import again to continue.")
    await db.commit()
    return len(rows)


def job_view(job: ImportJob, *, include_rows: bool = True) -> dict:
    out = {
        "id": job.id, "status": job.status, "file_format": job.file_format,
        "filename": job.filename, "created_by": job.created_by,
        "on_existing": job.on_existing, "skip_invalid": job.skip_invalid,
        "mode": job.mode, "discovery_job_id": job.discovery_job_id or None,
        "cancel_requested": job.cancel_requested or job.id in _ATOMIC_CANCEL,
        "total": job.total, "valid": job.valid, "invalid": job.invalid,
        "duplicates": job.duplicates, "warnings": job.warnings, "processed": job.processed,
        "imported": job.imported, "updated": job.updated, "unchanged": job.unchanged,
        "skipped": job.skipped, "failed": job.failed, "file_errors": job.file_errors,
        "error": job.error,
        **{k: (getattr(job, k).isoformat() if getattr(job, k) else None) for k in (
            "created_at", "expires_at", "confirmed_at", "started_at", "completed_at",
            "failed_at")},
    }
    rows = job.rows or []
    out["new"] = sum(r.get("action") == "create" for r in rows)
    out["existing_changed"] = sum(r.get("action") == "update" for r in rows)
    out["existing_unchanged"] = sum(r.get("action") == "unchanged" for r in rows)
    if include_rows:
        out["rows"] = [{k: r.get(k) for k in ("line", "name", "management_ip", "status",
                                               "action", "errors", "warnings", "diff",
                                               "result", "message")} for r in rows]
    return out


def error_report_csv(job: ImportJob) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf, quoting=csv.QUOTE_ALL, lineterminator="\r\n")
    writer.writerow(["line", "name", "management_ip", "status", "action", "result", "errors",
                     "warnings", "message"])
    for r in job.rows or []:
        if r.get("errors") or r.get("warnings") or r.get("result") in (
                "failed", "skipped", "not_processed"):
            writer.writerow([csv_cell(v) for v in (
                r.get("line"), r.get("name"), r.get("management_ip"), r.get("status"),
                r.get("action"), r.get("result"), " | ".join(r.get("errors") or []),
                " | ".join(r.get("warnings") or []), r.get("message"))])
    return buf.getvalue()


# ------------------------------------------------------------------------------- export ---
def _export_record(sw: Switch, credential_names: dict[int, str]) -> dict:
    """Only inventory metadata. Never passwords, keys, tokens or host keys."""
    return {
        "name": sw.name, "hostname": sw.hostname, "management_ip": sw.host,
        "ssh_port": sw.ssh_port,
        "credential_reference": credential_names.get(sw.credential_id or 0, ""),
        # Public fingerprint (not a secret): lets the file be re-imported without trusting an
        # unverified key.
        "ssh_host_key_fingerprint": sw.expected_host_key_fingerprint or sw.host_key_fingerprint,
        "expected_model": sw.expected_model, "expected_aos_version": sw.expected_aos_version,
        "site": sw.site, "location": sw.location, "description": sw.description,
        "role": sw.role, "environment": sw.environment, "enabled": sw.enabled,
        "uplink_ports": list(sw.uplink_ports or []),
        "port_locations": dict(sw.port_locations or {}),
        "vendor": sw.vendor, "discovered_model": sw.model,
        "discovered_aos_version": sw.aos_version, "discovery_status": sw.discovery_status,
        "status": sw.status,
        "created_at": sw.created_at.isoformat() if sw.created_at else "",
        "updated_at": sw.updated_at.isoformat() if sw.updated_at else "",
    }


async def export_switches(db: AsyncSession, file_format: str) -> tuple[str, int]:
    count = (await db.execute(select(func.count()).select_from(Switch))).scalar_one()
    if count > MAX_EXPORT_ROWS:
        raise ValidationFailedError(f"More than {MAX_EXPORT_ROWS} switches; export refused.")
    creds = {c.id: c.name for c in (await db.execute(select(Credential))).scalars()}
    switches = (await db.execute(select(Switch).order_by(Switch.name))).scalars().all()
    records = [_export_record(s, creds) for s in switches]
    if file_format == "json":
        return json.dumps({"format": "switch-inventory", "version": 1,
                           "exported_at": utcnow().isoformat(), "count": len(records),
                           "switches": records}, indent=2, ensure_ascii=False), len(records)
    buf = io.StringIO()
    writer = csv.writer(buf, quoting=csv.QUOTE_ALL, lineterminator="\r\n")
    writer.writerow(EXPORT_FIELDS)
    for rec in records:
        rec = {**rec, "uplink_ports": ";".join(rec["uplink_ports"]),
               "enabled": "true" if rec["enabled"] else "false"}
        writer.writerow([csv_cell(rec[f]) for f in EXPORT_FIELDS])
    return buf.getvalue(), len(records)


# Model / AOS version are discovered; the fingerprint comes from the switch console
# (verified out of band). The expected_* columns are optional.
TEMPLATE_CSV = (
    "name,hostname,management_ip,ssh_port,credential_reference,ssh_host_key_fingerprint,"
    "site,role,environment,enabled,expected_model,expected_aos_version\r\n"
    "R-BY-NET-SW-1,sw01,172.17.2.10,22,switch-readonly,,Main,access,production,true,,\r\n"
    "R-BY-NET-SW-2,sw02,172.17.2.11,22,switch-readonly,,Main,access,production,true,OS6450,"
    "6.7.1\r\n"
)
TEMPLATE_JSON = json.dumps({"switches": [
    {"name": "R-BY-NET-SW-1", "hostname": "sw01", "management_ip": "172.17.2.10",
     "ssh_port": 22, "credential_reference": "switch-readonly",
     "ssh_host_key_fingerprint": "", "site": "Main", "role": "access",
     "environment": "production", "enabled": True,
     "port_locations": {"1/1/5": "Building A - Floor 2 - Office 204"}},
]}, indent=2)
