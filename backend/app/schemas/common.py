from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, computed_field, field_validator

from app.core import inventory_fields as fields
from app.models import Role


class ORM(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class Strict(BaseModel):
    """Request bodies: unknown fields (e.g. "command") are rejected, never ignored."""

    model_config = ConfigDict(extra="forbid")


# ---------------------------------------------------------------- auth / users -------------
class LoginRequest(Strict):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class ChangePasswordRequest(Strict):
    current_password: str = Field(max_length=256)
    new_password: str = Field(max_length=256)


class UserOut(ORM):
    id: int
    username: str
    full_name: str
    role: str
    is_active: bool
    last_login_at: datetime | None
    created_at: datetime


class UserCreate(Strict):
    username: str = Field(pattern=r"^[a-zA-Z0-9._-]{3,64}$")
    full_name: str = Field(default="", max_length=128)
    password: str = Field(max_length=256)
    role: Role = Role.READONLY


class UserUpdate(Strict):
    full_name: str | None = Field(default=None, max_length=128)
    role: Role | None = None
    is_active: bool | None = None
    password: str | None = Field(default=None, max_length=256)


# ---------------------------------------------------------------- credentials --------------
class CredentialOut(ORM):
    id: int
    name: str
    username: str
    description: str
    has_password: bool = True
    switch_count: int = 0
    created_at: datetime
    updated_at: datetime


class CredentialCreate(Strict):
    name: str = Field(min_length=1, max_length=64)
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)
    description: str = Field(default="", max_length=255)


class CredentialUpdate(Strict):
    name: str | None = Field(default=None, min_length=1, max_length=64)
    username: str | None = Field(default=None, min_length=1, max_length=64)
    password: str | None = Field(default=None, min_length=1, max_length=256)
    description: str | None = Field(default=None, max_length=255)


# ---------------------------------------------------------------- switches -----------------
_HOST_PATTERN = r"^[A-Za-z0-9.\-:_]{1,255}$"


def _clean_ports(value: list[str]) -> list[str]:
    cleaned = []
    for port in value:
        port = port.strip()
        if not port:
            continue
        if not re.fullmatch(r"\d{1,2}/\d{1,3}(/\d{1,3}[A-Z]?)?", port):
            raise ValueError(f"Invalid port '{port}' (use 1/26 or 1/1/26).")
        cleaned.append(port)
    return sorted(set(cleaned))


_SWITCH_ROLE = r"^(access|distribution|core|unknown)$"


def _safe_text(value: str | None, field: str) -> str | None:
    """Location/description: no control characters, no leading spreadsheet-formula character."""
    if value is None:
        return None
    if fields.CONTROL_CHARS.search(value):
        raise ValueError(f"{field} contains control characters.")
    value = value.strip()
    if value.startswith(fields.FORMULA_PREFIXES):
        raise ValueError(f"{field} must not start with {value[0]!r}.")
    return value


class SwitchBase(Strict):
    name: str = Field(min_length=1, max_length=128)
    host: str = Field(pattern=_HOST_PATTERN)
    hostname: str = Field(default="", max_length=253)
    ssh_port: int = Field(default=22, ge=1, le=65535)
    # Model and AOS version are DISCOVERED, never entered. What an administrator expects may be
    # recorded as metadata; discovery compares it (mismatch blocks state changes).
    expected_model: str = Field(default="", max_length=64)
    expected_aos_version: str = Field(default="", max_length=64)
    expected_host_key_fingerprint: str = Field(default="", max_length=128)
    environment: str = Field(default="production", pattern=r"^(production|lab)$")
    site: str = Field(default="", max_length=128)
    location: str = Field(default="", max_length=128)
    description: str = Field(default="", max_length=255)
    enabled: bool = True
    credential_id: int | None = None
    profile_key: str = Field(default="", max_length=32)
    transport: str = Field(default="ssh", pattern=r"^(ssh|simulator)$")
    legacy_ssh_algorithms: bool = False
    uplink_ports: list[str] = Field(default_factory=list)
    port_locations: dict[str, str] = Field(default_factory=dict)
    role: str = Field(default="unknown", pattern=_SWITCH_ROLE)

    @field_validator("uplink_ports")
    @classmethod
    def _ports(cls, value: list[str]) -> list[str]:
        return _clean_ports(value)

    @field_validator("expected_model")
    @classmethod
    def _expected_model(cls, value: str) -> str:
        return fields.expected_model(value)

    @field_validator("expected_aos_version")
    @classmethod
    def _expected_version(cls, value: str) -> str:
        return fields.expected_aos_version(value)

    @field_validator("expected_host_key_fingerprint")
    @classmethod
    def _fingerprint(cls, value: str) -> str:
        return fields.host_key_fingerprint(value)

    @field_validator("hostname")
    @classmethod
    def _hostname(cls, value: str) -> str:
        return fields.hostname(value)

    @field_validator("site")
    @classmethod
    def _site(cls, value: str) -> str:
        return fields.free_text(value, "site", 128)

    @field_validator("location", "description")
    @classmethod
    def _text(cls, value: str, info) -> str:
        return _safe_text(value, info.field_name) or ""

    @field_validator("port_locations")
    @classmethod
    def _port_locations(cls, value: dict[str, str]) -> dict[str, str]:
        return fields.port_locations(value)


class SwitchCreate(SwitchBase):
    pass


class SwitchUpdate(Strict):
    name: str | None = Field(default=None, min_length=1, max_length=128)
    host: str | None = Field(default=None, pattern=_HOST_PATTERN)
    hostname: str | None = Field(default=None, max_length=253)
    ssh_port: int | None = Field(default=None, ge=1, le=65535)
    expected_model: str | None = Field(default=None, max_length=64)
    expected_aos_version: str | None = Field(default=None, max_length=64)
    expected_host_key_fingerprint: str | None = Field(default=None, max_length=128)
    environment: str | None = Field(default=None, pattern=r"^(production|lab)$")
    site: str | None = Field(default=None, max_length=128)
    location: str | None = Field(default=None, max_length=128)
    description: str | None = Field(default=None, max_length=255)
    enabled: bool | None = None
    credential_id: int | None = None
    profile_key: str | None = Field(default=None, max_length=32)
    transport: str | None = Field(default=None, pattern=r"^(ssh|simulator)$")
    legacy_ssh_algorithms: bool | None = None
    uplink_ports: list[str] | None = None
    port_locations: dict[str, str] | None = None
    role: str | None = Field(default=None, pattern=_SWITCH_ROLE)

    @field_validator("uplink_ports")
    @classmethod
    def _ports(cls, value: list[str] | None) -> list[str] | None:
        return None if value is None else _clean_ports(value)

    @field_validator("expected_model")
    @classmethod
    def _expected_model(cls, value: str | None) -> str | None:
        return None if value is None else fields.expected_model(value)

    @field_validator("expected_aos_version")
    @classmethod
    def _expected_version(cls, value: str | None) -> str | None:
        return None if value is None else fields.expected_aos_version(value)

    @field_validator("expected_host_key_fingerprint")
    @classmethod
    def _fingerprint(cls, value: str | None) -> str | None:
        return None if value is None else fields.host_key_fingerprint(value)

    @field_validator("hostname")
    @classmethod
    def _hostname(cls, value: str | None) -> str | None:
        return None if value is None else fields.hostname(value)

    @field_validator("site")
    @classmethod
    def _site(cls, value: str | None) -> str | None:
        return None if value is None else fields.free_text(value, "site", 128)

    @field_validator("location", "description")
    @classmethod
    def _text(cls, value: str | None, info) -> str | None:
        return _safe_text(value, info.field_name)

    @field_validator("port_locations")
    @classmethod
    def _port_locations(cls, value: dict[str, str] | None) -> dict[str, str] | None:
        return None if value is None else fields.port_locations(value)


class SwitchOut(ORM):
    id: int
    name: str
    host: str
    hostname: str = ""
    ssh_port: int
    # Discovered identity (read-only; from automatic discovery only).
    vendor: str = ""
    model: str
    aos_version: str
    discovery_status: str = "not_discovered"
    discovery_error: str = ""
    discovery_category: str = ""
    discovery_profile: str = ""
    discovered_at: datetime | None = None
    system_name: str = ""
    system_object_id: str = ""
    expected_model: str = ""
    expected_aos_version: str = ""
    expected_host_key_fingerprint: str = ""
    environment: str = "production"
    site: str = ""
    location: str
    description: str
    enabled: bool
    credential_id: int | None
    credential_name: str | None = None
    profile_key: str
    effective_profile: str | None = None
    profile_reason: str = ""
    transport: str
    legacy_ssh_algorithms: bool
    uplink_ports: list[str]
    port_locations: dict[str, str] = {}
    role: str = "unknown"
    host_key_fingerprint: str
    host_key_trusted: bool = False
    status: str
    last_check_at: datetime | None
    last_success_at: datetime | None
    last_error: str
    created_at: datetime
    updated_at: datetime


class ImportUpload(Strict):
    """The file is sent as text inside JSON (no multipart parsing); the size is bounded here and
    again by the importer (5 MB, 5000 rows)."""

    filename: str = Field(default="", max_length=255)
    format: str = Field(pattern=r"^(csv|json)$")
    content: str = Field(min_length=1, max_length=5_000_000)


class ImportConfirm(Strict):
    on_existing: str = Field(default="skip", pattern=r"^(skip|update)$")
    skip_invalid: bool = False
    # atomic (default): all rows or none. per_row: explicit opt-in, invalid rows skipped.
    mode: str = Field(default="atomic", pattern=r"^(atomic|per_row)$")


class TrustHostKeyRequest(Strict):
    fingerprint: str = Field(min_length=10, max_length=128)


# ---------------------------------------------------------------- search -------------------
class MacSearchRequest(Strict):
    # Deliberately loose length: the strict security validator (not pydantic) must see
    # malformed/malicious values so they are recorded as security events.
    mac: str = Field(min_length=1, max_length=128)
    switch_ids: list[int] | None = None
    mode: str = Field(default="STANDARD", pattern=r"^(FAST|STANDARD|DEEP)$")


class MacSearchOut(ORM):
    id: str
    mac: str
    requested_by: str
    status: str
    mode: str = "STANDARD"
    total_switches: int
    checked: int
    found_count: int
    failed_count: int
    timeout_count: int
    options: dict[str, Any]
    summary: dict[str, Any]
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    duration_ms: int | None


class MacSearchResultOut(ORM):
    id: int
    search_id: str
    switch_id: int | None
    switch_name: str
    switch_host: str
    location: str
    model: str
    aos_version: str
    profile_key: str
    status: str
    error_message: str
    port: str
    interface_raw: str
    is_linkagg: bool
    vlan_id: int | None
    mac_type: str
    operation: str
    port_details: dict[str, Any]
    vlans: list[Any]
    tagged_vlans: list[int]
    untagged_vlan: int | None
    lldp: list[Any]
    mac_count_on_port: int | None
    classification: str
    classification_confidence: str
    classification_score: float | None
    classification_reasons: list[Any]
    commands_executed: list[Any]
    warnings: list[Any]
    duration_ms: int | None
    created_at: datetime

    @computed_field  # type: ignore[prop-decorator]
    @property
    def category(self) -> str:
        """Safe error category of this switch's result ("" when found / not found)."""
        from app.core.error_categories import category_for_status

        return category_for_status(self.status)


# ---------------------------------------------------------------- port actions -------------
class PrepareRestartRequest(Strict):
    method: str = Field(default="link_bounce", pattern=r"^(link_bounce|poe_cycle)$")
    search_result_id: int | None = None
    switch_id: int | None = None
    port: str | None = Field(default=None, max_length=128)
    mac: str | None = Field(default=None, max_length=128)


class ExecuteRestartRequest(Strict):
    plan_token: str = Field(min_length=36, max_length=36)
    confirmations: list[str] = Field(default_factory=list, max_length=4)
    reason: str = Field(default="", max_length=500)


class PortActionOut(ORM):
    id: int
    plan_token: str
    action: str
    method: str
    strategy: str
    profile_key: str
    status: str
    switch_id: int | None
    switch_name: str
    switch_host: str
    aos_version: str
    port: str
    mac: str
    vlan_id: int | None
    vlans: list[Any]
    classification: str
    classification_confidence: str
    classification_reasons: list[Any]
    risk_level: str
    warnings: list[Any]
    required_phrases: list[str]
    available: bool
    execution_allowed: bool
    execution_note: str
    blocked_reason: str
    commands: list[str]
    commands_executed: list[str]
    steps: list[Any]
    verification: dict[str, Any]
    safety_report: dict[str, Any] = {}
    dry_run: bool
    trunk_override: bool
    reason: str
    result_message: str
    error_message: str
    # SUCCESS | VERIFICATION_FAILED | FAILED | UNKNOWN | BLOCKED, the safe error category and
    # the content hash of the command profile that was used.
    outcome: str | None = None
    error_category: str | None = None
    profile_version: str | None = None
    requested_by: str
    search_id: str | None
    created_at: datetime
    expires_at: datetime | None
    confirmed_at: datetime | None
    started_at: datetime | None
    finished_at: datetime | None


# ---------------------------------------------------------------- audit / settings ---------
class AuditOut(ORM):
    id: int
    ts: datetime
    username: str
    role: str = ""
    action: str
    operation: str = ""
    result: str
    severity: str = "INFO"
    vlan: int | None = None
    profile: str = ""
    command_fingerprint: str = ""
    risk_level: str = ""
    approval: str = ""
    error: str = ""
    before_state: dict[str, Any] | None = None
    after_state: dict[str, Any] | None = None
    target_type: str
    target_id: str
    target_label: str
    mac: str
    switch_name: str
    port: str
    message: str
    details: dict[str, Any]
    ip: str


class SettingsUpdate(Strict):
    values: dict[str, Any]


class VerificationCreate(Strict):
    """Administrator lab-verification record (§9): a capability ("READ" or a restart strategy)
    of a profile, verified on a model family ("*" = every supported model) and AOS version."""

    profile_key: str = Field(max_length=32)
    capability: str = Field(pattern=r"^[A-Z0-9_]{3,32}$")
    # An exact model family and at least major.minor: nobody verifies "every model" or "8.x".
    model_family: str = Field(pattern=r"^OS\d{2,5}K?[A-Z]?$")
    version_prefix: str = Field(pattern=r"^\d{1,2}\.\d{1,3}(\.\d{1,3}){0,2}$")
    notes: str = Field(default="", max_length=1000)


class VerificationStatusChange(Strict):
    """Profile state transition of a verification record (audited, reason mandatory)."""

    status: str = Field(pattern=r"^(LAB_VERIFIED|PRODUCTION_VERIFIED|BLOCKED|DEPRECATED)$")
    reason: str = Field(min_length=3, max_length=300)


class VerificationRun(Strict):
    """Run the read-only commands of the switch's profile against one sample port and validate
    each output against its documented contract. Optionally record READ verification."""

    switch_id: int
    port: str = Field(max_length=32)
    mac: str | None = Field(default=None, max_length=32)
    record: bool = False
    notes: str = Field(default="", max_length=1000)


class ModeChange(Strict):
    mode: str = Field(pattern=r"^(NORMAL|MAINTENANCE|READ_ONLY|EMERGENCY)$")
    reason: str = Field(min_length=3, max_length=300)


class KillSwitchRequest(Strict):
    active: bool
    reason: str = Field(min_length=3, max_length=300)


class BreakerReset(Strict):
    reason: str = Field(min_length=3, max_length=300)


class SimpleSearchRequest(Strict):
    mac: str = Field(min_length=1, max_length=128)


class SimpleRestartRequest(Strict):
    search_id: str = Field(min_length=36, max_length=36)


class ProfileCreate(Strict):
    key: str = Field(pattern=r"^[A-Z0-9_]{3,32}$")
    name: str = Field(min_length=3, max_length=128)
    clone_from: str = Field(max_length=32)
    description: str = Field(default="", max_length=2000)


class ProfileUpdate(Strict):
    name: str | None = Field(default=None, max_length=128)
    description: str | None = Field(default=None, max_length=2000)
    enabled: bool | None = None
    commands: dict[str, dict[str, Any]] | None = None
    strategies: list[dict[str, Any]] | None = None


class OperationRequest(Strict):
    """Operation-based API: the client names a predefined operation; the backend builds any
    command. There is no field that could carry CLI text."""

    operation: str = Field(min_length=1, max_length=64)
    switch_id: int | None = None
    switch_ids: list[int] | None = None
    port: str | None = Field(default=None, max_length=128)
    mac: str | None = Field(default=None, max_length=128)
    confirmation_token: str | None = Field(default=None, max_length=64)
    confirmations: list[str] = Field(default_factory=list, max_length=4)
    reason: str = Field(default="", max_length=500)
    mode: str = Field(default="STANDARD", pattern=r"^(FAST|STANDARD|DEEP)$")


class DiscoveryJobCreate(Strict):
    """Discover the given switches (or every enabled switch) in the background."""

    switch_ids: list[int] = Field(default_factory=list, max_length=5000)
    all_enabled: bool = False


class DiscoveryAccept(Strict):
    reason: str = Field(min_length=3, max_length=300)
