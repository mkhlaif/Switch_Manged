from __future__ import annotations

import enum
from datetime import datetime

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.timeutil import utcnow
from app.db.base import Base, UTCDateTime


class Credential(Base):
    """A reusable SSH login. The password is stored Fernet-encrypted, never in plaintext."""

    __tablename__ = "credentials"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True)
    username: Mapped[str] = mapped_column(String(64))
    password_encrypted: Mapped[str] = mapped_column(Text)
    description: Mapped[str] = mapped_column(String(255), default="")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, onupdate=utcnow)

    switches: Mapped[list[Switch]] = relationship(back_populates="credential")


class SwitchStatus(str, enum.Enum):
    UNKNOWN = "unknown"
    ONLINE = "online"
    OFFLINE = "offline"
    AUTH_FAILED = "auth_failed"
    HOSTKEY_ERROR = "hostkey_error"
    ERROR = "error"


class Transport(str, enum.Enum):
    SSH = "ssh"
    SIMULATOR = "simulator"


SWITCH_ROLES = ("access", "distribution", "core", "unknown")


class DiscoveryStatus(str, enum.Enum):
    NOT_DISCOVERED = "not_discovered"    # never identified (or legacy manual data)
    DISCOVERED = "discovered"            # vendor/model/AOS read from the device
    DISCOVERY_FAILED = "discovery_failed"  # could not be identified safely
    MISMATCH = "mismatch"                # device differs from expected/previous identity


DISCOVERY_STATUSES = tuple(s.value for s in DiscoveryStatus)
ENVIRONMENTS = ("production", "lab")


class Switch(Base):
    __tablename__ = "switches"
    __table_args__ = (
        # One inventory entry per management address (host names are case-insensitive): a second
        # entry for the same switch would make every MAC on it appear in two "locations".
        # Expression indexes: they also serve the case-insensitive lookups of the importer and
        # the switch API (without them every check was a full table scan).
        Index("uq_switches_host_port", text("lower(host)"), "ssh_port", unique=True),
        Index("uq_switches_name_lower", text("lower(name)"), unique=True),
        Index("uq_switches_hostname", "hostname", unique=True,
              postgresql_where=text("hostname <> ''"), sqlite_where=text("hostname <> ''")),
        CheckConstraint("ssh_port BETWEEN 1 AND 65535", name="ssh_port_range"),
        CheckConstraint("role IN ('access', 'distribution', 'core', 'unknown')",
                        name="role_valid"),
        CheckConstraint("transport IN ('ssh', 'simulator')", name="transport_valid"),
        CheckConstraint("discovery_status IN ('not_discovered', 'discovered', "
                        "'discovery_failed', 'mismatch')", name="discovery_status_valid"),
        CheckConstraint("environment IN ('production', 'lab')", name="environment_valid"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    host: Mapped[str] = mapped_column(String(255))
    # DNS host name of the switch (optional, informational; unique when set).
    hostname: Mapped[str] = mapped_column(String(255), default="", server_default="")
    ssh_port: Mapped[int] = mapped_column(Integer, default=22)
    # Identity READ FROM THE DEVICE by discovery (services/discovery); never entered by hand.
    vendor: Mapped[str] = mapped_column(String(16), default="", server_default="")
    model: Mapped[str] = mapped_column(String(64), default="")
    aos_version: Mapped[str] = mapped_column(String(64), default="")
    discovery_status: Mapped[str] = mapped_column(
        String(20), default=DiscoveryStatus.NOT_DISCOVERED.value,
        server_default=DiscoveryStatus.NOT_DISCOVERED.value)
    discovery_error: Mapped[str] = mapped_column(String(255), default="", server_default="")
    discovery_category: Mapped[str] = mapped_column(String(32), default="", server_default="")
    discovery_profile: Mapped[str] = mapped_column(String(32), default="", server_default="")
    discovered_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    system_name: Mapped[str] = mapped_column(String(128), default="", server_default="")
    system_description: Mapped[str] = mapped_column(String(255), default="", server_default="")
    system_object_id: Mapped[str] = mapped_column(String(64), default="", server_default="")
    # Administrator metadata (import / form): compared with discovery, never trusted as identity.
    expected_model: Mapped[str] = mapped_column(String(64), default="", server_default="")
    expected_aos_version: Mapped[str] = mapped_column(String(64), default="", server_default="")
    # SHA-256 fingerprint supplied out of band (e.g. in an import file): when the switch
    # presents exactly this key it is trusted automatically; anything else is refused.
    expected_host_key_fingerprint: Mapped[str] = mapped_column(String(128), default="",
                                                               server_default="")
    # production: restarts need PRODUCTION_VERIFIED strategies; lab: LAB_VERIFIED suffices.
    environment: Mapped[str] = mapped_column(String(12), default="production",
                                             server_default="production")
    site: Mapped[str] = mapped_column(String(128), default="", server_default="")
    location: Mapped[str] = mapped_column(String(128), default="")
    description: Mapped[str] = mapped_column(String(255), default="")
    # Human-readable location per port ({"1/1/5": "Building A - Floor 2 - Office 204"}). This is
    # the only location text the MAC_OPERATOR sees; without it, site and location are shown.
    port_locations: Mapped[dict] = mapped_column(JSON, default=dict,
                                                 server_default=text("'{}'"))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    credential_id: Mapped[int | None] = mapped_column(
        ForeignKey("credentials.id", ondelete="RESTRICT"), nullable=True
    )
    # Explicit command profile; when empty the profile is chosen from the detected AOS version.
    profile_key: Mapped[str] = mapped_column(String(32), default="")
    transport: Mapped[str] = mapped_column(String(16), default=Transport.SSH.value)
    # Trusted SSH host key in OpenSSH format ("ssh-rsa AAAA..."). Required unless the lab-only
    # SSH_ALLOW_UNKNOWN_HOST_KEYS option is on.
    host_key: Mapped[str] = mapped_column(Text, default="")
    host_key_fingerprint: Mapped[str] = mapped_column(String(128), default="")
    # Enables older SSH algorithms (diffie-hellman-group1-sha1, CBC ciphers, ssh-dss) for old AOS 6.
    legacy_ssh_algorithms: Mapped[bool] = mapped_column(Boolean, default=False)
    # Ports known to be uplinks/trunks (e.g. ["1/1/49", "1/1/50"]). Always classified TRUNK and
    # can never be restarted from this tool.
    uplink_ports: Mapped[list] = mapped_column(JSON, default=list)
    # Topology role (§55): core | distribution | access | unknown. Ports on core/distribution
    # switches are infrastructure and are never restarted outside EMERGENCY mode.
    role: Mapped[str] = mapped_column(String(16), default="unknown", server_default="unknown")

    status: Mapped[str] = mapped_column(String(16), default=SwitchStatus.UNKNOWN.value)
    last_check_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    last_success_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)
    last_error: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, onupdate=utcnow)

    credential: Mapped[Credential | None] = relationship(back_populates="switches")


class CommandProfileRecord(Base):
    """Command profiles. Built-in profiles are synced from code at startup and are read-only;
    administrators can clone them into custom profiles whose templates pass the safety linter."""

    __tablename__ = "command_profiles"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    key: Mapped[str] = mapped_column(String(32), unique=True)
    name: Mapped[str] = mapped_column(String(128))
    description: Mapped[str] = mapped_column(Text, default="")
    builtin: Mapped[bool] = mapped_column(Boolean, default=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    definition: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, onupdate=utcnow)
