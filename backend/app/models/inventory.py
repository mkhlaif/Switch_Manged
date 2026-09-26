from __future__ import annotations

import enum
from datetime import datetime

from sqlalchemy import JSON, Boolean, ForeignKey, Integer, String, Text
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


class Switch(Base):
    __tablename__ = "switches"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    host: Mapped[str] = mapped_column(String(255))
    ssh_port: Mapped[int] = mapped_column(Integer, default=22)
    model: Mapped[str] = mapped_column(String(64), default="")
    aos_version: Mapped[str] = mapped_column(String(64), default="")
    location: Mapped[str] = mapped_column(String(128), default="")
    description: Mapped[str] = mapped_column(String(255), default="")
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
