"""Application configuration, loaded from environment variables (and an optional .env file)."""

from __future__ import annotations

from functools import lru_cache

from pydantic import AliasChoices, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_name: str = "OmniSwitch MAC Locator"
    environment: str = Field(default="production", description="production | development | test")

    # --- Database -------------------------------------------------------------------------------
    database_url: str = "sqlite+aiosqlite:///./data/dev.db"

    # --- Secrets --------------------------------------------------------------------------------
    # Fernet key (urlsafe base64, 32 bytes) used to encrypt switch credentials at rest.
    # Generate with: python -m app.cli generate-key
    credential_encryption_key: str = ""

    # --- Web session security -------------------------------------------------------------------
    session_ttl_minutes: int = 480
    # Sessions unused for this long are ended (in addition to the absolute lifetime above).
    session_idle_minutes: int = Field(default=60, ge=5, le=1440)
    cookie_secure: bool = True
    # Comma-separated list; only needed when the UI is served from a different origin (dev).
    cors_origins: str = ""

    # --- Bootstrap admin (only used when the users table is empty) ------------------------------
    initial_admin_username: str = ""
    initial_admin_password: str = ""

    # --- SSH engine -----------------------------------------------------------------------------
    max_concurrent_switch_connections: int = Field(
        default=5, ge=1, le=100,
        validation_alias=AliasChoices("MAX_CONCURRENT_SSH", "MAX_CONCURRENT_SWITCH_CONNECTIONS"))
    ssh_connect_timeout: float = Field(
        default=10.0, validation_alias=AliasChoices("SSH_TIMEOUT", "SSH_CONNECT_TIMEOUT"))
    ssh_login_timeout: float = 20.0
    ssh_command_timeout: float = Field(
        default=15.0, validation_alias=AliasChoices("COMMAND_TIMEOUT", "SSH_COMMAND_TIMEOUT"))
    ssh_connect_retries: int = Field(default=1, ge=0, le=5)
    ssh_switch_budget_seconds: float = 120.0
    # Maximum wall-clock duration of one SSH session (then it is closed, fail closed).
    ssh_max_session_seconds: float = 300.0
    # LAB ONLY. When true, switches without a trusted host key are connected to anyway.
    # Never enable this in production: it disables man-in-the-middle protection.
    ssh_allow_unknown_host_keys: bool = False

    # --- Lab / simulator ------------------------------------------------------------------------
    enable_simulator: bool = False

    # --- Port actions ---------------------------------------------------------------------------
    # Initial value of the "dry run" system setting (the live value is stored in the database).
    default_dry_run: bool = True
    # Global READ-ONLY mode: when true the effective operation mode is READ_ONLY regardless of
    # runtime settings; every state-changing operation (RESTART_PORT) is blocked. This is the
    # recommended initial production state. Read-only operations are unaffected.
    read_only_mode: bool = False
    # ENABLED | DISABLED. DISABLED forces the kill switch ("STOP ALL NETWORK OPERATIONS").
    # Fresh installs: DISABLED (kill switch engaged). Only exactly "ENABLED" allows
    # state-changing commands; any other value keeps them blocked (fail closed).
    network_command_execution: str = "DISABLED"
    # Initial SSH-failure threshold of the circuit breaker (runtime setting afterwards).
    circuit_breaker_threshold: int = Field(default=5, ge=1, le=100)

    # --- Integrations (read-only; optional) -----------------------------------------------------
    netbox_url: str = ""
    netbox_token: str = ""
    netbox_verify_tls: bool = True
    zabbix_url: str = ""          # e.g. https://zabbix.example/api_jsonrpc.php
    zabbix_token: str = ""        # API token, sent as "Authorization: Bearer" (Zabbix >= 6.4)
    zabbix_verify_tls: bool = True
    integration_timeout: float = 10.0

    # --- Logging --------------------------------------------------------------------------------
    log_level: str = "INFO"
    log_format: str = "text"

    @field_validator("log_level")
    @classmethod
    def _upper_level(cls, value: str) -> str:
        return value.upper()

    @property
    def cors_origin_list(self) -> list[str]:
        return [v.strip() for v in self.cors_origins.split(",") if v.strip()]

    @property
    def is_sqlite(self) -> bool:
        return self.database_url.startswith("sqlite")


@lru_cache
def get_settings() -> Settings:
    return Settings()
