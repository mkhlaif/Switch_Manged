"""Role-based access control: explicit permission sets per role (enforced server-side).

Roles are NOT a simple hierarchy: MAC_OPERATOR is a separate, deliberately tiny permission set for
non-technical staff (search a MAC, request a restart through the simplified flow). It has none of
the technical/read permissions of READ_ONLY.
"""

from __future__ import annotations

import enum

from app.models.user import Role


class Permission(str, enum.Enum):
    # --- technical read access -------------------------------------------------------------
    MAC_SEARCH = "mac_search"                # full technical MAC search + results
    PORT_INSPECT = "port_inspect"            # live port queries (GET_PORT_* operations)
    VIEW_INVENTORY = "view_inventory"        # switch list / details
    VIEW_HISTORY = "view_history"            # search history
    VIEW_PORT_ACTIONS = "view_port_actions"  # port action history / change reports
    VIEW_DASHBOARD = "view_dashboard"
    VIEW_ALERTS = "view_alerts"
    VIEW_SAFETY = "view_safety"              # safety status, operation policy, profiles
    VIEW_SETTINGS = "view_settings"
    VIEW_INTEGRATIONS = "view_integrations"  # NetBox / Zabbix read views
    # --- operational actions ---------------------------------------------------------------
    TEST_SWITCH = "test_switch"              # SSH test (discovery command only)
    RESTART_PORT = "restart_port"            # technical restart workflow
    ACK_ALERTS = "ack_alerts"
    STOP_OPERATIONS = "stop_operations"      # ENGAGE the kill switch (safety-increasing only)
    # --- simplified (non-technical) flow ---------------------------------------------------
    SIMPLE_SEARCH = "simple_search"
    SIMPLE_RESTART = "simple_restart"
    # --- administration --------------------------------------------------------------------
    VIEW_AUDIT = "view_audit"                # audit log, security events, SSH sessions
    MANAGE_INVENTORY = "manage_inventory"    # switches, host keys, detection
    IMPORT_SWITCHES = "import_switches"      # bulk switch import (CSV / JSON)
    EXPORT_SWITCHES = "export_switches"      # switch inventory export (no secrets)
    MANAGE_CREDENTIALS = "manage_credentials"
    MANAGE_USERS = "manage_users"
    MANAGE_PROFILES = "manage_profiles"      # command profiles, lab verification, approvals
    MANAGE_SAFETY = "manage_safety"          # operation modes, kill-switch release, breaker reset
    EMERGENCY_ACTIONS = "emergency_actions"  # approve emergency operations (trunk override)


_READ = frozenset({
    Permission.MAC_SEARCH, Permission.PORT_INSPECT, Permission.VIEW_INVENTORY,
    Permission.VIEW_HISTORY, Permission.VIEW_PORT_ACTIONS, Permission.VIEW_DASHBOARD,
    Permission.VIEW_ALERTS, Permission.VIEW_SAFETY, Permission.VIEW_SETTINGS,
    Permission.VIEW_INTEGRATIONS,
})

ROLE_PERMISSIONS: dict[Role, frozenset[Permission]] = {
    Role.READONLY: _READ,
    Role.MAC_OPERATOR: frozenset({Permission.SIMPLE_SEARCH, Permission.SIMPLE_RESTART}),
    Role.OPERATOR: _READ | {Permission.TEST_SWITCH, Permission.RESTART_PORT,
                            Permission.ACK_ALERTS, Permission.STOP_OPERATIONS},
    Role.ADMIN: frozenset(Permission) - {Permission.SIMPLE_SEARCH, Permission.SIMPLE_RESTART},
}


def permissions_for(role: Role | str) -> frozenset[Permission]:
    try:
        return ROLE_PERMISSIONS[Role(role)]
    except (ValueError, KeyError):
        return frozenset()  # unknown role: no permissions (fail closed)


def has_permission(role: Role | str, permission: Permission) -> bool:
    return permission in permissions_for(role)


PERMISSION_DESCRIPTIONS: dict[Permission, str] = {
    Permission.MAC_SEARCH: "Technical MAC search and results",
    Permission.PORT_INSPECT: "Live read-only port queries (GET_PORT_* operations)",
    Permission.VIEW_INVENTORY: "Switch list, switch details and topology",
    Permission.VIEW_HISTORY: "Search history",
    Permission.VIEW_PORT_ACTIONS: "Port action history and change reports",
    Permission.VIEW_DASHBOARD: "Dashboard",
    Permission.VIEW_ALERTS: "Alerts",
    Permission.VIEW_SAFETY: "Safety state, operation policy, command profiles",
    Permission.VIEW_SETTINGS: "Runtime settings (read)",
    Permission.VIEW_INTEGRATIONS: "NetBox / Zabbix read-only views",
    Permission.TEST_SWITCH: "SSH connection test (discovery command only)",
    Permission.RESTART_PORT: "Technical port restart workflow",
    Permission.ACK_ALERTS: "Acknowledge alerts",
    Permission.STOP_OPERATIONS: "Engage the kill switch (safety-increasing only)",
    Permission.SIMPLE_SEARCH: "Simplified MAC search (device location only)",
    Permission.SIMPLE_RESTART: "Direct restart of a verified endpoint port (automatic safety "
                               "checks, no administrator approval)",
    Permission.VIEW_AUDIT: "Audit log, security events, SSH session records",
    Permission.MANAGE_INVENTORY: "Switches, host keys, model/version detection",
    Permission.IMPORT_SWITCHES: "Bulk switch import (CSV / JSON, validated preview)",
    Permission.EXPORT_SWITCHES: "Switch inventory export (CSV / JSON, never secrets)",
    Permission.MANAGE_CREDENTIALS: "SSH credentials",
    Permission.MANAGE_USERS: "Users, roles view, force logout",
    Permission.MANAGE_PROFILES: "Command profiles and lab verification",
    Permission.MANAGE_SAFETY: "Operation modes, kill-switch release, SAFE MODE reset",
    Permission.EMERGENCY_ACTIONS: "Approve emergency operations (trunk override)",
}
