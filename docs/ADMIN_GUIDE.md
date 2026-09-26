# Administrator guide

Everything in the [USER_GUIDE.md](USER_GUIDE.md) plus the administration tasks below.
Installation: [DEPLOYMENT.md](DEPLOYMENT.md).

## Switch management

*Switches → Add switch*:

| Field | Notes |
|---|---|
| Name, management IP, SSH port | as configured on the switch (name and IP + port are unique, case-insensitive) |
| Hostname | DNS name (optional, unique) |
| Site, location | where the switch is; shown to MAC operators when no port location is set |
| Device locations per port | one line per port, e.g. `1/1/5 = Building A - Floor 2 - Office 204` — the only location MAC operators see |
| Credential | from *Settings → Credentials* (stored encrypted, never shown again) |
| Model / AOS version | leave empty and use **Detect model / AOS** (`show system` only) |
| Command profile | *Automatic* selects the profile by exact model family and AOS version |
| Topology role | access / distribution / core / unknown — ports of core and distribution switches are never restarted outside EMERGENCY mode; MAC operators can restart only on **access** switches |
| Uplink / trunk ports | always classified TRUNK, never restartable |
| Legacy SSH algorithms | only for old AOS 6 switches that need them |

Then on the switch page: **Fetch host key** → compare the SHA-256 fingerprint with the switch
console → type the last 8 characters → **Trust this key**; **Test SSH connection**; **Detect model
/ AOS**. A changed host key is refused until an administrator trusts the new one — find out why
first. The NetBox and Zabbix panels compare the inventory with those systems (read-only).

## Bulk import and export

*Switches → Import* adds or updates many switches from a CSV or JSON file (validation → preview
→ confirmation → background import with progress); *Export CSV / Export JSON* downloads the
inventory without any secret. Passwords are never part of these files: create the credential
first and reference it by name. Full description: [SWITCH_IMPORT_EXPORT.md](SWITCH_IMPORT_EXPORT.md).

## Users and roles

*Settings → Users*: create users (username, name, role, password), edit name/role/active flag,
reset a password (enter a new one when editing), **Force logout**, delete. The list shows active
sessions and last login. Rules: nobody can change their own role or disable themselves; the last
active administrator cannot be demoted, disabled or deleted; a role change ends the user's
sessions. *Settings → Roles* shows the fixed permission matrix.

| Role | Intended for |
|---|---|
| MAC_OPERATOR | non-technical staff: search a MAC (sees the location only) and restart that device's endpoint port directly — no approval by you, but every automatic safety check (see below) |
| READ_ONLY | technical staff who investigate |
| OPERATOR | technical staff who may restart access ports |
| ADMIN | platform administrators |

## MAC operators

A MAC operator's restart needs no approval from an administrator — it is allowed only when every
automatic check passes (details: [SECURITY.md § 4](SECURITY.md#4-mac_operator-direct-endpoint-restart)).
To make it work where you want it:

1. Set the **topology role** of access switches to `access` (the default `unknown` blocks MAC
   operators on purpose).
2. Declare uplink ports; keep port descriptions meaningful (a description with *uplink*,
   *trunk*, *mgmt*, *stack*, *LAG*, … blocks the simple restart).
3. Enter **device locations per port** (switch edit form, or JSON import `port_locations`) so
   the operator sees *Building A - Floor 2 - Office 204* instead of just the site.
4. Lab-verify the restart strategy for the model family / AOS version, turn dry run off and open
   a **MAINTENANCE** window when restarts may happen (NORMAL mode is read-only).

When a MAC operator gets *"This device cannot be restarted automatically"*, the exact reason is in
*Audit Logs* (action `SIMPLE_RESTART_BLOCKED` or `PORT_RESTART_PREPARE` / `DENIED`). A restart
that did not fully verify (MAC not back in the same VLAN, VLANs or classification changed) is
shown to them as *"could not be verified"*; the verification details are in *Port Actions*.

## Command profiles and lab verification

*Settings → Command profiles* lists every command per profile with source, output contract and
verification. Before production use, per model family and AOS version:

1. **Run read-only verification on a lab switch…** → *Run checks* → *Record READ verification*.
2. For each restart strategy you want to use, follow
   [DEPLOYMENT.md § Production enablement](DEPLOYMENT.md#5-production-enablement) and **Record**
   it.

Revoking a record (×) immediately stops that capability for that family/version. Custom
profiles (Clone) can only choose among allowlisted templates and start disabled.

## MAC search, port inspection, restart workflow

As in the user guide. Which classifications operators may restart is configurable in *Settings →
Port actions* (default: ACCESS and LIKELY ACCESS). Only administrators, only in EMERGENCY mode
and with two typed confirmations, may restart trunk ports and ports of core/distribution
switches. UNKNOWN ports, declared uplinks and link aggregates are never restarted. Every step is
audited.

## Safety controls

| Control | How | Effect |
|---|---|---|
| Operation mode | *Safety Controls* → Normal / Maintenance / Read only / Emergency (reason required) | NORMAL = read-only operations; MAINTENANCE = authorised restarts; EMERGENCY = admin-only emergency operations |
| Kill switch | **STOP ALL NETWORK OPERATIONS** (operators may engage; only admins release) | blocks every state-changing command immediately; a restart in progress still restores its port |
| Circuit breaker | automatic → SAFE MODE; *Reset SAFE MODE* (reason required) | trips on repeated SSH/auth failures of healthy switches, validation failures, unexpected CLI output; thresholds under *Limits and thresholds* |
| Dry run | *Settings → Port actions* | restarts only show the commands |
| Locks | *Safety Controls → Switch and port locks* | one state-changing operation per switch and per port |
| Environment overrides | `.env`: `READ_ONLY_MODE=true`, `NETWORK_COMMAND_EXECUTION=DISABLED` | cannot be overridden from the UI |

Every change is written to the safety events and the audit log.

## Audit logs

*Audit Logs*: every login, change, search, restart, import, export, blocked attempt and security event, with
user, role, source IP, operation, switch, port, MAC, VLAN, profile, command fingerprint, risk,
approval, result, error and before/after state. The database refuses to modify or delete audit
rows. *SSH sessions* shows every session with the commands (by key and fingerprint). CSV export is
available (formula-safe).

## NetBox and Zabbix

Configure `NETBOX_URL`/`NETBOX_TOKEN` and/or `ZABBIX_URL`/`ZABBIX_TOKEN` in `.env` (read-only
tokens), `docker compose up -d`, check *Settings → Integrations*. NetBox: device and interface
comparison, reconciliation with mismatch alerts — nothing is ever written to NetBox. Zabbix: host
monitoring state and current problems (Zabbix 6.4+ API token) — nothing is ever changed in
Zabbix.

## Regular tasks

- Review alerts and SAFE MODE causes; acknowledge handled alerts.
- Back up the database ([BACKUP_RESTORE.md](BACKUP_RESTORE.md)) and keep
  `CREDENTIAL_ENCRYPTION_KEY` safe.
- Update carefully ([UPGRADE.md](UPGRADE.md)); re-run the lab verification after AOS upgrades on
  the switches (a new AOS version prefix needs its own record).
