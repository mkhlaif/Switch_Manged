# Switch import and export

Administrators can add or update many switches at once from a CSV or JSON file, and export the
inventory. *Switches → Import / Export CSV / Export JSON* (the buttons are only shown to
administrators; the API refuses every other role).

## Workflow

```
Upload file → Validation (server) → Preview → Confirm → Background import (batches) → Result
```

1. **Upload** a `.csv` or `.json` file (max. 5 MB / 5000 switches). Templates: *CSV template*,
   *JSON template* in the dialog (`GET /api/switches/import/template?format=csv|json`).
2. **Validation and preview.** Nothing is written yet. The preview shows *Total, Valid, Invalid,
   Duplicates, Warnings, New, Existing changed, Unchanged* and every row with its errors and
   warnings. *Download error report* gives the same as a CSV file.
3. **Confirm.** Choose what happens to switches that already exist with different values:
   - **Skip — do not change them** (default): they are reported as *skipped*;
   - **Update them with the file's values**: they are changed (a changed management address or
     SSH port clears the trusted host key, which must then be enrolled again).

   If the file contains invalid or duplicate rows you must tick *Skip the … invalid/duplicate
   rows* — a partial import never happens silently. The preview expires after 30 minutes; only
   the administrator who uploaded it can confirm it; only one import runs at a time.
4. **Import** runs in the background: each row is re-checked against the current inventory and
   written in its own transaction (a row that fails — e.g. a name created meanwhile — is
   reported as *failed* and does not affect other rows); progress is saved every 100 rows. *Cancel
   import* stops after the current batch (rows already imported stay; import the file again to
   continue — it is idempotent). A job stops after 15 minutes. If the application restarts during
   an import, the job is marked *interrupted*.
5. **Result**: *Imported, Updated, Unchanged, Skipped, Failed* per row, plus an audit entry
   (`SWITCH_IMPORT`) listing the created/updated switches.

Importing the same file twice creates nothing new: the second run reports every switch as
*unchanged*.

## CSV format

```csv
name,hostname,management_ip,model,aos_version,site,role,ssh_port,enabled,credential
R-BY-NET-SW-1,sw01,172.17.2.10,OS6360,8.10R1,Main,access,22,true,switch-readonly
R-BY-NET-SW-2,sw02,172.17.2.11,OS6450,6.7.1,Main,access,22,true,switch-readonly
```

UTF-8 (a BOM is accepted), comma-separated (semicolon files from spreadsheet programs are
detected), header row required, column names are case-insensitive.

| Column | Required | Rules |
|---|:-:|---|
| `name` | ✔ | 1–128 characters: letters, digits, `.`, `_`, `-`, spaces; starts with a letter or digit; unique (case-insensitive) |
| `management_ip` | ✔ | IPv4 or IPv6 address the tool connects to; not 0.0.0.0/multicast/broadcast; unique together with `ssh_port` |
| `model` | ✔ | OmniSwitch model, e.g. `OS6360`, `OS6860E-P24` |
| `aos_version` | ✔ | e.g. `8.10R1`, `8.9.221.R03`, `6.7.1`; model + version must match a supported command profile ([ALCATEL_COMMAND_PROFILES.md](ALCATEL_COMMAND_PROFILES.md)), otherwise the row is refused |
| `hostname` | | DNS name (letters, digits, `-`, `.`), unique when set |
| `site`, `location` | | ≤ 128 characters of text |
| `description` | | ≤ 255 characters of text |
| `role` | | `access`, `distribution`, `core` or `unknown` (default). **MAC operators can only restart devices on `access` switches.** |
| `ssh_port` | | 1–65535, default 22 |
| `enabled` | | `true/false`, `yes/no`, `1/0`; default true |
| `credential` | | **name** of an SSH credential created under *Settings → Credentials* |
| `uplink_ports` | | ports separated by `;` or spaces, e.g. `1/1/49;1/1/50` — always treated as uplinks |
| `status`, `created_at`, `updated_at` | | accepted and ignored (present in exports) |

Text values must not start with `=`, `+`, `-` or `@` (spreadsheet formulas), must not contain
control characters (line breaks, tabs), and may only use letters of any language, digits, spaces
and `. , : / ( ) # ' & + -`.

**Never put passwords in an import file.** Columns such as `password`, `secret`, `token`, `key`,
`enable_password`, `community` or anything ending in `_password` make the whole file fail with an
explanation. Any other unknown column also rejects the file.

## JSON format

A list of objects, or `{"switches": [ ... ]}` (the export format), with the same fields as the
CSV columns. JSON can additionally carry the MAC-operator location labels:

```json
{"switches": [
  {"name": "R-BY-NET-SW-1", "hostname": "sw01", "management_ip": "172.17.2.10",
   "model": "OS6360", "aos_version": "8.10R1", "site": "Main", "role": "access",
   "ssh_port": 22, "enabled": true, "credential": "switch-readonly",
   "uplink_ports": ["1/1/49", "1/1/50"],
   "port_locations": {"1/1/5": "Building A - Floor 2 - Office 204"}}
]}
```

## What is reported

| Status | Meaning |
|---|---|
| *valid / new* | will be created |
| *valid / exists, differs* | the switch exists with different values (listed); changed only with *Update* |
| *valid / unchanged* | identical to the inventory — nothing to do |
| *invalid* | one or more errors (listed); never imported |
| *duplicate* | identical to an earlier line of the file; skipped |
| *warning* | imported, but check it (no credential referenced, role `unknown`, loopback address …) |

After the import each row shows *imported, updated, unchanged, skipped, failed* or *not
processed* (cancelled / stopped).

## Export

*Export CSV* / *Export JSON* (`GET /api/switches/export?format=csv|json`) download the whole
inventory: `name, hostname, management_ip, ssh_port, model, aos_version, site, location,
description, role, enabled, credential, uplink_ports, status, created_at, updated_at` (JSON also
`port_locations`).

Never exported, even for administrators: passwords, the encrypted password, SSH host keys,
private keys, tokens, TLS keys. The credential appears by **name** only. CSV cells that could be
read as formulas are prefixed with `'`. An export can be imported again unchanged (round trip).
Exports are audited (`SWITCH_EXPORT`) and limited to 10 per minute per administrator and 20 000
switches.

## After an import

1. *Switches → switch → Fetch host key* → compare the fingerprint → *Trust* (for each new switch).
2. *Test SSH connection*, then the lab verification of new model families / AOS versions
   ([DEPLOYMENT.md § Production enablement](DEPLOYMENT.md#5-production-enablement)).
3. For MAC operators: set the switch role to `access` where appropriate and add *Device locations
   per port* (or import them with JSON `port_locations`).

Measured on PostgreSQL 16 (Docker Desktop on Windows): validation of 5000 rows 0.64 s; import of
1000 rows 9.1 s and of 5000 rows 55.7 s (about 10 ms per row, independent of the inventory size);
re-validation of 1000 unchanged switches 0.4 s; export of 1000 switches 70–150 ms; backend
memory below 100 MB during imports.
