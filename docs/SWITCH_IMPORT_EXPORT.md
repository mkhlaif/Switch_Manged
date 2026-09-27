# Switch import and export

Administrators can add or update many switches at once from a CSV or JSON file, and export the
inventory. *Switches → Import / Export CSV / Export JSON* (the buttons are only shown to
administrators; the API refuses every other role).

A row says **how to reach** a switch: name, management IP, SSH port, the *name* of an SSH
credential and — ideally — the SSH host-key fingerprint read on the switch console. **What the
switch is** (vendor, model, AOS version) is never taken from the file: it is discovered
automatically after the import ([DISCOVERY.md](DISCOVERY.md)). A model / AOS version column is
optional **expected metadata** that discovery compares with the device.

## Workflow

```
Upload → Validation (server) → Preview → Confirm (mode) → Import (one transaction) → Result
      → automatic discovery of the imported switches
```

1. **Upload** a `.csv` or `.json` file (max. 5 MB / 5000 switches). Templates: *CSV template*,
   *JSON template* in the dialog (`GET /api/switches/import/template?format=csv|json`).
2. **Validation and preview.** Nothing is written yet. The preview shows *Total, Valid, Invalid,
   Duplicates, Warnings, New, Existing changed, Unchanged* and every row with its errors and
   warnings. *Download error report* gives the same as a CSV file.
3. **Confirm.** Choose what happens to switches that already exist with different values:
   - **Skip — do not change them** (default): they are reported as *skipped*;
   - **Update them with the file's values**: they are changed. A changed management address or
     SSH port clears the trusted host key and resets the switch to *not discovered* (it may be
     another device).

   and the **mode**:
   - **All or nothing** (`atomic`, default): the file must be completely valid (identical
     duplicate lines may be skipped). Every row is applied in **one database transaction**; any
     failure — a name or address taken meanwhile, the timeout, a cancellation — rolls the whole
     import back and the inventory is unchanged.
   - **Row by row** (`per_row`, explicit choice): invalid / duplicate rows are skipped (you must
     tick *Skip the … rows*) and each valid row is written in its own transaction; a row that
     fails is reported as *failed* without affecting the others.

   The preview expires after 30 minutes; only the administrator who uploaded it can confirm it;
   only one import runs at a time.
4. **Import** runs in the background; every row is re-checked against the current inventory.
   *Cancel import* stops after the current batch (atomic: everything is rolled back; row by row:
   rows already imported stay). A job stops after 15 minutes. If the application restarts during
   an import, the job is marked *interrupted*.
5. **Result**: *Imported, Updated, Unchanged, Skipped, Failed* (atomic failures show every row as
   *rolled back*), plus an audit entry (`SWITCH_IMPORT`) listing the created/updated switches.
6. **Automatic discovery** starts (a background discovery job) for the created / updated switches
   whose host key can be trusted without guessing: a fingerprint in the file (the key is trusted
   only if the switch presents exactly that fingerprint) or a key already enrolled. Other switches
   are discovered after an administrator trusts their host key on the switch page.

Importing the same file twice creates nothing new: the second run reports every switch as
*unchanged*.

## CSV format

```csv
name,hostname,management_ip,ssh_port,credential_reference,ssh_host_key_fingerprint,site,role,environment,enabled,expected_model,expected_aos_version
R-BY-NET-SW-1,sw01,172.17.2.10,22,switch-readonly,SHA256:3kL…,Main,access,production,true,,
R-BY-NET-SW-2,sw02,172.17.2.11,22,switch-readonly,,Main,access,production,true,OS6450,6.7.1
```

UTF-8 (a BOM is accepted), comma-separated (semicolon files from spreadsheet programs are
detected), header row required, column names are case-insensitive.

| Column | Required | Rules |
|---|:-:|---|
| `name` | ✔ | 1–128 characters: letters, digits, `.`, `_`, `-`, spaces; starts with a letter or digit; unique (case-insensitive) |
| `management_ip` | ✔ | IPv4 or IPv6 address the tool connects to; not 0.0.0.0/multicast/broadcast; unique together with `ssh_port` |
| `credential_reference` (alias `credential`) | | **name** of an SSH credential created under *Settings → Credentials* |
| `ssh_host_key_fingerprint` | | OpenSSH SHA256 fingerprint (`SHA256:` + 43 base64 characters) read on the switch console. Lets discovery start without anyone trusting an unverified key. Refused if it contradicts a key already trusted for that switch |
| `ssh_port` | | 1–65535, default 22 |
| `expected_model` (alias `model`) | | optional expected metadata, e.g. `OS6360`, `OS6860E-P24` — compared with the discovered model family |
| `expected_aos_version` (alias `aos_version`) | | optional expected metadata, e.g. `8.10R1`, `6.7.1` — compared on major.minor |
| `environment` | | `production` (default) or `lab`. Production switches need PRODUCTION_VERIFIED command profiles for any state change |
| `hostname` | | DNS name (letters, digits, `-`, `.`), unique when set |
| `site`, `location` | | ≤ 128 characters of text |
| `description` | | ≤ 255 characters of text |
| `role` | | `access`, `distribution`, `core` or `unknown` (default). **MAC operators can only restart devices on `access` switches.** |
| `enabled` | | `true/false`, `yes/no`, `1/0`; default true |
| `uplink_ports` | | ports separated by `;` or spaces, e.g. `1/1/49;1/1/50` — always treated as uplinks |
| `vendor`, `discovered_model`, `discovered_aos_version`, `discovery_status`, `status`, `created_at`, `updated_at` | | accepted and ignored (present in exports) |

A column and its alias together (e.g. `model` and `expected_model`) reject the file. An expected
model / version that no command profile covers is a **warning**, not an error: the switch will be
identified but no operation will be available for it.

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
   "ssh_port": 22, "credential_reference": "switch-readonly",
   "ssh_host_key_fingerprint": "SHA256:…", "site": "Main", "role": "access",
   "environment": "production", "enabled": true,
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
| *invalid* | one or more errors (listed); never imported (and blocks an atomic import) |
| *duplicate* | identical to an earlier line of the file; skipped |
| *warning* | imported, but check it (no credential, no fingerprint, role `unknown`, no profile covers the expected model …) |

After the import each row shows *imported, updated, unchanged, skipped, failed, rolled back* or
*not processed* (cancelled / stopped).

## Export

*Export CSV* / *Export JSON* (`GET /api/switches/export?format=csv|json`) download the whole
inventory: `name, hostname, management_ip, ssh_port, credential_reference,
ssh_host_key_fingerprint, expected_model, expected_aos_version, site, location, description, role,
environment, enabled, uplink_ports`, and — for information, ignored on import — `vendor,
discovered_model, discovered_aos_version, discovery_status, status, created_at, updated_at` (JSON
also `port_locations`).

Never exported, even for administrators: passwords, the encrypted password, SSH host keys,
private keys, tokens, TLS keys. The credential appears by **name** only; the host key only as its
public **fingerprint** (not a secret), so that the file can be re-imported elsewhere without
trusting an unverified key. CSV cells that could be read as formulas are prefixed with `'`. An
export imported again reports every switch as *unchanged* (round trip, tested). Exports are
audited (`SWITCH_EXPORT`) and limited to 10 per minute per administrator and 20 000 switches.

## After an import

1. Switches without a fingerprint: *Switches → switch → Fetch host key* → compare the fingerprint
   → *Trust*. Discovery then starts automatically.
2. Check *Switches* → *Identity*: every switch should be *Discovered*. *Identity mismatch* means
   the device differs from the expected metadata — review it on the switch page.
3. Verify new model families / AOS versions ([DEPLOYMENT.md § Production
   enablement](DEPLOYMENT.md#5-production-enablement)).
4. For MAC operators: set the switch role to `access` where appropriate and add *Device locations
   per port* (or import them with JSON `port_locations`).

Measured on PostgreSQL 16 (Docker Desktop on Windows, previous release, per-row mode): validation
of 5000 rows 0.64 s; import of 1000 rows 9.1 s and of 5000 rows 55.7 s (about 10 ms per row);
re-validation of 1000 unchanged switches 0.4 s; export of 1000 switches 70–150 ms; backend memory
below 100 MB during imports. The atomic mode writes all rows in one transaction (fewer commits).
