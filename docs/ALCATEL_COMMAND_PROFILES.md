# Alcatel command profiles

Every CLI command the application can send, per model and AOS version. Generated from
`backend/app/services/alcatel/profiles.py` and `backend/app/security/policy.py` (the single
authoritative allowlist). Sources, page references and the corrections made to the original
requirements: [AOS_COMMAND_VERIFICATION.md](AOS_COMMAND_VERIFICATION.md).

## Verification status — read this first

Three separate things are tracked for every command. None of them can be set by the
application on its own; nothing is ever promoted automatically.

**1. Command source** (fixed in code, per command):

| Level | Meaning |
|---|---|
| **Documentation-verified** (`doc_example` / `doc_syntax`) | The exact command (or its syntax definition) is in the official ALE CLI Reference Guide. Verified on 2026-09-25 against AOS 8.10R1 [A8] and AOS 6.7.1 [A6]. **Not executed on real hardware by this project.** |
| **UNVERIFIED** | Not verifiable against a guide. Disabled — never used. |

Commands never come from anything else: no AI output, blog, forum or guess.

**2. Evidence level** (how far a command has been proven):

| Evidence | What it proves | Where it comes from |
|---|---|---|
| `SIMULATED` | Runs against the in-process simulator | Automated tests; simulator verification runs (never recorded as verification) |
| `FIXTURE_TESTED` | Parsers and output contracts accept the documented output | Tests on `backend/tests/fixtures/aos8`, `aos6` — every built-in command |
| `LAB_VERIFIED` | Executed on a real lab switch of that model family / AOS version | Verification record created by an administrator |
| `PRODUCTION_VERIFIED` | Additionally proven by a recorded run on a real (SSH) switch | Promotion of a record; the server checks the evidence (below) |

Status of this project on 2026-09-26: every built-in command is **FIXTURE_TESTED** and
SIMULATED. **No command is LAB_VERIFIED or PRODUCTION_VERIFIED by this project** — no real
switch was available.

**3. Profile state** of each capability (READ = all read-only commands, or one restart strategy)
per exact **model family and AOS version (major.minor at least)**:

| State | Effect |
|---|---|
| `DRAFT` (no record) | Not usable on real switches. |
| `LAB_VERIFIED` | Reads on real switches; restarts on switches marked `environment = lab` (and on the simulator). |
| `PRODUCTION_VERIFIED` | Restarts on production switches. Promotion requires recorded evidence: for READ a passed read-only verification run on a real SSH switch of that family / version; for a restart strategy a live restart on such a switch whose post-restart verification succeeded. |
| `BLOCKED` | Refused everywhere; wins over any other record. Must be lifted explicitly (with a reason) before it can be verified again. |
| `DEPRECATED` | Retired (a revoked record); kept for history, ignored. Re-verifying revives it. |

Every transition is audited (`PROFILE_STATE_CHANGE`, reason mandatory). Legacy records for
"all models" (`*`) or a single-component version such as `8` are never production evidence:
`*` counts as LAB_VERIFIED at most, `8` does not count at all; new records must name one model
family and at least `major.minor`.

## Command source per command family

| Command family | Source | Evidence in this project |
|---|---|---|
| Discovery (`show system`) | [A8] p.61-56, [A6] p.2-31 (Discovery Profile Registry) | FIXTURE_TESTED, SIMULATED |
| MAC lookup, MACs on a port | [A8] p.4-41, [A6] p.20-10 | FIXTURE_TESTED, SIMULATED |
| VLAN membership | [A8] p.5-13, [A6] p.25-15 | FIXTURE_TESTED, SIMULATED |
| Port status / admin state | [A8] p.1-59, p.1-63, [A6] p.23-49, p.23-79 | FIXTURE_TESTED, SIMULATED |
| LLDP neighbours | [A8] p.18-63, [A6] p.13-47 | FIXTURE_TESTED, SIMULATED |
| Link bounce (restart) | [A8] p.1-3, [A6] p.23-15 | SIMULATED only (write commands print nothing) |
| PoE power cycle (restart) | [A8] p.2-4, [A6] p.4-2 / p.4-4 | SIMULATED only |
| Serial number / chassis inventory | — | **not implemented**: no command verified for it; not collected |

## Discovery Profile Registry

Before a switch's AOS generation is known, the only command that may run is `show system`
(documented and read-only on both generations). The registry
(`backend/app/services/discovery/registry.py`, visible under *Settings → Command profiles*) holds
for each generation: vendor, model families, AOS versions, command, expected output patterns,
parser, safety class, sources, verification status and fixtures.

| Entry | Identifies | Expected output |
|---|---|---|
| `ALE_AOS8_SHOW_SYSTEM` | ALE AOS 8 families (table below), AOS `8.` | `Description: Alcatel-Lucent[ Enterprise] OS…` **and** `Object ID: 1.3.6.1.4.1.6486.…` |
| `ALE_AOS6_SHOW_SYSTEM` | ALE AOS 6 families, AOS 6.6 / 6.7 | same |

The vendor is ALE only when **both** the description and the ALE enterprise OID agree. The
version must have the exact AOS format (e.g. `8.9.221.R03`, `6.7.2.191.R08`). Anything else is
`DISCOVERY_FAILED` and no other command is sent. AOS 7 (OS10K, OS6900 on 7.x) has no registry
entry and no documented output fixture: such a switch ends `DISCOVERY_FAILED`. See
[DISCOVERY.md](DISCOVERY.md).

## Model / version → profile

| Model family | AOS | Profile | Port format | Status |
|---|---|---|---|---|
| OS6360, OS6465, OS6560, OS6570M, OS6860, OS6860N, OS6865, OS6900, OS9900 | 8.x | `AOS8` | `chassis/slot/port`, e.g. `1/1/24` | documentation-verified against 8.10R1; other 8.x releases need lab verification |
| OS6250, OS6350, OS6450 | 6.6, 6.7 | `AOS6` | `slot/port`, e.g. `1/24` | documentation-verified against 6.7.1 |
| OS10K, OS6900 | 7.x | `AOS7` | — | **UNVERIFIED — disabled** |
| any other model or version | — | none | — | **unsupported — blocked** ("Command profile unavailable for this switch model/version") |

OS6350 and OS6450 are AOS 6 platforms; OS6360 and OS6465 are AOS 8 platforms. The commands are
**not interchangeable** between the two; the profile is selected by exact model family and AOS
version, never guessed.

## AOS 8 (`AOS8`)

**Applies to:** OS6360, OS6465, OS6560, OS6570M, OS6860, OS6860N, OS6865, OS6900, OS9900 on AOS 8.x (documentation reviewed: 8.10R1). Ports `chassis/slot/port`.

| Operation | Key | Command | Risk | Expected prompt | Expected output (contract) | Parser | Level | Source |
|---|---|---|---|---|---|---|---|---|
| discovery | `system_info` | `show system` | READ_ONLY | `… ->` | contains `Description:` | system parser | doc_example | [A8] p.61-56 |
| SEARCH_MAC | `mac_lookup` | `show mac-learning mac-address {mac}` | READ_ONLY | `… ->` | `Mac Address` / `Total number of Valid MAC` | mac_table_parser | doc_syntax | [A8] p.4-41 |
| GET_PORT_MACS | `mac_on_port` | `show mac-learning port {port}` | READ_ONLY | `… ->` | same as above | mac_table_parser | doc_syntax | [A8] p.4-41 |
| GET_PORT_VLAN | `vlan_port` | `show vlan members port {port}` | READ_ONLY | `… ->` | header `vlan type status` | vlan_port_parser | doc_example | [A8] p.5-13 |
| GET_PORT_VLAN | `vlan_linkagg` | `show vlan members linkagg {agg}` | READ_ONLY | `… ->` | header `vlan type status` | vlan_port_parser | doc_syntax | [A8] p.5-13 |
| GET_PORT_STATUS | `port_detail` | `show interfaces port {port}` | READ_ONLY | `… ->` | `Operational Status` | port_status_parser | doc_example | [A8] p.1-59 |
| GET_PORT_STATUS | `port_admin` | `show interfaces port {port} alias` | READ_ONLY | `… ->` | header `Admin Link` | port_admin_parser | doc_example | [A8] p.1-63 |
| GET_LLDP | `lldp_port` | `show lldp port {port} remote-system` | READ_ONLY | `… ->` | `Remote LLDP` (empty = no neighbour) | lldp_parser | doc_syntax | [A8] p.18-63 |
| RESTART_PORT (link bounce) | `INTERFACE_ADMIN_STATE` | `interfaces port {port} admin-state disable` → `… enable` | **STATE_CHANGING** | `… ->` | no output | — | doc_syntax | [A8] p.1-3 |
| RESTART_PORT (PoE cycle) | `LANPOWER_ADMIN_STATE` | `lanpower port {port} admin-state disable` → `… enable` | **STATE_CHANGING** | `… ->` | no output | — | doc_example | [A8] p.2-4 — not on OS6570M, OS6900; PoE models only |

## AOS 6 (`AOS6`)

**Applies to:** OS6250, OS6350, OS6450 on AOS 6.6 / 6.7 (documentation reviewed: 6.7.1). Ports `slot/port`.

| Operation | Key | Command | Risk | Expected prompt | Expected output (contract) | Parser | Level | Source |
|---|---|---|---|---|---|---|---|---|
| discovery | `system_info` | `show system` | READ_ONLY | `… ->` | contains `Description:` | system parser | doc_example | [A6] p.2-31 |
| SEARCH_MAC | `mac_lookup` | `show mac-address-table {mac}` | READ_ONLY | `… ->` | `Mac Address` / `Total number of Valid MAC` | mac_table_parser | doc_syntax | [A6] p.20-10 |
| GET_PORT_MACS | `mac_on_port` | `show mac-address-table {port}` | READ_ONLY | `… ->` | same as above | mac_table_parser | doc_syntax — **no literal example in the guide; lab-verify** | [A6] p.20-10 |
| GET_PORT_VLAN | `vlan_port` | `show vlan port {port}` | READ_ONLY | `… ->` | header `vlan type status` | vlan_port_parser | doc_example | [A6] p.25-15 |
| GET_PORT_VLAN | `vlan_linkagg` | `show vlan port {agg}` | READ_ONLY | `… ->` | header `vlan type status` | vlan_port_parser | doc_syntax | [A6] p.25-15 |
| GET_PORT_STATUS | `port_detail` | `show interfaces {port}` | READ_ONLY | `… ->` | `Operational Status` | port_status_parser | doc_example | [A6] p.23-49 |
| GET_PORT_STATUS | `port_admin` | `show interfaces {port} port` | READ_ONLY | `… ->` | header `Admin Link` | port_admin_parser | doc_example | [A6] p.23-79 |
| GET_LLDP | `lldp_port` | `show lldp {port} remote-system` | READ_ONLY | `… ->` | `Remote LLDP` (empty = no neighbour) | lldp_parser | doc_syntax | [A6] p.13-47 |
| RESTART_PORT (link bounce) | `INTERFACE_ADMIN` | `interfaces {port} admin down` → `… admin up` | **STATE_CHANGING** | `… ->` | no output | — | doc_example | [A6] p.23-15 |
| RESTART_PORT (PoE cycle) | `LANPOWER_STOP_START` | `lanpower stop {port}` → `lanpower start {port}` | **STATE_CHANGING** | `… ->` | no output | — | doc_example | [A6] p.4-2, p.4-4 — PoE models only |

## Expected prompt, pagers and timeouts

Every command is sent on an interactive SSH shell and is complete only when the switch prompt
returns:

- **Prompt:** must match `->` at the end of the line (AOS default `->`, or `<system name> ->`,
  e.g. `SW-ACCESS-01 ->`). The exact prompt seen after login is learned and then required for
  every later command in the session.
- **Pagers** are answered automatically: AOS 6 `More? [next screen <sp>, next line <cr>, filter
  pattern </>, quit </>]`, `--More--`, `More?`, `Press any key to continue`.
- **Errors:** any line starting with `ERROR:` makes the command fail (nothing is guessed).
- **Timeouts:** `COMMAND_TIMEOUT` per command (default 15 s), `SSH_MAX_SESSION_SECONDS` per
  session (default 300 s), at most 60 commands per session.

## How a command is used

- Parameters are validated before any connection: MAC (normalised to `xx:xx:xx:xx:xx:xx`), port
  (format of the AOS generation), link aggregate id. Anything else — including `;`, `&&`, `|`,
  newlines, `$( )`, backticks — is rejected and audited.
- An answer that does not match the expected-output contract is **discarded** ("UNEXPECTED CLI
  OUTPUT"), raises an alert and counts towards the circuit breaker. Write commands must print
  nothing.
- The *down* command is sent at most once per restart; the *up* (restore) command at most twice,
  the second time only after the port's admin state was read back.

## Explicitly blocked

Everything not in the tables above, in particular: `reload`, `reboot`, `write memory`, `copy`,
`delete`, `configure`, VLAN creation/deletion/modification, routing, spanning tree, link
aggregation/LACP, ACLs, user and password changes, firmware/boot changes, and any shell command.
The risk classifier marks these DANGEROUS and the firewall blocks them (CRITICAL security event),
even if they were somehow placed into a profile. Custom profiles can only choose among the
allowlisted templates; adding a command requires a reviewed code change.

## Lab verification in the application

*Settings → Command profiles*:

- **READ** — *Run read-only verification on a lab switch…* runs every read command once on the
  selected (discovered) switch and checks each output against its contract; *Record* stores a
  LAB_VERIFIED record for that model family and AOS version. (`vlan_linkagg` needs a link
  aggregate and is reported as *not exercised*.) A run against the simulator is SIMULATED
  evidence and cannot be recorded.
- **Restart strategies** — recorded manually (LAB_VERIFIED) after the procedure in
  [DEPLOYMENT.md](DEPLOYMENT.md#5-production-enablement).
- **Promotion** — the `⋯` menu of a record changes its state. PRODUCTION_VERIFIED is refused
  unless the evidence described above exists in the database.
- API: `POST /api/profiles/verifications` (create LAB_VERIFIED),
  `POST /api/profiles/verifications/{id}/status` (`{"status", "reason"}`),
  `DELETE /api/profiles/verifications/{id}` (= DEPRECATED).
