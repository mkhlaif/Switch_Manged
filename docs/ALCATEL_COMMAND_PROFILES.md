# Alcatel command profiles

Every CLI command the application can send, per model and AOS version. Generated from
`backend/app/services/alcatel/profiles.py` and `backend/app/security/policy.py` (the single
authoritative allowlist). Sources, page references and the corrections made to the original
requirements: [AOS_COMMAND_VERIFICATION.md](AOS_COMMAND_VERIFICATION.md).

## Verification status — read this first

| Level | Meaning |
|---|---|
| **Documentation-verified** (`doc_example` / `doc_syntax`) | The exact command (or its syntax definition) is in the official ALE CLI Reference Guide. Verified on 2026-09-25 against AOS 8.10R1 [A8] and AOS 6.7.1 [A6]. **Not executed on real hardware by this project.** |
| **Lab-verified** | An administrator ran the command on a lab switch of that model family and AOS version and recorded it in the application (*Settings → Command profiles*). Required before production use; the application enforces it for real switches. |
| **UNVERIFIED** | Not verifiable against a guide. Disabled — never used. |

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

| Operation | Key | Command | R/W | Expected output (contract) | Parser | Level | Source |
|---|---|---|---|---|---|---|---|
| discovery | `system_info` | `show system` | read | contains `Description:` | system parser | doc_example | [A8] p.61-56 |
| SEARCH_MAC | `mac_lookup` | `show mac-learning mac-address {mac}` | read | `Mac Address` / `Total number of Valid MAC` | mac_table_parser | doc_syntax | [A8] p.4-41 |
| GET_PORT_MACS | `mac_on_port` | `show mac-learning port {port}` | read | same as above | mac_table_parser | doc_syntax | [A8] p.4-41 |
| GET_PORT_VLAN | `vlan_port` | `show vlan members port {port}` | read | header `vlan type status` | vlan_port_parser | doc_example | [A8] p.5-13 |
| GET_PORT_VLAN | `vlan_linkagg` | `show vlan members linkagg {agg}` | read | header `vlan type status` | vlan_port_parser | doc_syntax | [A8] p.5-13 |
| GET_PORT_STATUS | `port_detail` | `show interfaces port {port}` | read | `Operational Status` | port_status_parser | doc_example | [A8] p.1-59 |
| GET_PORT_STATUS | `port_admin` | `show interfaces port {port} alias` | read | header `Admin Link` | port_admin_parser | doc_example | [A8] p.1-63 |
| GET_LLDP | `lldp_port` | `show lldp port {port} remote-system` | read | `Remote LLDP` (empty = no neighbour) | lldp_parser | doc_syntax | [A8] p.18-63 |
| RESTART_PORT (link bounce) | `INTERFACE_ADMIN_STATE` | `interfaces port {port} admin-state disable` → `… enable` | **write** | no output | — | doc_syntax | [A8] p.1-3 |
| RESTART_PORT (PoE cycle) | `LANPOWER_ADMIN_STATE` | `lanpower port {port} admin-state disable` → `… enable` | **write** | no output | — | doc_example | [A8] p.2-4 — not on OS6570M, OS6900; PoE models only |

## AOS 6 (`AOS6`)

| Operation | Key | Command | R/W | Expected output (contract) | Parser | Level | Source |
|---|---|---|---|---|---|---|---|
| discovery | `system_info` | `show system` | read | contains `Description:` | system parser | doc_example | [A6] p.2-31 |
| SEARCH_MAC | `mac_lookup` | `show mac-address-table {mac}` | read | `Mac Address` / `Total number of Valid MAC` | mac_table_parser | doc_syntax | [A6] p.20-10 |
| GET_PORT_MACS | `mac_on_port` | `show mac-address-table {port}` | read | same as above | mac_table_parser | doc_syntax — **no literal example in the guide; lab-verify** | [A6] p.20-10 |
| GET_PORT_VLAN | `vlan_port` | `show vlan port {port}` | read | header `vlan type status` | vlan_port_parser | doc_example | [A6] p.25-15 |
| GET_PORT_VLAN | `vlan_linkagg` | `show vlan port {agg}` | read | header `vlan type status` | vlan_port_parser | doc_syntax | [A6] p.25-15 |
| GET_PORT_STATUS | `port_detail` | `show interfaces {port}` | read | `Operational Status` | port_status_parser | doc_example | [A6] p.23-49 |
| GET_PORT_STATUS | `port_admin` | `show interfaces {port} port` | read | header `Admin Link` | port_admin_parser | doc_example | [A6] p.23-79 |
| GET_LLDP | `lldp_port` | `show lldp {port} remote-system` | read | `Remote LLDP` (empty = no neighbour) | lldp_parser | doc_syntax | [A6] p.13-47 |
| RESTART_PORT (link bounce) | `INTERFACE_ADMIN` | `interfaces {port} admin down` → `… admin up` | **write** | no output | — | doc_example | [A6] p.23-15 |
| RESTART_PORT (PoE cycle) | `LANPOWER_STOP_START` | `lanpower stop {port}` → `lanpower start {port}` | **write** | no output | — | doc_example | [A6] p.4-2, p.4-4 — PoE models only |

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
  selected switch and checks each output against its contract; *Record* stores the evidence for
  that model family and AOS version. (`vlan_linkagg` needs a link aggregate and is reported as
  *not exercised*.)
- **Restart strategies** — recorded manually after the procedure in
  [DEPLOYMENT.md](DEPLOYMENT.md#5-production-enablement).
