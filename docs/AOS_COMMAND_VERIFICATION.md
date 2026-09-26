# AOS Command Verification

This document records **which Alcatel-Lucent Enterprise OmniSwitch CLI commands this tool uses, why, and
how each one was verified**. The executable form of this document is split in two places:

- The **authoritative allowlist**: every template literal and bounce pair that can ever be sent,
  plus the discovery profile. It lives in
  [`backend/app/security/policy.py`](../backend/app/security/policy.py) and is enforced by the
  Command Safety Firewall (see [SECURITY_FIREWALL.md](SECURITY_FIREWALL.md)).
- The **command profiles**, which select templates from that allowlist per AOS generation, with
  verification levels. They live in
  [`backend/app/services/alcatel/profiles.py`](../backend/app/services/alcatel/profiles.py).

If you change this document, change those files too.

## Sources

| Ref | Document | Covers |
|-----|----------|--------|
| **[A8]** | *OmniSwitch AOS Release 8 CLI Reference Guide*, 8.10R1, July 2024 (ALE, part of `omniswitch-aos-release-810r1-cli-reference-user-guide-rev-a-en.pdf`) | OS6360, OS6465, OS6560, OS6570M, OS6860(N), OS6865, OS6900, OS9900 |
| **[A6]** | *OmniSwitch AOS Release 6250/6350/6450 CLI Reference Guide*, Part No. 033071-00 Rev B, June 2016 (release 6.7.1) | OS6250, OS6350, OS6450 |

Page numbers below refer to those guides.

## Verification levels

Every command in a profile carries one of these levels:

| Level | Meaning | Allowed use |
|-------|---------|-------------|
| `doc_example` | The exact command form appears as an example in the guide. | Read-only: enabled. Write: needs admin lab approval. |
| `doc_syntax` | Built from the guide's syntax definition; no literal example of this exact form. | Read-only: enabled. Write: needs admin lab approval. |
| `unverified` | Could not be verified against an ALE guide. | **Disabled.** An admin must lab-validate it and mark it verified. |

Every command also records **who verified it and when** (`verified_by`, `verified_at`). For the
built-in profiles that is the documentation review of this project ("ALE CLI Reference Guide
(documentation review)", 2026-09-25). That is **not** a lab test.

### Lab verification per model family and AOS version

Documentation alone never authorizes a command on a production switch. An administrator records
**lab verification** in the `command_verifications` table, per profile, **capability**, **model
family** (`OS6860`, `OS6360`, …, or `*` for every supported model of the profile) and **AOS
version prefix** (`8.10`, `6.7`):

| Capability | Covers | How it is verified |
|---|---|---|
| `READ` | every read-only command of the profile | *Settings → Command profiles → Run read-only verification*: each command runs once against a lab switch, its output must match the documented contract and parse. `vlan_linkagg` needs a link aggregate and is reported as *not exercised*. |
| `INTERFACE_ADMIN_STATE`, `INTERFACE_ADMIN`, `LANPOWER_ADMIN_STATE`, `LANPOWER_STOP_START` | one restart strategy | manual: dry run, then a supervised restart of a lab access port, then *Record* |

Without a matching record:

- read commands are refused on real (SSH) switches with *"Command profile unavailable for this
  switch model/version"* (the requirement can be switched off in *Safety Controls → Limits*, which
  is audited; the lab simulator is exempt);
- restart strategies are available as dry run only.

### Supported models and versions

A profile applies only to the **exact model families and AOS versions it lists**. Anything else
fails closed with *"Command profile unavailable for this switch model/version"*.

| Profile | Model families | AOS versions | Status |
|---|---|---|---|
| `AOS8` | OS6360, OS6465, OS6560, OS6570M, OS6860, OS6860N, OS6865, OS6900, OS9900 | 8.x | enabled |
| `AOS6` | OS6250, OS6350, OS6450 | 6.6, 6.7 | enabled |
| `AOS7` | OS10K, OS6900 | 7.x | **disabled** (unverified) |

The model family is taken from the model string: `OS6860E-P24` → `OS6860`, `OS6860N-P48M` →
`OS6860N`, `OS6570M-12` → `OS6570M`.

### Output contracts

Every read command has a documented output contract (parser + expected-output pattern). An answer
that does not match is treated as **UNEXPECTED CLI OUTPUT**: the result is discarded (never
guessed), an alert is raised and the circuit breaker counts it. State-changing commands must print
nothing (AOS prints nothing on success).

| Command key | Parser | Expected output contains |
|---|---|---|
| `mac_lookup`, `mac_on_port` | `mac_table_parser` | `Mac Address` or `Total number of Valid MAC` |
| `vlan_port`, `vlan_linkagg` | `vlan_port_parser` | a `vlan type status` header line |
| `port_detail` | `port_status_parser` | `Operational Status` |
| `port_admin` | `port_admin_parser` | `Admin Link` header |
| `lldp_port` | `lldp_parser` | `Remote LLDP` (empty output allowed: no neighbor) |
| `system_info` (discovery) | system parser | `Description:` |

---

## Corrections to the original specification

The original requirements supplied several example commands. They were checked against the guides:

| Supplied example | Finding | Correct form |
|------------------|---------|--------------|
| `interfaces 1/1/26 admin down` / `admin up` | **Invalid on every AOS generation.** `admin {up\|down}` is AOS 6 syntax, where ports are `slot/port` (2-part). AOS 8 uses `admin-state {enable\|disable}` and the `port` keyword. | AOS 6: `interfaces 1/26 admin down` / `interfaces 1/26 admin up` [A6 p.23-15]<br>AOS 8: `interfaces port 1/1/26 admin-state disable` / `... enable` [A8 p.1-3] |
| `lanpower stop 1/1/26` / `lanpower start 1/1/26` | AOS 6 only, and AOS 6 uses 2-part ports. | AOS 6: `lanpower stop 1/26` / `lanpower start 1/26` [A6 p.4-2, p.4-4] |
| `lanpower port 1/1/26 admin-state disable/enable` | Valid on **AOS 8 only** (introduced 8.1.1). Not supported on OS6570M or OS6900 per the platform table. | as supplied [A8 p.2-4] |
| `show vlan members port` | **AOS 8 only.** | AOS 6: `show vlan port 1/26` [A6 p.25-15] |
| `show mac-address-table` | **AOS 6 only.** AOS 8 replaced it with `show mac-learning`. | AOS 8: `show mac-learning mac-address <mac>` [A8 p.4-41] |
| "OmniSwitch 6450 / AOS 8.x / 8.10.x, port 1/1/26" | **Not a real combination.** The OS6450 runs AOS 6.x only [A6 title page: "release 6.7.1 of the OmniSwitch 6250/6350/6450"], and AOS 6 uses `slot/port` numbering (for example `1/26`). | Use AOS 6 profile and `1/26`-style ports for OS6450. |
| OS6350 listed as an AOS 8 platform | **Incorrect.** The OS6350 is covered by the AOS 6.7.1 guide [A6] together with OS6250/OS6450. | `AOS6` profile. |
| OS6360 / OS6465 listed as AOS 6 platforms | **Incorrect.** Both are AOS 8 platforms [A8 platform list]. | `AOS8` profile, `chassis/slot/port` numbering. |

### Link bounce vs. PoE power cycle are different operations

`interfaces … admin …` bounces the **Ethernet link**. `lanpower …` switches **PoE power** off and on. A
PoE cycle reboots a powered device (phone, AP, camera) but does nothing to a non-PoE endpoint. A link
bounce drops the link but may leave PoE power on. They are **not interchangeable**. The tool exposes them as
separate methods, and each has its own strategy:

| Strategy | Profile | Commands | Source |
|----------|---------|----------|--------|
| `INTERFACE_ADMIN` | AOS 6 | `interfaces {port} admin down` then `interfaces {port} admin up` | [A6 p.23-15] |
| `INTERFACE_ADMIN_STATE` | AOS 8 | `interfaces port {port} admin-state disable` then `... enable` | [A8 p.1-3] |
| `LANPOWER_STOP_START` | AOS 6 | `lanpower stop {port}` then `lanpower start {port}` | [A6 p.4-2, p.4-4] |
| `LANPOWER_ADMIN_STATE` | AOS 8 | `lanpower port {port} admin-state disable` then `... enable` | [A8 p.2-4] |

---

## AOS 8 profile (`AOS8`), verified against [A8]

MAC addresses are passed in colon form `xx:xx:xx:xx:xx:xx` (per the guide: "A MAC Address (for example,
00:00:39:59:f1:0c)"). Ports are `chassis/slot/port`, with an optional breakout suffix (`1/1/1A`). A
link aggregate appears in MAC output as `0/<agg_id>`.

| Purpose | Command | Level | Ref |
|---------|---------|-------|-----|
| Identify switch / version (DISCOVERY_PROFILE) | `show system` | doc_example | p.61-56 (`Description: Alcatel-Lucent Enterprise OS6900-X40 8.3.1.313.R01 GA`) |
| MAC lookup (filtered) | `show mac-learning mac-address {mac}` | doc_syntax | p.4-41: `show mac-learning [...] [mac-address mac_address]` |
| MACs on port (count) | `show mac-learning port {port}` | doc_syntax | p.4-41: `[port chassis/slot/port]` |
| VLANs on port | `show vlan members port {port}` | doc_example | p.5-13: `-> show vlan members port 2/1/2` |
| VLANs on link agg | `show vlan members linkagg {agg}` | doc_syntax | p.5-13 |
| Port detail (oper status, speed, duplex, errors) | `show interfaces port {port}` | doc_example | p.1-59: `-> show interfaces port 1/1/2` |
| Port admin status + alias | `show interfaces port {port} alias` | doc_example | p.1-63: `-> show interfaces port 1/1/2 alias` |
| LLDP neighbor | `show lldp port {port} remote-system` | doc_syntax | p.18-63: `show lldp [...] [port chassis/slot/port] remote-system` |

**VLAN membership types** (p.5-13): `untagged`, `tagged`, `dynamic` (MVRP), `mirror`, `spb`,
`UNP Untagged`, `UNP QTagged`. **Status**: `forwarding`, `blocking`, `inactive`, and others.

**Pagination:** AOS 8's `more` command is a file/pipe pager (`more filename`, `write terminal | more`)
[A8 p.63-38]. Normal `show` output is not paginated by default. The SSH engine still detects and answers
pager prompts defensively.

## AOS 6 profile (`AOS6`), verified against [A6]

MAC addresses are colon form. Ports are `slot/port` (`1/26`). A link aggregate appears in MAC output as
`0/<agg_id>`. The guide's own example output shows interface values with an embedded space (`8/ 1`). The
parser handles that.

| Purpose | Command | Level | Ref |
|---------|---------|-------|-----|
| Identify switch / version (DISCOVERY_PROFILE) | `show system` | doc_example | p.2-31 (`Description: Alcatel-Lucent OS6250-24 6.6.2.63.R02 ...`) |
| MAC lookup (filtered) | `show mac-address-table {mac}` | doc_syntax | p.20-10: `show mac-address-table [permanent \| learned] [mac_address] ...` |
| MACs on port (count) | `show mac-address-table {port}` | doc_syntax | p.20-10: `[slot slot \| slot/port]` (positional `slot/port`; the guide's own example `show mac-address-table 10-15` confirms positional filters). **Lab-validate.** |
| VLANs on port | `show vlan port {port}` | doc_example | p.25-15: `-> show vlan port 3/2` |
| VLANs on link agg | `show vlan port {agg}` | doc_syntax | p.25-15: `show vlan [vid] port [slot/port \| link_agg]` |
| Port detail | `show interfaces {port}` | doc_example | p.23-49: `-> show interfaces 1/2` |
| Port admin status + alias | `show interfaces {port} port` | doc_example | p.23-79: `-> show interfaces 1/1 port` |
| LLDP neighbor | `show lldp {port} remote-system` | doc_syntax | p.13-47: `show lldp [slot/port \| slot] remote-system` |

**VLAN membership types** (p.25-15): `default` (untagged/native), `qtagged` (802.1Q tagged), `mobile`,
`mirror`, `dynamic` (GVRP), `vstkQtag`. **Status**: `inactive`, `forwarding`, `blocking`, `filtering`.

**Pagination** (p.6-39/6-40): "more mode" is **disabled by default**. When enabled, the pager prompt is
`More? [next screen <sp>, next line <cr>, filter pattern </>, quit </>]`. The SSH engine answers it with a
space. The tool does **not** send `no more` because it never sends anything that is not strictly
needed.

Other AOS 6 platforms (OS6400, OS6850(E), OS6855, OS9000E on 6.4.x) use a similar grammar in their own
guides, but those guides were **not** reviewed here. The `AOS6` profile is therefore limited to OS6250,
OS6350 and OS6450 on 6.6/6.7; any other AOS 6 model fails closed until a reviewed profile is added.

## AOS 7 profile (`AOS7`)

AOS 7.x (OS10K, early OS6900) is the ancestor of AOS 8. The [A8] release history lists many of the above
commands as "introduced in 7.1.1". However, these commands were **not verified against an AOS 7 guide**.
The `AOS7` profile ships with every command at `unverified`, so it is **disabled**. An administrator must
lab-validate each command and mark it verified before AOS 7 switches can be searched.

## Error detection

AOS reports CLI errors on a line beginning with `ERROR:` (for example `ERROR: Invalid entry: "mac-learning"`).
The SSH engine treats any such line as a command failure and reports it as *"The selected command profile may
not be compatible with this AOS version. No configuration changes were made."*

## Real-switch validation checklist (Phase 7)

Run these in order against **one lab switch per model/AOS version** you operate, and record the results:

1. `Switches → Test SSH connection` (runs `show system` only).
2. `Switches → Detect model/version` and confirm the profile chosen.
3. MAC search for a known endpoint MAC. Confirm the switch, port and VLAN.
4. Open the result and confirm the VLAN table, port status and LLDP against the switch CLI by hand.
5. Confirm the MAC count on the port. **This validates the AOS 6 `show mac-address-table {port}` form.**
6. As admin, run the **read-only verification** (`Settings → Command profiles`) on the lab switch and
   record `READ` for that model family and version.
7. With **dry run enabled**, prepare a port restart on a lab access port. Check the exact command sequence shown.
8. Switch to MAINTENANCE mode, disable dry run, restart the lab access port, and confirm post-restart
   verification (port UP, MAC relearned, VLAN, change report).
9. Record the strategy's lab verification for that model family and AOS version prefix.
10. Re-enable dry run and return to NORMAL mode until you are ready for production.
