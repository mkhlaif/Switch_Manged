# User guide (READ_ONLY and OPERATOR)

For network staff using the technical interface. Administrators: see also
[ADMIN_GUIDE.md](ADMIN_GUIDE.md). Non-technical staff: [MAC_OPERATOR_GUIDE.md](MAC_OPERATOR_GUIDE.md).

## The safety indicator

Always visible at the top of the sidebar (at the top of the screen on phones):

| Indicator | Meaning |
|---|---|
| **● READ ONLY** | no state-changing operation is possible (NORMAL or READ_ONLY mode) |
| **● ACTIVE** | MAINTENANCE mode: authorised, fully checked restarts are possible |
| **● EMERGENCY** | only administrator emergency operations |
| **⚠ SAFE MODE** | the circuit breaker tripped; restarts blocked until an administrator resets it |
| **● STOPPED** | STOP ALL NETWORK OPERATIONS is active |

Searches and read-only views always work, whatever the indicator shows.

## MAC search

*MAC Search*: enter a MAC in any common format (`00:11:22:33:44:55`, `00-11-22-33-44-55`,
`0011.2233.4455`, `001122334455`) and choose a mode:

| Mode | What it does |
|---|---|
| **Fast** | MAC lookup only (one command per switch); ports are not analysed (classification UNKNOWN) |
| **Standard** | lookup + port status, VLANs, LLDP and MAC count of the port where the MAC was found |
| **Deep** | Standard + the list of MACs on the port; only on 1–5 switches you select |

Progress is live. The result shows every location: switch, port, VLAN, status, MAC count, LLDP
neighbour and the **classification** (ACCESS, LIKELY ACCESS, UNKNOWN, LIKELY TRUNK, TRUNK) with
the evidence. When the MAC is seen on several switches (normal: every switch on the path learns
it), the likely edge port is highlighted, the possible causes are listed, and the **network path**
(`Device → access switch port → distribution → core`) is drawn from LLDP evidence. Nothing is
deleted or changed automatically.

## Port details

From a result, **Port** opens the port page: description, admin/operational state, speed,
duplex, VLANs, LLDP neighbours, error/drop/traffic counters, classification and evidence.
**Refresh** reads the port again; **Trace MAC** searches the MAC across all switches; **Load
MACs** lists the MACs on the port. All of these are read-only. **Restart port** is shown
separately (operators and administrators only).

## Restarting a port (OPERATOR, ADMIN)

1. From a search result or the port page choose **Restart port**, then *Link bounce* (port
   disable/enable) or *PoE power cycle* (power off/on for phones, APs, cameras).
2. **Re-check & prepare** reads the port again and shows the classification, warnings, the exact
   commands and the command safety test. Nothing has been changed yet.
3. Type the confirmation exactly: `RESTART PORT <port>` (for example `RESTART PORT 1/1/24`) and
   add a reason. The plan expires after a few minutes.
4. The platform re-verifies the port immediately before the change. If anything changed since
   your confirmation you see *"Network state changed since confirmation. Operation cancelled for
   safety."* — nothing was sent.
5. After the restart you see port state, MAC relearned (or *WARNING: MAC has not been
   relearned*), VLAN, and the **change report** (before/after).

Blocked by design: UNKNOWN ports, declared uplinks, link aggregates, TRUNK / LIKELY TRUNK ports
and every port of a core/distribution switch (only administrators in EMERGENCY mode), and ports
that are administratively disabled (a restart would enable them). Outside MAINTENANCE mode, or
with dry run on, restarts are only simulated.

## Other pages

| Page | Content |
|---|---|
| Dashboard | safety state, circuit breaker, open alerts, inventory health, recent activity |
| Switches / Topology | inventory (site, location, role), switch details (NetBox/Zabbix panels), switches by role and LLDP links; administrators also see *Import* and *Export* |
| Alerts | multiple locations, MAC moves, undeclared trunks, SSH failures, failed restarts, … (operators can acknowledge) |
| Search History / Port Actions | past searches and restarts with change reports; CSV export |
| Safety Controls | modes, kill switch (operators may **engage** STOP ALL NETWORK OPERATIONS), breaker, locks |
