# Automatic device discovery

Nobody types a switch model or AOS version into this platform. An administrator gives the
management address, the SSH port and the *name* of a credential; the platform identifies the
device itself, read-only, and selects the command profile from what the device reports. A device
that cannot be identified exactly receives no other command.

## Flow

```
IP / hostname + credential reference (+ optional host-key fingerprint, expected metadata)
  → trusted SSH host key: enrolled by an administrator, or exactly the fingerprint supplied
    out of band (otherwise: HOST_KEY_UNTRUSTED, nothing is sent)
  → SSH session through the Command Safety Firewall
  → the registry's read-only discovery command: show system
  → vendor = ALE only if the description AND the enterprise OID (1.3.6.1.4.1.6486) agree
  → model and AOS version in their documented formats only (e.g. OS6860E-P24, 8.9.221.R03)
  → exactly one Discovery Profile Registry entry
  → compare with the expected metadata and with the identity discovered before
  → identity stored (vendor, model, version, system name, object id, registry entry, time)
  → command profile selected from the discovered model family and AOS version
  → operations allowed according to the profile states (ALCATEL_COMMAND_PROFILES.md)
```

The registry, its sources and fixtures are described in
[ALCATEL_COMMAND_PROFILES.md § Discovery Profile Registry](ALCATEL_COMMAND_PROFILES.md#discovery-profile-registry).

## Discovery status of a switch

| Status | Meaning | What is possible |
|---|---|---|
| `not_discovered` | never identified, or its address / SSH port / transport changed | discovery only (a MAC search discovers it first) |
| `discovered` | identified; matches the expected metadata and the previous identity | reads; restarts according to the profile states |
| `mismatch` | identified, but different from the expected metadata or from the identity discovered before (model family or exact AOS version changed) | reads with the profile of the device as it is now; **no state change** until an administrator accepts the identity |
| `discovery_failed` | could not be identified (other vendor, unreadable model / version, unreachable, authentication, host key) — with a safe error category | nothing but a new discovery |

A switch that was discovered and later cannot be reached keeps its identity (it did not change,
it was only unreachable); the SSH status shows the failure.

## When discovery runs

- after a switch is created (if its host key can be trusted without guessing: simulator,
  enrolled key or a supplied fingerprint), after its host key is trusted, and after a change of
  address, port, transport, credential or expected metadata;
- after a bulk import, for the created / updated switches ([SWITCH_IMPORT_EXPORT.md](SWITCH_IMPORT_EXPORT.md));
- during a MAC search, for switches that were never identified (same SSH session, before the MAC
  lookup; the identity is then stored exactly as by an explicit discovery);
- on request: *switch page → Run discovery*, *Switches → Discover all*
  (`POST /api/switches/{id}/discover`, `POST /api/discovery/jobs`);
- **before every restart, twice**: the device is identified again in the prepare session and in
  the execution session, before the first state-changing command. A different device (e.g. an
  AOS upgrade in the meantime) aborts the restart and turns the switch into `mismatch`.

Background jobs use at most `MAX_CONCURRENT_SWITCH_CONNECTIONS` SSH sessions, can be cancelled,
stop after 30 minutes, and are marked *interrupted* if the application stops. One manual job at a
time.

## Expected metadata

`expected_model` and `expected_aos_version` (switch form, import columns `model` / `aos_version`
or `expected_*`) are never used to select commands. Discovery compares them with the device:

- model: same model family (`OS6860E-P24` ≙ `OS6860`);
- AOS version: same major.minor (`8.10R1` ≙ `8.10.94.R03`) — the mapping of release names to build
  numbers is not guessed.

A difference makes the switch `mismatch`, raises a HIGH alert (`DISCOVERY_MISMATCH`) and counts
towards the circuit breaker (3 mismatches in the window → SAFE MODE).

## Reviewing a mismatch

*Switch page → Review and accept identity* (administrators): shows the discovered identity and
the difference and requires a reason. Accepting makes the discovered identity the expected one
(audited `DISCOVERY_ACCEPT` with the previous values). Command profiles must still be verified for
the new model family / AOS version, and the identity is checked again before every restart.
`POST /api/switches/{id}/discovery/accept` `{"reason": "…"}`.

## Audit and errors

Every discovery is audited (`DEVICE_DISCOVERY`: result, site, error category, discovered
identity, registry entry, commands, source = manual / job / import / mac-search /
restart-prepare); jobs as `DISCOVERY_JOB_START` / `DISCOVERY_JOB`. Errors use the safe categories
(`DEVICE_UNREACHABLE`, `AUTHENTICATION_FAILED`, `HOST_KEY_UNTRUSTED`, `DISCOVERY_FAILED`,
`PROFILE_NOT_FOUND`, `SAFETY_CHECK_FAILED`, `TIMEOUT`, …). MAC operators never see discovery
information.

## Limitations

- **Serial number / chassis information is not collected**: no command for it is verified in
  this project (`show chassis` is not in the allowlist). It is shown as "not collected".
- **AOS 7 (OS10K and OS6900 on 7.x)** has no registry entry and no documented output fixture: such
  switches end `discovery_failed` (the model format is not read). Supporting them requires a
  verified registry entry and fixtures.
- Discovery was exercised against the simulator and the documented output fixtures only; it has
  **not been run against real Alcatel-Lucent hardware** by this project.
