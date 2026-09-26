# Final project report — Switch_Manged

**Date:** 2026-09-26 · **Scope:** audit, hardening, testing, documentation and GitHub preparation
of the Alcatel Network Operations & Safety Platform. Findings referenced as S*/B*/F*/T*/D*/DOC*/G*
are defined in [AUDIT_REPORT.md](AUDIT_REPORT.md).

## 1. Project status

**PASS WITH LIMITATIONS**

The application is tested, hardened, documented and reproducible from a clean clone on Windows
(verified) and Linux (Docker images; documented). It is **not** declared production-ready,
because:

- no Alcatel command has been executed on real OmniSwitch hardware by this project — commands are
  verified against the official ALE CLI Reference Guides and exercised against a simulator that
  reproduces the documented output. Each model family / AOS version must pass the built-in lab
  verification first (the application enforces this);
- the NetBox and Zabbix integrations are tested against mocked HTTP only;
- the GitHub push requires the repository owner's credentials (see section 9).

## 2. What was fixed

| Finding | Fix | Evidence |
|---|---|---|
| S1 **HIGH** client IP spoofing (rate-limit bypass, forged audit IPs) | nginx overwrites `X-Forwarded-For` with `$remote_addr` | `test_nginx_overwrites_x_forwarded_for`; Docker: forged header not in audit |
| S2 CSV formula injection | cells starting with `= + - @ TAB CR` are prefixed with `'` | `test_csv_exports_neutralise_formulas`; Docker check |
| S3 own role / own account changes | refused (API) and not offered (UI) | `test_admin_cannot_change_own_role_or_disable_self` |
| S4 no idle timeout | `SESSION_IDLE_MINUTES` (default 60) | `test_idle_session_is_ended` |
| S5 log injection | CR/LF escaped in every log line | `test_log_lines_cannot_be_forged` |
| S6 unbounded passwords | length limits on all password fields | `test_password_length_is_bounded` |
| F1 execution enabled on fresh installs | `NETWORK_COMMAND_EXECUTION=DISABLED` default (code, compose, template) | `test_fresh_install_defaults_block_state_changes`; Docker: indicator STOPPED |
| B1 health endpoint | `/health` + `/api/health`: `status`, `database`, `safety_firewall`; 503 when the DB is down; no config values | `test_health_*` |
| B2 MAC operator message | "The device could not be verified after restart. Please contact IT support." | `test_mac_operator_sees_required_message_when_device_does_not_return` |
| Public exposure by default | web ports published on `127.0.0.1` unless `BIND_ADDRESS` is set | compose test + `docker compose config` |
| HTTPS redirect dropped non-standard ports (found by the fresh-machine test) | redirect uses the published `HTTPS_PORT` | fresh clone: `301 https://127.0.0.1:28443/…` |
| nginx health check failed in HTTPS mode (found by the fresh-machine test) | `/nginx-health` location that never redirects | all services healthy in `https.conf` mode |
| Performance measurement distorted by its own sampler | exact session counting, coarse memory sampling | section 7 |
| Accessibility: 5 unlabelled filter controls; cramped mobile header | labels added; two-row mobile header | UI check: 106 combinations clean |
| Inconsistent line endings (B3); internal-looking example names (G4) | `.gitattributes` (LF); neutral examples, both **before** the first commit | history contains neither |
| Lab-validation procedure was circular in the docs | manual console test → record → in-app restart (matches what the code enforces) | DEPLOYMENT.md §5 |

## 3. What was added

- `AUDIT_REPORT.md` and this report.
- Read-only **Topology** view (switches by role, LLDP links from stored evidence) and **Roles**
  permission matrix (admin).
- `backend/scripts/perf_search.py` — performance test at 10/50/100 switches.
- `scripts/init-env.sh|ps1` (generates secrets), `scripts/backup.sh|ps1`, `scripts/restore.sh|ps1`.
- Frontend health check in Compose; `/health` routed by nginx and the Vite dev proxy.
- GitHub Actions CI (`.github/workflows/ci.yml`): backend tests, frontend tests + build, Docker
  image build.
- Tests: 36 backend hardening/regression tests (incl. the full §10 injection matrix for MAC,
  port, switch id, path and username), topology/roles tests, 7 new frontend tests (login, MAC
  search, DEEP mode, restart confirmation, trunk refusal, role restrictions).
- Documentation: README rewrite; `docs/` ARCHITECTURE, DEPLOYMENT (rewritten), WINDOWS_SETUP,
  LINUX_SETUP, NETWORK_SETUP, ALCATEL_COMMAND_PROFILES, USER_GUIDE, ADMIN_GUIDE,
  MAC_OPERATOR_GUIDE, TROUBLESHOOTING, BACKUP_RESTORE, UPGRADE; SECURITY and the command
  verification document updated.

## 4. Security improvements

On top of the existing controls (Command Safety Firewall, RBAC on every route, CSRF, argon2,
encrypted credentials, host-key pinning, append-only audit, circuit breaker, kill switch):
trustworthy client IPs, formula-safe exports, no self-role changes, idle session timeout, log
line integrity, bounded inputs, fail-closed fresh-install defaults (`READ_ONLY_MODE=true`,
`NETWORK_COMMAND_EXECUTION=DISABLED`, dry run on, NORMAL mode, no lab verification records),
localhost-only publishing by default, health endpoint without configuration data, stricter
`.gitignore` (env files, databases, dumps, keys, certificates, logs), CI.

Checked and not vulnerable (see audit §14): SQL injection, command injection, XSS, CSRF, path
traversal, file upload, unsafe deserialization, API privilege escalation, secrets in the
repository or its history.

## 5. Network safety

The browser can only request named operations (`SEARCH_MAC`, `GET_PORT_STATUS`,
`GET_PORT_VLAN`, `GET_PORT_MACS`, `GET_LLDP`, `RESTART_PORT`); the backend builds every command
from an exact template allowlist per AOS profile, validates every parameter, classifies the risk,
seals and fingerprints the command and re-validates it before the SSH transport — which accepts
nothing else. Everything else (`reload`, `write memory`, `configure`, VLAN/routing/STP/LACP/ACL,
users, passwords, firmware, boot, shell) is blocked and audited; tests prove that no command
reached the switch. Restarts additionally need MAINTENANCE mode, lab-verified strategies,
typed confirmation, locks, pre-restart re-verification and post-restart verification; trunks,
uplinks, link aggregates, core/distribution switches and UNKNOWN ports are refused (MAC
operators only ever reach confident ACCESS ports). Details:
[docs/SECURITY_FIREWALL.md](docs/SECURITY_FIREWALL.md).

## 6. Alcatel compatibility

| Model family | AOS | Profile | Status |
|---|---|---|---|
| OS6360, OS6465, OS6560, OS6570M, OS6860, OS6860N, OS6865, OS6900, OS9900 | 8.x | AOS8 | documentation-verified (8.10R1); **not hardware-tested**; lab verification required per family/version |
| OS6250, OS6350, OS6450 | 6.6, 6.7 | AOS6 | documentation-verified (6.7.1); **not hardware-tested**; `show mac-address-table <slot/port>` has no literal guide example |
| OS10K, OS6900 | 7.x | AOS7 | **UNVERIFIED — disabled** |
| OS6400, OS6850(E), OS6855, OS9000E (AOS 6.4) and any other model/version | — | none | **unsupported — blocked** |

Every command, with operation, R/W, expected output, parser and source:
[docs/ALCATEL_COMMAND_PROFILES.md](docs/ALCATEL_COMMAND_PROFILES.md).

## 7. Testing

| Suite | Executed | Passed | Failed | Skipped |
|---|---:|---:|---:|---:|
| Backend (pytest: unit, integration, security, RBAC, SSH over real SSH to the lab server, migrations, architecture) | 422 | 422 | 0 | 0 |
| Frontend (vitest + Testing Library) | 23 | 23 | 0 | 0 |
| **Total automated** | **445** | **445** | **0** | **0** |

Additional validation (manual/scripted, not part of CI):

| Check | Result |
|---|---|
| Frontend production build (`tsc` + Vite) | pass |
| Docker build + start from a clean clone (final commit), lab profile | all services healthy; migrations 0001→0003 applied; bootstrap admin created |
| End-to-end on Docker/PostgreSQL, read-only default (18 checks) | 17 pass + 1 script expectation updated for the intentional health-format change (`"healthy"`); endpoint verified healthy |
| End-to-end on Docker/PostgreSQL, execution enabled (13 checks: MAC operator restart, change report, audit, phrase, kill switch) | 13/13 pass |
| Fresh-machine test (clone → init-env → HTTPS self-signed → build → admin → checks) | 9/9 pass after fixing the two deployment bugs it found |
| Update procedure (backup → `git pull` → rebuild) | pass |
| Backup/restore (Linux sh and Windows PowerShell scripts) | pass; data restored exactly; audit triggers active after restore |
| Browser login on `http://localhost` with `COOKIE_SECURE=true` | pass |
| UI quality: 12 admin pages + settings tabs + simple screen × desktop/tablet/mobile × light/dark | 106 combinations: no overflow, no page errors, all controls labelled |
| Audit immutability in PostgreSQL (`UPDATE`/`DELETE`/`TRUNCATE`) | rejected |

**Performance** (`backend/scripts/perf_search.py`, simulated switches, `MAX_CONCURRENT_SSH=5`,
STANDARD search, MAC on exactly one switch):

| Switches | Latency / command | Search time | CPU | Peak RSS | Peak SSH sessions | SQL statements |
|---:|---:|---:|---:|---:|---:|---:|
| 10 | 50 ms | 0.41 s | 0.16 s | 75 MB | 5 | 64 |
| 50 | 50 ms | 1.24 s | 0.50 s | 79 MB | 5 | 264 |
| 100 | 50 ms | 2.47 s | 0.81 s | 81 MB | 5 | 514 |
| 10 | 300 ms | 1.97 s | 0.12 s | 75 MB | 5 | 64 |
| 50 | 300 ms | 3.68 s | 0.34 s | 76 MB | 5 | 264 |
| 100 | 300 ms | 6.87 s | 0.88 s | 78 MB | 5 | 514 |

Concurrency never exceeded the limit; resources stay flat. The simulator does not model the SSH
handshake: on a real network expect roughly `ceil(N / MAX_CONCURRENT_SSH) × per-switch time`.

## 8. Deployment

On a new machine (details: [docs/WINDOWS_SETUP.md](docs/WINDOWS_SETUP.md),
[docs/LINUX_SETUP.md](docs/LINUX_SETUP.md)):

```bash
git clone https://github.com/mkhlaif/Switch_Manged.git
cd Switch_Manged
./scripts/init-env.sh        # Windows: powershell -ExecutionPolicy Bypass -File .\scripts\init-env.ps1
docker compose up -d --build
docker compose exec backend python -m app.cli create-user --role admin admin
# open http://localhost:8080 — for LAN access: HTTPS + BIND_ADDRESS (docs/NETWORK_SETUP.md)
```

Then follow the production enablement order in
[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md#5-production-enablement): read-only → switches → SSH test →
MAC search → profile verification → tests → lab switch → controlled restart → endpoint port →
production.

## 9. GitHub

| Item | Value |
|---|---|
| Repository | https://github.com/mkhlaif/Switch_Manged (public; was empty before this work) |
| Branch | `main` (new default branch; no remote branches existed) |
| Commits | 22 logical commits (baseline in 5 commits, audit, security, features, tests, performance, CI/scripts, UI, deployment fixes, docs, this report, pre-push cleanup, post-push fix) |
| Commit identity | `mkhlaif <267584620+mkhlaif@users.noreply.github.com>` (repo-local; GitHub noreply address so no personal e-mail is published) |
| Secrets check | whole history scanned: no `.env`, database, dump, key, certificate or credential committed |
| Push | done — see "Push result" below |

### Push result

**Pushed on 2026-09-26** with a normal `git push -u origin main` (no force, no history rewrite;
the remote was empty, so it was a plain new-branch push). The repository owner completed the
GitHub sign-in through Git Credential Manager; no credential was stored in the repository.

- First push: 21 commits, `main` → `2b453b1`; local `main` == `origin/main` afterwards.
- First GitHub Actions run (backend tests, frontend tests and build, Docker image build):
  **success** — https://github.com/mkhlaif/Switch_Manged/actions/runs/36233107230
- Follow-up commit (normal push): this section updated, a broken Windows command in the README
  fixed and a test regex repaired (its `\b` word boundaries had been written as control
  characters, so the "no technical words in MAC_OPERATOR messages" check was weaker than
  intended; all tests pass with the corrected regex).

## 10. Known limitations

- **Hardware:** commands verified against documentation and a simulator only; lab verification
  on real switches is mandatory before production (built into the application).
- **AOS 8 versions:** only the 8.10R1 guide was reviewed; other 8.x releases rely on the per-
  version lab verification (an administrator can switch that requirement off — do not).
- **AOS 6:** `show mac-address-table <slot/port>` has no literal example in the guide.
- **Zabbix:** only host availability and current problems; traffic, errors, drops, uptime, CPU,
  memory and temperature need template-specific item keys and are not read (not guessed).
- **NetBox/Zabbix** tested against mocked APIs only; Zabbix needs 6.4+ (Bearer tokens).
- **Path/topology** depend on LLDP between switches; stale LLDP evidence is shown with its age.
- **MAC_OPERATOR restarts** require every enabled switch to answer (fail-closed); an offline
  switch blocks their restarts network-wide.
- **Link bounce only** in the MAC operator flow (no PoE cycling there).
- **Single backend process** (no Redis) — by design; no MFA/SSO; no self-service password reset.
- **Audit immutability** relies on database triggers; the database owner role can remove them —
  use a separate application role for stronger guarantees.
- **Behind a load balancer**, real client IPs need `set_real_ip_from` (documented).
- **Docker Desktop** records the Docker gateway address as client IP (NAT).
- **CI** has not run yet on GitHub (it runs on the first push).
- **No LICENSE** file — the owner's decision.
