"""Performance test of discovery and MAC search with controlled SSH concurrency (simulated).

    cd backend
    python scripts/perf_search.py --switches 10 50 100 500 --concurrency 5 --latency 0.05
    python scripts/perf_search.py --scenario discovery --switches 10 50 100 500

For each inventory size N the script builds N simulated OmniSwitches (AOS 8 access switches,
the searched MAC present on exactly one of them) and runs, through the normal service code
(firewall, profiles, parsers, classification, database), one of:

* ``search`` — a MAC search over switches that were already discovered;
* ``first-search`` — a MAC search over switches that were never discovered (each switch is
  identified with the discovery command first, in the same SSH session);
* ``discovery`` — a background discovery job over every switch.

It reports:

* wall-clock search time,
* process CPU time and peak resident memory (psutil),
* the peak number of simultaneously open switch sessions (must never exceed --concurrency),
* the number of SQL statements executed.

It uses a temporary SQLite database and the in-process simulator: no real switch and no network
access. `--latency` is the simulated response time per CLI command; the SSH handshake of a real
switch is NOT simulated, so absolute times on a real network are higher (roughly
ceil(N / concurrency) x real per-switch time). The value of this test is the scaling behaviour
and the proof that concurrency and resources stay bounded.
"""

from __future__ import annotations

import argparse
import asyncio
import copy
import json
import os
import sys
import tempfile
import time
from contextlib import asynccontextmanager
from pathlib import Path

from cryptography.fernet import Fernet

TMP = Path(tempfile.mkdtemp(prefix="netops-perf-"))
os.environ.update({
    "ENVIRONMENT": "test",
    "DATABASE_URL": f"sqlite+aiosqlite:///{(TMP / 'perf.db').as_posix()}",
    "CREDENTIAL_ENCRYPTION_KEY": Fernet.generate_key().decode(),
    "ENABLE_SIMULATOR": "true",
    "LOG_LEVEL": "WARNING",
    "SSH_COMMAND_TIMEOUT": "10",
    "SSH_SWITCH_BUDGET_SECONDS": "120",
})
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import psutil  # noqa: E402
from sqlalchemy import event, select  # noqa: E402

MAC = "001122334455"


async def run(n: int, concurrency: int, latency: float, mode: str, scenario: str) -> dict:
    from app.core.config import get_settings
    from app.core.crypto import encrypt_secret
    from app.core.logging import configure_logging
    from app.core.security import hash_password
    from app.db.base import Base
    from app.db.session import dispose_engine, init_engine, session_factory
    from app.models import Credential, MacSearch, Role, Switch, User
    from app.security.circuit_breaker import init_breaker
    from app.security.firewall import init_firewall
    from app.services.discovery.service import create_job
    from app.services.mac_search.service import start_search
    from app.services.ssh import manager
    from app.simulator import session as sim_session
    from app.simulator.scenarios import SIM_PASSWORD, SIM_USERNAME, build_lab
    from app.workers import tasks

    configure_logging("WARNING")
    settings = get_settings()
    settings.max_concurrent_switch_connections = concurrency
    db_file = TMP / f"perf-{n}.db"
    url = f"sqlite+aiosqlite:///{db_file.as_posix()}"
    settings.database_url = url
    engine = init_engine(url)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    connector = manager.init_connector(settings)
    init_firewall(breaker=init_breaker())

    template = build_lab()["SIM-SW-01"]
    fleet = {}
    for i in range(1, n + 1):
        sw = copy.deepcopy(template)
        sw.name = f"PERF-SW-{i:03d}"
        sw.behavior.command_delay = latency
        if i != max(1, n // 2):  # the MAC is on exactly one access port
            sw.ports["1/1/26"].macs = []
            sw.ports["1/1/49"].macs = []
        fleet[sw.name] = sw
    sim_session.set_registry(fleet)

    async with session_factory()() as db:
        cred = Credential(name="perf", username=SIM_USERNAME,
                          password_encrypted=encrypt_secret(SIM_PASSWORD))
        db.add(cred)
        await db.flush()
        identified = scenario == "search"
        for name, sw in fleet.items():
            # The identity only ever comes from discovery: "search" starts from switches that
            # were discovered before; the other scenarios start from an empty identity.
            db.add(Switch(name=name, host=name, transport="simulator", role="access",
                          model=sw.model if identified else "",
                          aos_version=sw.version if identified else "",
                          vendor="ALE" if identified else "",
                          discovery_status="discovered" if identified else "not_discovered",
                          credential_id=cred.id))
        user = User(username="perf", full_name="Perf", role=Role.READONLY.value,
                    password_hash=hash_password("Perf-Passw0rd!!"))
        db.add(user)
        await db.commit()

    statements = 0

    def count(*_args, **_kw):
        nonlocal statements
        statements += 1

    event.listen(engine.sync_engine, "before_cursor_execute", count)

    proc = psutil.Process()
    peak_rss = proc.memory_info().rss
    stop = False

    # Exact peak of simultaneously open sessions: wrap the connector's session context.
    active = peak_sessions = 0
    original_session = connector.session

    @asynccontextmanager
    async def counted_session(*a, **kw):
        nonlocal active, peak_sessions
        async with original_session(*a, **kw) as fs:
            active += 1
            peak_sessions = max(peak_sessions, active)
            try:
                yield fs
            finally:
                active -= 1

    connector.session = counted_session

    async def sample_memory():  # coarse sampling: must not load the event loop itself
        nonlocal peak_rss
        while not stop:
            peak_rss = max(peak_rss, proc.memory_info().rss)
            await asyncio.sleep(0.1)

    sampler = asyncio.create_task(sample_memory())
    cpu0, t0 = time.process_time(), time.perf_counter()
    async with session_factory()() as db:
        user = (await db.execute(select(User))).scalar_one()
        if scenario == "discovery":
            ids = list((await db.execute(select(Switch.id))).scalars())
            job_id = (await create_job(db, user, ids, source="perf")).id
        else:
            search_id = (await start_search(db, user, MAC, mode=mode)).id
    await asyncio.gather(*tasks.running())
    elapsed = time.perf_counter() - t0
    cpu = time.process_time() - cpu0
    stop = True
    await sampler
    async with session_factory()() as db:
        discovered = len(list((await db.execute(select(Switch.id).where(
            Switch.discovery_status == "discovered"))).scalars()))
        if scenario == "discovery":
            from app.models import DiscoveryJob

            job = await db.get(DiscoveryJob, job_id)
            status, found, failed, timeout = job.status, None, job.failed, 0
        else:
            s = await db.get(MacSearch, search_id)
            status, found, failed, timeout = (s.status, s.found_count, s.failed_count,
                                              s.timeout_count)
        result = {"scenario": scenario, "switches": n, "mode": mode,
                  "concurrency_limit": concurrency,
                  "latency_per_command_s": latency, "status": status,
                  "found": found, "failed": failed, "timeout": timeout,
                  "discovered_switches": discovered,
                  "time_s": round(elapsed, 2), "cpu_time_s": round(cpu, 2),
                  "peak_rss_mb": round(peak_rss / 2**20, 1),
                  "peak_concurrent_sessions": peak_sessions,
                  "sql_statements": statements,
                  "sql_per_switch": round(statements / n, 1)}
    await dispose_engine()
    sim_session.reset_registry()
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--switches", type=int, nargs="+", default=[10, 50, 100])
    parser.add_argument("--concurrency", type=int, default=5)
    parser.add_argument("--latency", type=float, default=0.05)
    parser.add_argument("--mode", default="STANDARD", choices=["FAST", "STANDARD"])
    parser.add_argument("--scenario", default="search",
                        choices=["search", "first-search", "discovery"])
    args = parser.parse_args()
    results = []
    for n in args.switches:
        r = asyncio.run(run(n, args.concurrency, args.latency, args.mode, args.scenario))
        results.append(r)
        print(json.dumps({**r, "check": "PASS" if _ok(r, args.concurrency) else "FAIL"}))
    return 0 if all(_ok(r, args.concurrency) for r in results) else 1


def _ok(r: dict, concurrency: int) -> bool:
    if r["peak_concurrent_sessions"] > concurrency or r["status"] != "completed":
        return False
    if r["scenario"] == "discovery":
        return r["failed"] == 0 and r["discovered_switches"] == r["switches"]
    return r["found"] == 1 and r["failed"] == 0 and r["discovered_switches"] == r["switches"]


if __name__ == "__main__":
    sys.exit(main())
