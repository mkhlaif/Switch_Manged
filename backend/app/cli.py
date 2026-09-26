"""Administrative command line.

    python -m app.cli generate-key                  # new CREDENTIAL_ENCRYPTION_KEY
    python -m app.cli create-user --role admin NAME # prompts for the password
    python -m app.cli seed-lab                      # lab mode: add simulated switches
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import sys

from sqlalchemy import select

from app.core.config import get_settings
from app.core.crypto import encrypt_secret, generate_key
from app.core.security import hash_password, validate_password_strength
from app.db.session import dispose_engine, init_engine, session_factory
from app.models import Credential, Role, Switch, User


def read_stdin_password(stream) -> str:
    """One line from stdin without the line ending. Windows PowerShell pipes append CRLF (and
    may prepend a UTF-8 BOM); keeping the CR would silently create an unusable password."""
    return stream.readline().lstrip("\ufeff").rstrip("\r\n")


async def _create_user(username: str, role: str, full_name: str, password: str | None) -> int:
    password = password or getpass.getpass(f"Password for {username}: ")
    problem = validate_password_strength(password)
    if problem:
        print(f"error: {problem}", file=sys.stderr)
        return 2
    init_engine()
    try:
        async with session_factory()() as db:
            if (await db.execute(select(User).where(User.username == username.lower()))).first():
                print(f"error: user {username} already exists", file=sys.stderr)
                return 1
            db.add(User(username=username.lower(), full_name=full_name, role=Role(role).value,
                        password_hash=hash_password(password)))
            await db.commit()
    finally:
        await dispose_engine()
    print(f"created {role} user {username.lower()}")
    return 0


# Topology roles of the simulated lab (SIM-SW-02 aggregates SIM-SW-01; the OS10K is the core).
LAB_ROLES = {"SIM-SW-02": "distribution", "SIM-SW-07": "core"}


async def _seed_lab() -> int:
    if not get_settings().enable_simulator:
        print("error: set ENABLE_SIMULATOR=true to use lab mode", file=sys.stderr)
        return 2
    from app.simulator.scenarios import SIM_PASSWORD, SIM_USERNAME, build_lab

    init_engine()
    try:
        async with session_factory()() as db:
            cred = (await db.execute(select(Credential).where(Credential.name == "lab-simulator")
                                     )).scalar_one_or_none()
            if cred is None:
                cred = Credential(name="lab-simulator", username=SIM_USERNAME,
                                  password_encrypted=encrypt_secret(SIM_PASSWORD),
                                  description="Credential for simulated lab switches")
                db.add(cred)
                await db.flush()
            added = 0
            for sim in build_lab().values():
                if (await db.execute(select(Switch).where(Switch.name == sim.name))).first():
                    continue
                db.add(Switch(
                    name=sim.name, host=sim.name, ssh_port=22, transport="simulator",
                    location=sim.location, description=f"Simulated {sim.model}",
                    # No model / AOS version: automatic discovery identifies every switch
                    # (on the first search or an explicit discovery run).
                    environment="lab", credential_id=cred.id,
                    role=LAB_ROLES.get(sim.name, "access"),
                ))
                added += 1
            await db.commit()
    finally:
        await dispose_engine()
    print(f"lab seeded: {added} simulated switch(es) added")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.cli")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("generate-key", help="print a new Fernet key for CREDENTIAL_ENCRYPTION_KEY")
    cu = sub.add_parser("create-user", help="create a user")
    cu.add_argument("username")
    cu.add_argument("--role", choices=[r.value for r in Role], default="readonly")
    cu.add_argument("--full-name", default="")
    cu.add_argument("--password-stdin", action="store_true",
                    help="read the password from stdin instead of prompting")
    sub.add_parser("seed-lab", help="add simulated switches (requires ENABLE_SIMULATOR=true)")
    args = parser.parse_args(argv)

    if args.cmd == "generate-key":
        print(generate_key())
        return 0
    if args.cmd == "create-user":
        password = read_stdin_password(sys.stdin) if args.password_stdin else None
        return asyncio.run(_create_user(args.username, args.role, args.full_name, password))
    if args.cmd == "seed-lab":
        return asyncio.run(_seed_lab())
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
