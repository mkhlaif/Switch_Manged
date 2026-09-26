"""Lab SSH server that serves simulated OmniSwitches over real SSH.

Each simulated switch listens on its own TCP port, so the application can be pointed at it with
``transport = ssh`` exactly like a real switch. This exercises the full SSH path: host-key
verification, password authentication, banners, echo, prompts and AOS 6 pagination.

    python -m app.simulator.ssh_server --host 127.0.0.1 --base-port 2201

prints one line per switch with its port and host-key fingerprint. Never expose this server on a
production network.
"""

from __future__ import annotations

import argparse
import asyncio
from pathlib import Path

import asyncssh

from app.simulator.model import SimSwitch
from app.simulator.scenarios import build_lab
from app.simulator.terminal import SimTerminal


class _Server(asyncssh.SSHServer):
    def __init__(self, switch: SimSwitch) -> None:
        self.switch = switch

    def begin_auth(self, username: str) -> bool:
        return True

    def password_auth_supported(self) -> bool:
        return True

    def validate_password(self, username: str, password: str) -> bool:
        if self.switch.behavior.auth_fail:
            return False
        return (username, password) == (self.switch.username, self.switch.password)


def _make_process_handler(switch: SimSwitch):
    async def handle(process: asyncssh.SSHServerProcess) -> None:
        terminal = SimTerminal(switch)

        async def pump_out() -> None:
            while True:
                chunk = await terminal.read()
                if not chunk:
                    break
                process.stdout.write(chunk)

        writer = asyncio.create_task(pump_out())
        terminal.start()
        try:
            while True:
                data = await process.stdin.read(1024)
                if not data:
                    break
                terminal.feed(data)
        except (asyncssh.BreakReceived, asyncssh.TerminalSizeChanged, ConnectionError):
            pass
        finally:
            terminal.close()
            writer.cancel()
            process.exit(0)

    return handle


async def start_servers(
    switches: dict[str, SimSwitch], host: str, base_port: int, key_path: Path | None = None
) -> list[tuple[SimSwitch, int, asyncssh.SSHAcceptor, str]]:
    if key_path and key_path.exists():
        key = asyncssh.read_private_key(str(key_path))
    else:
        key = asyncssh.generate_private_key("ssh-ed25519")
        if key_path:
            key_path.parent.mkdir(parents=True, exist_ok=True)
            key.write_private_key(str(key_path))
    public = key.export_public_key("openssh").decode().strip()
    started = []
    for offset, switch in enumerate(switches.values()):
        port = base_port + offset if base_port else 0
        acceptor = await asyncssh.create_server(
            lambda sw=switch: _Server(sw), host, port,
            server_host_keys=[key],
            process_factory=_make_process_handler(switch),
            line_editor=False,
            encoding="utf-8",
        )
        actual_port = acceptor.sockets[0].getsockname()[1]
        started.append((switch, actual_port, acceptor, public))
    return started


async def _main(args: argparse.Namespace) -> None:
    servers = await start_servers(build_lab(), args.host, args.base_port,
                                  Path(args.key) if args.key else None)
    fingerprint = asyncssh.import_public_key(servers[0][3]).get_fingerprint("sha256")
    print(f"Simulated OmniSwitch SSH servers on {args.host} (user lab / lab-password)")
    print(f"Host key fingerprint (all switches): {fingerprint}")
    for switch, port, _acc, _pub in servers:
        print(f"  {switch.name:<10} port {port:<6} {switch.model:<14} AOS {switch.version}")
    await asyncio.Event().wait()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--base-port", type=int, default=2201)
    parser.add_argument("--key", default="data/sim_host_key", help="host key file (created)")
    try:
        asyncio.run(_main(parser.parse_args()))
    except KeyboardInterrupt:
        pass
