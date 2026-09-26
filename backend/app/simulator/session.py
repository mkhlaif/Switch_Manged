"""In-process simulated switch sessions (transport = "simulator").

The simulated switch is looked up by the inventory ``host`` field (e.g. ``SIM-SW-01``). State is
kept in a process-wide registry so a port bounced in one session is seen as down by the next.
"""

from __future__ import annotations

import asyncio

from app.core.config import Settings
from app.services.ssh.cli import InteractiveCli
from app.services.ssh.errors import AuthenticationFailed, ConnectionFailed
from app.simulator.model import SimSwitch
from app.simulator.scenarios import build_lab
from app.simulator.terminal import SimTerminal

_registry: dict[str, SimSwitch] | None = None


def registry() -> dict[str, SimSwitch]:
    global _registry
    if _registry is None:
        _registry = {k.upper(): v for k, v in build_lab().items()}
    return _registry


def set_registry(switches: dict[str, SimSwitch]) -> None:
    global _registry
    _registry = {k.upper(): v for k, v in switches.items()}


def reset_registry() -> None:
    global _registry
    _registry = None


class SimulatedCliSession:
    def __init__(self, terminal: SimTerminal, cli: InteractiveCli, label: str) -> None:
        self.terminal = terminal
        self.cli = cli
        self.label = label

    async def run_approved(self, request, timeout: float | None = None) -> str:
        """Same contract as the real SSH transport: only firewall-sealed requests."""
        from app.security.firewall import assert_sealed

        approved = assert_sealed(request)
        return await self.cli.run(approved.text, timeout)

    async def close(self) -> None:
        self.terminal.close()


async def open_simulated_session(target, settings: Settings) -> SimulatedCliSession:
    switch = registry().get(target.host.upper())
    if switch is None:
        raise ConnectionFailed(f"No simulated switch named '{target.host}'.")
    await asyncio.sleep(0)  # yield like a real network connect would
    if switch.behavior.connect_refused:
        raise ConnectionFailed("Connection refused (SSH disabled or wrong port?).")
    if switch.behavior.auth_fail or (target.username, target.password) != (
        switch.username, switch.password
    ):
        raise AuthenticationFailed(
            "Authentication failed. Check the username/password of the assigned credential."
        )
    terminal = SimTerminal(switch)
    cli = InteractiveCli(terminal.read, terminal.feed, prompt_pattern=target.prompt_pattern,
                         command_timeout=settings.ssh_command_timeout)
    terminal.start()
    await cli.wait_for_initial_prompt(settings.ssh_login_timeout)
    return SimulatedCliSession(terminal, cli, target.name)
