"""SSH manager: connection factory, concurrency limit and retries.

The only thing this module hands to business logic is a
:class:`~app.security.firewall.FirewallSession`. The raw transport stays private: there is no
public way to obtain an unguarded session or to send text to a switch.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass

from app.core.config import Settings, get_settings
from app.core.logging import get_logger
from app.security.firewall import ExecutionContext, FirewallSession, Transport, get_firewall
from app.services.ssh.errors import ConnectionFailed, ConnectTimeout, SwitchError

log = get_logger("ssh")


@dataclass
class ConnectionTarget:
    switch_id: int | None
    name: str
    host: str
    port: int
    username: str
    password: str
    host_key: str | None
    legacy_algorithms: bool
    transport: str = "ssh"
    prompt_pattern: str = r"->\s*$"
    model: str | None = None
    aos_version: str | None = None
    previous_status: str = "unknown"

    @property
    def previously_healthy(self) -> bool:
        return self.previous_status == "online"

    def __repr__(self) -> str:  # never print the password
        return f"ConnectionTarget(name={self.name!r}, host={self.host!r}, port={self.port})"


class SwitchConnector:
    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self._semaphore = asyncio.Semaphore(self.settings.max_concurrent_switch_connections)
        self.active = 0

    async def _open_transport_once(self, target: ConnectionTarget) -> Transport:
        if target.transport == "simulator":
            if not self.settings.enable_simulator:
                raise ConnectionFailed(
                    "Simulator transport is disabled (set ENABLE_SIMULATOR=true for lab mode)."
                )
            from app.simulator.session import open_simulated_session

            return await open_simulated_session(target, self.settings)

        from app.services.ssh.asyncssh_session import AsyncSshCliSession, SshParams

        params = SshParams(
            host=target.host,
            port=target.port,
            username=target.username,
            password=target.password,
            host_key=target.host_key or None,
            allow_unknown_host_key=self.settings.ssh_allow_unknown_host_keys,
            legacy_algorithms=target.legacy_algorithms,
            connect_timeout=self.settings.ssh_connect_timeout,
            login_timeout=self.settings.ssh_login_timeout,
            command_timeout=self.settings.ssh_command_timeout,
            prompt_pattern=target.prompt_pattern,
            label=target.name,
        )
        return await AsyncSshCliSession.open(params)

    async def _open_transport(self, target: ConnectionTarget) -> Transport:
        """Open with retries. Only connection-level failures are retried; authentication and
        host-key failures are never retried (retrying them only risks account lockout)."""
        attempts = 1 + self.settings.ssh_connect_retries
        last: SwitchError | None = None
        for attempt in range(1, attempts + 1):
            try:
                return await self._open_transport_once(target)
            except (ConnectTimeout, ConnectionFailed) as exc:
                last = exc
                if attempt < attempts:
                    log.info("SSH connect to %s failed (%s); retry %d/%d", target.name,
                             exc.reason, attempt, attempts - 1)
                    await asyncio.sleep(min(2.0 * attempt, 5.0))
        assert last is not None
        raise last

    @asynccontextmanager
    async def session(self, target: ConnectionTarget,
                      ctx: ExecutionContext) -> AsyncIterator[FirewallSession]:
        """Open an SSH session wrapped by the Command Safety Firewall.

        Fails closed before connecting if the firewall is not operational."""
        from app.security.circuit_breaker import get_breaker

        firewall = get_firewall()
        breaker = get_breaker()
        try:
            firewall.ensure_ready()
        except SwitchError as exc:
            firewall.record_connection_failure(ctx, device=target.name,
                                               switch_id=target.switch_id, exc=exc)
            raise
        async with self._semaphore:
            self.active += 1
            try:
                try:
                    transport = await self._open_transport(target)
                except SwitchError as exc:
                    firewall.record_connection_failure(ctx, device=target.name,
                                                       switch_id=target.switch_id, exc=exc)
                    if exc.status in {"timeout", "connection_failed", "auth_failed",
                                      "hostkey_error"}:
                        breaker.record_ssh_failure(
                            switch_name=target.name, auth=exc.status == "auth_failed",
                            previously_healthy=target.previously_healthy, reason=exc.status)
                        if target.previously_healthy:
                            from app.security.recorder import AlertItem

                            firewall.recorder.submit(AlertItem(
                                kind="SSH_FAILURE",
                                severity="HIGH" if exc.status in {"auth_failed",
                                                                  "hostkey_error"}
                                else "WARNING",
                                title=f"SSH failure: {target.name}",
                                message=f"{exc.title}: {exc.reason}",
                                switch_name=target.name,
                                dedupe_key=f"ssh:{target.name}:{exc.status}"))
                    raise
                breaker.record_ssh_success()
                fs = firewall.open_session(transport, ctx, device=target.name,
                                           switch_id=target.switch_id,
                                           transport_kind=target.transport)
                error: BaseException | None = None
                try:
                    yield fs
                except BaseException as exc:
                    error = exc
                    raise
                finally:
                    try:
                        await transport.close()
                    finally:
                        fs.close(error)
            finally:
                self.active -= 1


_connector: SwitchConnector | None = None


def init_connector(settings: Settings | None = None) -> SwitchConnector:
    global _connector
    _connector = SwitchConnector(settings)
    return _connector


def get_connector() -> SwitchConnector:
    if _connector is None:
        return init_connector()
    return _connector
