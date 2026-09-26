"""SSH transport for real switches, built on asyncssh.

Host-key verification is mandatory: the switch's trusted key (stored in inventory, enrolled by an
administrator who confirms the fingerprint) is the only key accepted. The lab-only escape hatch
``SSH_ALLOW_UNKNOWN_HOST_KEYS`` is off by default and logged as a SECURITY event whenever used.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass

import asyncssh

from app.core.logging import get_logger, log_security
from app.services.ssh.cli import InteractiveCli
from app.services.ssh.errors import (
    AuthenticationFailed,
    ConnectionFailed,
    ConnectTimeout,
    HostKeyError,
)

log = get_logger("ssh")

# Extra algorithms for old AOS 6 releases; only offered when a switch has legacy_ssh_algorithms.
LEGACY_KEX = ["diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1",
              "diffie-hellman-group1-sha1"]
LEGACY_CIPHERS = ["aes128-cbc", "aes192-cbc", "aes256-cbc", "3des-cbc"]
LEGACY_HOSTKEY = ["ssh-rsa", "ssh-dss"]


@dataclass
class SshParams:
    host: str
    port: int
    username: str
    password: str
    host_key: str | None
    allow_unknown_host_key: bool
    legacy_algorithms: bool
    connect_timeout: float
    login_timeout: float
    command_timeout: float
    prompt_pattern: str
    label: str = ""

    def __repr__(self) -> str:  # never print the password
        return f"SshParams(host={self.host!r}, port={self.port}, username={self.username!r})"


def _algorithm_options(legacy: bool) -> dict:
    if not legacy:
        return {}
    from asyncssh.encryption import get_default_encryption_algs, get_encryption_algs
    from asyncssh.kex import get_default_kex_algs, get_kex_algs
    from asyncssh.public_key import get_default_public_key_algs, get_public_key_algs

    def merge(defaults: list[bytes], extra: list[str], available: list[bytes]) -> list[str]:
        names = [a.decode() for a in defaults]
        avail = {a.decode() for a in available}
        return names + [e for e in extra if e in avail and e not in names]

    return {
        "kex_algs": merge(get_default_kex_algs(), LEGACY_KEX, get_kex_algs()),
        "encryption_algs": merge(get_default_encryption_algs(), LEGACY_CIPHERS,
                                 get_encryption_algs()),
        "server_host_key_algs": merge(get_default_public_key_algs(), LEGACY_HOSTKEY,
                                      get_public_key_algs()),
    }


def _known_hosts(params: SshParams):
    if params.host_key:
        try:
            key = asyncssh.import_public_key(params.host_key)
        except (asyncssh.KeyImportError, ValueError) as exc:
            raise HostKeyError("The stored host key is malformed. Re-enroll the host key.") from exc
        return ([key], [], [])
    if params.allow_unknown_host_key:
        log_security(log, "Host key verification DISABLED for %s (lab option "
                     "SSH_ALLOW_UNKNOWN_HOST_KEYS=true)", params.label or params.host)
        return None
    raise HostKeyError(
        "No trusted SSH host key is stored for this switch. An administrator must enroll the "
        "host key (Switches → Host key → Fetch & trust) before the tool can connect."
    )


class AsyncSshCliSession:
    def __init__(self, conn: asyncssh.SSHClientConnection, process, cli: InteractiveCli,
                 label: str) -> None:
        self._conn = conn
        self._process = process
        self.cli = cli
        self.label = label

    @property
    def banner(self) -> str:
        return self.cli.banner

    @classmethod
    async def open(cls, params: SshParams) -> AsyncSshCliSession:
        known_hosts = _known_hosts(params)
        options = dict(
            username=params.username,
            password=params.password,
            known_hosts=known_hosts,
            client_keys=None,
            agent_path=None,
            config=None,
            preferred_auth=("keyboard-interactive", "password"),
            connect_timeout=params.connect_timeout,
            login_timeout=params.login_timeout,
            keepalive_interval=15,
            **_algorithm_options(params.legacy_algorithms),
        )
        try:
            conn = await asyncio.wait_for(
                asyncssh.connect(params.host, params.port, **options),
                timeout=params.connect_timeout + params.login_timeout + 5,
            )
        except asyncssh.PermissionDenied as exc:
            log_security(log, "SSH authentication failed for %s@%s", params.username,
                         params.label or params.host)
            raise AuthenticationFailed(
                "Authentication failed. Check the username/password of the assigned credential."
            ) from exc
        except asyncssh.HostKeyNotVerifiable as exc:
            log_security(log, "SSH host key mismatch for %s", params.label or params.host)
            raise HostKeyError(
                "The switch presented a host key that does not match the trusted key. This can "
                "mean a man-in-the-middle attack or a replaced switch. Connection refused."
            ) from exc
        except (asyncio.TimeoutError, TimeoutError) as exc:
            raise ConnectTimeout("Connection timeout.") from exc
        except ConnectionRefusedError as exc:
            raise ConnectionFailed("Connection refused (SSH disabled or wrong port?).") from exc
        except asyncssh.DisconnectError as exc:
            raise ConnectionFailed(f"SSH negotiation failed: {exc.reason}") from exc
        except OSError as exc:
            raise ConnectionFailed(f"Network error: {exc.strerror or exc.__class__.__name__}") from exc
        except asyncssh.Error as exc:
            raise ConnectionFailed(f"SSH error: {exc}") from exc

        try:
            process = await conn.create_process(
                term_type="vt100", term_size=(400, 200), encoding="utf-8", errors="replace"
            )

            async def read_chunk() -> str:
                return await process.stdout.read(65536)

            cli = InteractiveCli(read_chunk, process.stdin.write,
                                 prompt_pattern=params.prompt_pattern,
                                 command_timeout=params.command_timeout)
            await cli.wait_for_initial_prompt(params.login_timeout)
        except BaseException:
            conn.close()
            raise
        log.debug("SSH session established to %s", params.label or params.host)
        return cls(conn, process, cli, params.label or params.host)

    async def run_approved(self, request, timeout: float | None = None) -> str:
        """Send one command. Only firewall-sealed requests are accepted (see
        app.security.firewall.assert_sealed); there is no method that sends raw text."""
        from app.security.firewall import assert_sealed

        approved = assert_sealed(request)
        return await self.cli.run(approved.text, timeout)

    async def close(self) -> None:
        try:
            self._process.close()
        except Exception:  # pragma: no cover - best effort
            pass
        self._conn.close()
        try:
            await asyncio.wait_for(self._conn.wait_closed(), timeout=5)
        except Exception:  # pragma: no cover - best effort
            logging.getLogger(__name__).debug("SSH close timed out for %s", self.label)


async def fetch_host_key(host: str, port: int, legacy: bool, timeout: float) -> tuple[str, str]:
    """Return (openssh_public_key, sha256_fingerprint) presented by the server. No login occurs."""
    opts = _algorithm_options(legacy)
    try:
        key = await asyncio.wait_for(
            asyncssh.get_server_host_key(
                host, port, config=None,
                kex_algs=opts.get("kex_algs", ()),
                server_host_key_algs=opts.get("server_host_key_algs", ()),
            ),
            timeout=timeout,
        )
    except (asyncio.TimeoutError, TimeoutError) as exc:
        raise ConnectTimeout("Connection timeout while fetching host key.") from exc
    except OSError as exc:
        raise ConnectionFailed(f"Network error: {exc.strerror or exc.__class__.__name__}") from exc
    except asyncssh.Error as exc:
        raise ConnectionFailed(f"SSH error: {exc}") from exc
    if key is None:
        raise HostKeyError("The server did not present a host key.")
    return key.export_public_key("openssh").decode().strip(), key.get_fingerprint("sha256")
