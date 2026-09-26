"""Interactive AOS CLI driver (transport independent).

OmniSwitch does not reliably support SSH "exec" channels, so commands are typed into an interactive
shell exactly as an operator would. This class implements that state machine on top of two
callables (read a chunk / write text) so it can be unit tested without a network:

* waits for the login banner to finish and learns the exact prompt (default AOS prompt ``->``,
  optionally prefixed by a system name, e.g. ``SW-ACCESS-01 ->``);
* sends one command, strips the echo, and reads until the prompt returns;
* answers pager prompts (AOS 6 "More? [next screen <sp>, ...]", ``--More--``, "Press any key")
  with a space so paginated output can never hang the session;
* detects AOS error lines (``ERROR: Invalid entry: ...``);
* enforces a per-command timeout, after which the session is marked unusable.
"""

from __future__ import annotations

import asyncio
import re
import time
from collections.abc import Awaitable, Callable

from app.parsers.common import ANSI_ESCAPE, clean_output
from app.services.ssh.errors import CommandFailed, CommandTimeout, SessionClosed

PAGER_AT_END = [
    re.compile(r"More\?\s*\[next screen <sp>, next line <cr>, filter pattern </>, quit </>\]\s*$"),
    re.compile(r"-+\s*More\s*-+(?:\s*\(\d+%\))?\s*$"),
    re.compile(r"More\?\s*$"),
    re.compile(r"Press any key to continue(?: \(Q to quit\))?\s*$", re.IGNORECASE),
]
ERROR_LINE = re.compile(r"^\s*ERROR:\s*(.+?)\s*$", re.MULTILINE)
DEFAULT_PROMPT = r"->\s*$"
MAX_OUTPUT_CHARS = 5_000_000  # hard cap so a runaway command cannot exhaust memory
MAX_PAGES = 5000


def _apply_backspaces(text: str) -> str:
    out: list[str] = []
    for ch in text:
        if ch == "\b":
            if out and out[-1] not in "\n":
                out.pop()
        else:
            out.append(ch)
    return "".join(out)


class InteractiveCli:
    def __init__(
        self,
        read_chunk: Callable[[], Awaitable[str]],
        write: Callable[[str], object],
        *,
        prompt_pattern: str = DEFAULT_PROMPT,
        command_timeout: float = 30.0,
    ) -> None:
        self._read_chunk = read_chunk
        self._write = write
        self._prompt_re = re.compile(prompt_pattern)
        self.command_timeout = command_timeout
        self.prompt: str | None = None
        self.banner: str = ""
        self._buffer = ""
        self._broken = False
        self._lock = asyncio.Lock()

    @property
    def usable(self) -> bool:
        return not self._broken

    # -- low level -------------------------------------------------------------------------------
    def _last_line(self) -> tuple[int, str]:
        idx = self._buffer.rfind("\n")
        return idx + 1, self._buffer[idx + 1 :].replace("\r", "")

    def _is_prompt(self, line: str) -> bool:
        stripped = line.strip()
        if not stripped:
            return False
        if self.prompt is not None:
            return stripped == self.prompt
        return bool(self._prompt_re.search(stripped))

    async def _read_until_prompt(self, timeout: float) -> str:
        deadline = time.monotonic() + timeout
        pages = 0
        while True:
            start, last = self._last_line()
            pager = next((p for p in PAGER_AT_END if p.search(last)), None)
            if pager is not None:
                pages += 1
                if pages > MAX_PAGES:
                    self._broken = True
                    raise CommandTimeout("Output exceeded the pagination safety limit.")
                # Drop the pager text and ask for the next screen.
                self._buffer = self._buffer[:start] + pager.sub("", last)
                self._write(" ")
                continue
            if self._is_prompt(last):
                output = self._buffer[:start]
                if self.prompt is None:
                    self.prompt = last.strip()
                self._buffer = ""
                return output
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                self._broken = True
                raise CommandTimeout(f"No prompt received within {timeout:.0f}s.")
            try:
                chunk = await asyncio.wait_for(self._read_chunk(), timeout=remaining)
            except asyncio.TimeoutError as exc:
                self._broken = True
                raise CommandTimeout(f"No prompt received within {timeout:.0f}s.") from exc
            if not chunk:
                self._broken = True
                raise SessionClosed("The switch closed the SSH session.")
            chunk = ANSI_ESCAPE.sub("", chunk)
            self._buffer = _apply_backspaces(self._buffer + chunk) if "\b" in chunk else (
                self._buffer + chunk
            )
            if len(self._buffer) > MAX_OUTPUT_CHARS:
                self._broken = True
                raise CommandTimeout("Command output exceeded the safety size limit.")

    # -- public API ------------------------------------------------------------------------------
    async def wait_for_initial_prompt(self, timeout: float) -> None:
        """Consume the login banner until the first prompt, nudging with Enter if it is silent."""
        first_wait = min(5.0, timeout / 2)
        try:
            self.banner = clean_output(await self._read_until_prompt(first_wait))
            return
        except CommandTimeout:
            self._broken = False
        self._write("\n")
        self.banner = clean_output(await self._read_until_prompt(max(timeout - first_wait, 1.0)))

    async def run(self, command: str, timeout: float | None = None) -> str:
        if "\n" in command or "\r" in command:
            raise ValueError("Commands must be a single line.")
        async with self._lock:
            if self._broken:
                raise SessionClosed("SSH session is no longer usable after a previous failure.")
            self._write(command + "\n")
            raw = await self._read_until_prompt(timeout or self.command_timeout)
        output = clean_output(raw)
        out_lines = output.split("\n")
        # Remove the echoed command (may be preceded by prompt remnants).
        if out_lines and command.strip() and command.strip() in out_lines[0]:
            out_lines = out_lines[1:]
        output = "\n".join(out_lines).strip("\n")
        error = ERROR_LINE.search(output)
        if error:
            raise CommandFailed(error.group(1), command=command, output=output)
        return output
