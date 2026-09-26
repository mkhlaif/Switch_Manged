"""A byte-stream terminal for a simulated switch.

It behaves like the switch end of an interactive SSH shell: echoes typed characters, prints the
banner and prompt, paginates long output with the AOS 6 pager prompt when "more" mode is on, and
can be made to hang or delay. Both the in-process session and the lab SSH server drive it, so the
real :class:`~app.services.ssh.cli.InteractiveCli` is always exercised.
"""

from __future__ import annotations

import asyncio

from app.simulator.cli import SimCli
from app.simulator.model import SimSwitch

PAGER = "More? [next screen <sp>, next line <cr>, filter pattern </>, quit </>]"


class SimTerminal:
    def __init__(self, switch: SimSwitch) -> None:
        self.switch = switch
        self.cli = SimCli(switch)
        self._out: asyncio.Queue[str] = asyncio.Queue()
        self._line = ""
        self._pages: list[list[str]] | None = None
        self.closed = False

    @property
    def prompt(self) -> str:
        return f"{self.switch.prompt} "

    def start(self) -> None:
        banner = self.switch.behavior.banner or (
            "\r\nWelcome to the Alcatel-Lucent Enterprise OmniSwitch (SIMULATED)\r\n"
            f"Software Version {self.switch.version}\r\n\r\n"
        )
        self._emit(banner + self.prompt)

    def _emit(self, text: str) -> None:
        if not self.closed:
            self._out.put_nowait(text)

    async def read(self) -> str:
        if self.closed and self._out.empty():
            return ""
        return await self._out.get()

    def close(self) -> None:
        self.closed = True
        self._out.put_nowait("")

    def feed(self, data: str) -> None:
        # Echo is batched per write, as an SSH server delivers it (one chunk, not one per
        # character); ordering relative to the command output is preserved.
        echo: list[str] = []

        def flush_echo() -> None:
            if echo:
                self._emit("".join(echo))
                echo.clear()

        for ch in data:
            if self._pages is not None:
                flush_echo()
                if ch in " \r\n":
                    self._next_page()
                elif ch.lower() == "q":
                    self._pages = None
                    self._emit("\r\n" + self.prompt)
                continue
            if ch in "\r\n":
                flush_echo()
                line, self._line = self._line, ""
                self._emit("\r\n")
                self._handle(line)
            elif ch in "\x7f\b":
                self._line = self._line[:-1]
            else:
                self._line += ch
                echo.append(ch)  # echo
        flush_echo()

    def _handle(self, line: str) -> None:
        if not line.strip():
            self._emit(self.prompt)
            return
        behavior = self.switch.behavior
        if any(s in line for s in behavior.hang_on):
            return  # never answer: the client must time out
        if any(s in line for s in behavior.silent_on):
            self.cli.execute(line)  # applied, but the answer is lost: an AMBIGUOUS outcome
            return
        if behavior.command_delay:
            asyncio.get_running_loop().call_later(behavior.command_delay, self._respond, line)
        else:
            self._respond(line)

    def _respond(self, line: str) -> None:
        output = self.cli.execute(line)
        out_lines = output.split("\n") if output else []
        size = self.switch.behavior.paginate_lines
        if size and len(out_lines) > size:
            self._pages = [out_lines[i : i + size] for i in range(0, len(out_lines), size)]
            self._next_page()
            return
        body = "\r\n".join(out_lines)
        self._emit((body + "\r\n" if body else "") + self.prompt)

    def _next_page(self) -> None:
        assert self._pages is not None
        page = self._pages.pop(0)
        self._emit("\r\n".join(page) + "\r\n")
        if self._pages:
            self._emit(PAGER)
        else:
            self._pages = None
            self._emit(self.prompt)
