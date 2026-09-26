"""InteractiveCli state machine against scripted terminal streams (no network)."""

import asyncio

import pytest

from app.services.ssh.cli import InteractiveCli
from app.services.ssh.errors import CommandFailed, CommandTimeout, SessionClosed


class FakeTerminal:
    """Replies to each command with a scripted list of chunks."""

    def __init__(self, banner: list[str], replies: dict[str, list[str]]):
        self.queue: asyncio.Queue[str] = asyncio.Queue()
        self.replies = replies
        self.sent: list[str] = []
        self.buffer = ""
        for chunk in banner:
            self.queue.put_nowait(chunk)

    async def read(self) -> str:
        return await self.queue.get()

    def write(self, data: str) -> None:
        self.sent.append(data)
        self.buffer += data
        while "\n" in self.buffer:
            line, self.buffer = self.buffer.split("\n", 1)
            for chunk in self.replies.get(line, []):
                self.queue.put_nowait(chunk)
        if data == " " and " " in self.replies:
            for chunk in self.replies[" "]:
                self.queue.put_nowait(chunk)


async def make_cli(term: FakeTerminal, **kw) -> InteractiveCli:
    cli = InteractiveCli(term.read, term.write, command_timeout=kw.pop("timeout", 1.0), **kw)
    await cli.wait_for_initial_prompt(2)
    return cli


async def test_banner_and_prompt_learning_with_hostname():
    term = FakeTerminal(
        ["\r\nWelcome to OmniSwitch\r\n", "SW-ACCESS-01 -", "> "],
        {"show system": ["show system\r\n", "System:\r\n  Name: sw,\r\n", "SW-ACCESS-01 -> "]},
    )
    cli = await make_cli(term)
    assert cli.prompt == "SW-ACCESS-01 ->"
    assert "Welcome" in cli.banner
    out = await cli.run("show system")
    assert out == "System:\n  Name: sw,"  # echo stripped, prompt stripped


async def test_pager_is_answered_with_space():
    pager = "More? [next screen <sp>, next line <cr>, filter pattern </>, quit </>]"
    term = FakeTerminal(["-> "], {
        "show vlan port 1/1": ["show vlan port 1/1\r\n", "line1\r\nline2\r\n", pager],
        " ": ["\r\nline3\r\n-> "],
    })
    cli = await make_cli(term)
    out = await cli.run("show vlan port 1/1")
    assert out.split("\n") == ["line1", "line2", "", "line3"]
    assert " " in term.sent


async def test_generic_more_prompt():
    term = FakeTerminal(["-> "], {
        "show x": ["show x\r\n", "a\r\n--More--"],
        " ": ["\x1b[2K\rb\r\n-> "],
    })
    cli = await make_cli(term)
    assert (await cli.run("show x")).split("\n") == ["a", "b"]


async def test_aos_error_line_raises_command_failed():
    term = FakeTerminal(["-> "], {
        "show mac-learning": ["show mac-learning\r\n", 'ERROR: Invalid entry: "mac-learning"\r\n',
                              "-> "],
    })
    cli = await make_cli(term)
    with pytest.raises(CommandFailed) as exc:
        await cli.run("show mac-learning")
    assert "Invalid entry" in exc.value.reason


async def test_timeout_marks_session_unusable():
    term = FakeTerminal(["-> "], {"show slow": ["show slow\r\n", "partial"]})
    cli = await make_cli(term, timeout=0.3)
    with pytest.raises(CommandTimeout):
        await cli.run("show slow")
    assert not cli.usable
    with pytest.raises(SessionClosed):
        await cli.run("show system")


async def test_eof_raises_session_closed():
    term = FakeTerminal(["-> "], {"show system": ["show system\r\n", ""]})
    cli = await make_cli(term)
    with pytest.raises(SessionClosed):
        await cli.run("show system")


async def test_silent_login_is_nudged_with_enter():
    term = FakeTerminal([], {"": ["-> "]})
    cli = InteractiveCli(term.read, term.write, command_timeout=1)
    await cli.wait_for_initial_prompt(1.0)
    assert cli.prompt == "->"
    assert "\n" in term.sent


async def test_multiline_command_rejected():
    term = FakeTerminal(["-> "], {})
    cli = await make_cli(term)
    with pytest.raises(ValueError):
        await cli.run("show system\nreload")
