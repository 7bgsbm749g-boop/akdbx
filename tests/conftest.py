import io
import sys

import pytest


@pytest.fixture(autouse=True)
def no_terminal_input(monkeypatch):
    """Every tested workflow must work without an accessible broker terminal."""
    def reject_input(*args, **kwargs):
        pytest.fail("broker attempted to read terminal input")

    class UnreadableStdin(io.StringIO):
        read = reject_input
        readline = reject_input

    monkeypatch.setattr(sys, "stdin", UnreadableStdin())
    monkeypatch.setattr("builtins.input", reject_input)
    monkeypatch.setattr("getpass.getpass", reject_input)


@pytest.fixture
def tmp_path(tmp_path_factory):
    # Evidence roots can be long. Keep AF_UNIX test sockets below sun_path.
    return tmp_path_factory.mktemp('t')


@pytest.fixture(autouse=True)
def private_state_home(tmp_path_factory, monkeypatch):
    """A Linux broker saves its unlock-link block under XDG_STATE_HOME: never the real home."""
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path_factory.mktemp("state-home")))


@pytest.fixture(autouse=True)
def no_agent_desktop_slot(monkeypatch):
    """An agent desktop's slot variable must not reach the tests' CLI requests."""
    monkeypatch.delenv("AGENT_DESKTOP_SLOT", raising=False)
    monkeypatch.delenv("AKDBX_BROWSER_PROFILE_ROOT", raising=False)
