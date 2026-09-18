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
