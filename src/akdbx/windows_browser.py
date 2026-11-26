"""Check the selected Chromium profile and its port file through private Windows handles."""
import os
from pathlib import Path
import re

from . import windows_security as security


class BrowserEndpointError(Exception):
    """Internal only: callers return their own fixed, secret-free refusal."""


def endpoint(profile):
    """Return the local DevTools URL of one private, operator-selected profile.

    Every ancestor must resist replacement by another user. The profile itself
    and its port file must grant no access outside this user, SYSTEM and
    administrators. Junctions, symlinks, hard links, UNC paths and alternate
    data streams are refused by the shared handle checks.
    """
    if profile is None:
        raise BrowserEndpointError()
    try:
        path = Path(os.path.abspath(os.fspath(profile)))
        with security.trusted_directory(path.parent):
            with security.checked_handle(path, directory=True):
                data, _ = security.read_private(path / 'DevToolsActivePort', limit=256)
        match = re.fullmatch(r'([1-9][0-9]{0,4})\n(/devtools/browser/[a-zA-Z0-9-]{1,80})\n?',
                             data.decode('ascii'))
    except Exception:
        raise BrowserEndpointError() from None
    if match is None or int(match[1]) > 65535:
        raise BrowserEndpointError()
    return 'ws://127.0.0.1:' + match[1] + match[2]
