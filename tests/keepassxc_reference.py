"""Optional independent KeePassXC 2.7.10 oracle for synthetic test images."""
from functools import lru_cache
from pathlib import Path
import subprocess

import pytest


@lru_cache(maxsize=1)
def _installed():
    cli = Path('/usr/bin/keepassxc-cli')
    return cli.is_file() and subprocess.check_output([cli, '--version'], timeout=10).strip() == b'2.7.10'


def reference_merge(folder, synthetic_vault):
    if not _installed():
        pytest.skip('independent comparison requires KeePassXC 2.7.10')
    subprocess.run(['/usr/bin/keepassxc-cli', 'merge', '--quiet', '--same-credentials',
                    folder / 'candidate.kdbx', folder / 'source.kdbx'],
                   input=(synthetic_vault.password + '\n').encode(), check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=180)
