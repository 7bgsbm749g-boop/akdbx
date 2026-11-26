"""Read and install the per-user launchd job created by guided setup."""
import os
import plistlib
import stat
import tempfile
from pathlib import Path

from .macos import require_private_acl
from .runtime import trusted_user_directory


LABEL = 'org.akdbx.broker'
MARKER = 'Managed by akdbx setup'


def configuration(argv, environment):
    return plistlib.dumps(dict(Label=LABEL, Comment=MARKER, RunAtLoad=True,
                               LimitLoadToSessionType='Aqua', ProgramArguments=argv,
                               EnvironmentVariables=environment, Umask=0o077))


def _read(directory, name):
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    except FileNotFoundError:
        return None
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or
                info.st_nlink != 1 or info.st_mode & 0o022 or info.st_size > 65536):
            raise ValueError('unsafe LaunchAgent file')
        require_private_acl(fd)
        data = stream.read(65537)
    try:
        config = plistlib.loads(data)
    except Exception:
        raise ValueError('unrecognized LaunchAgent file') from None
    if not isinstance(config, dict) or config.get('Label') != LABEL or config.get('Comment') != MARKER:
        raise ValueError('LaunchAgent was not written by akdbx setup')
    return data


def read(path):
    try:
        with trusted_user_directory(path.parent) as directory:
            return _read(directory, path.name)
    except FileNotFoundError:
        return None


def install(path, data, previous):
    with trusted_user_directory(path.parent, create_leaf=True) as directory:
        fd, filename = tempfile.mkstemp(dir=path.parent)
        temporary = Path(filename).name
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(data)
            if _read(directory, path.name) != previous:
                raise ValueError('LaunchAgent changed during setup')
            if previous is None:
                os.link(temporary, path.name, src_dir_fd=directory, dst_dir_fd=directory)
            else:
                os.replace(temporary, path.name, src_dir_fd=directory, dst_dir_fd=directory)
        finally:
            try:
                os.unlink(temporary, dir_fd=directory)
            except FileNotFoundError:
                pass
