"""Read and install the per-user launchd job created by guided setup."""
import os
import plistlib
import stat
import tempfile
from contextlib import contextmanager
from pathlib import Path

from .macos import require_private_acl
from .runtime import _validate_trusted_ancestor


LABEL = 'org.akdbx.broker'
MARKER = 'Managed by akdbx setup'


def configuration(argv, environment):
    return plistlib.dumps(dict(Label=LABEL, Comment=MARKER, RunAtLoad=True,
                               LimitLoadToSessionType='Aqua', ProgramArguments=argv,
                               EnvironmentVariables=environment, Umask=0o077))


@contextmanager
def _directory(path, create):
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    fd = os.open(path.anchor, flags)
    current = Path(path.anchor)
    try:
        for part in path.parts[1:]:
            current /= part
            if create and current == path:
                try:
                    os.mkdir(part, 0o700, dir_fd=fd)
                except FileExistsError:
                    pass
            child = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = child
            _validate_trusted_ancestor(os.fstat(fd), current, os.getuid(), fd)
        if os.fstat(fd).st_uid != os.getuid():
            raise PermissionError('LaunchAgents directory belongs to another user')
        yield fd
    finally:
        os.close(fd)


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
        with _directory(path.parent, False) as directory:
            return _read(directory, path.name)
    except FileNotFoundError:
        return None


def install(path, data, previous):
    with _directory(path.parent, True) as directory:
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
