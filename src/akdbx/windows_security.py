"""Windows handle and ACL checks. Imported only on Windows; never print secrets."""
from contextlib import contextmanager, suppress
from pathlib import Path
import os

import win32api
import win32con
import win32file
import win32security
import win32process
import pywintypes
import ntsecuritycon

TRUSTED_INSTALLER = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000


@contextmanager
def managed_handle(handle):
    # pywin32 PyHANDLE supplies Close(), but is not a context manager.
    try:
        yield handle
    finally:
        handle.Close()


def process_identity(pid):
    """Verify user/session and keep a process handle to prevent PID reuse."""
    handle = win32api.OpenProcess(0x1000 | win32con.SYNCHRONIZE, False, pid)
    try:
        with managed_handle(win32security.OpenProcessToken(handle, win32con.TOKEN_QUERY)) as token:
            sid = win32security.ConvertSidToStringSid(
                win32security.GetTokenInformation(token, win32security.TokenUser)[0])
            session = win32security.GetTokenInformation(token, win32security.TokenSessionId)
        return handle, (sid, session, win32process.GetProcessTimes(handle)['CreationTime'])
    except BaseException:
        handle.Close()
        raise


def current_identity():
    handle, identity = process_identity(os.getpid())
    handle.Close()
    return identity[:2]


def verify_process(pid):
    handle, identity = process_identity(pid)
    if identity[:2] != current_identity():
        handle.Close()
        raise PermissionError('Windows peer must have the same user and desktop session')
    return handle, identity


def private_attributes():
    sid = current_identity()[0]
    descriptor = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
        f'O:{sid}D:P(A;;FA;;;{sid})(A;;FA;;;SY)', 1)
    attributes = pywintypes.SECURITY_ATTRIBUTES()
    attributes.SECURITY_DESCRIPTOR = descriptor
    attributes.bInheritHandle = False
    return attributes


def check_acl(handle, *, private=True):
    descriptor = win32security.GetSecurityInfo(
        handle, win32security.SE_FILE_OBJECT,
        win32security.OWNER_SECURITY_INFORMATION | win32security.DACL_SECURITY_INFORMATION)
    trusted = {current_identity()[0], 'S-1-5-18', 'S-1-5-32-544', TRUSTED_INSTALLER}
    owner = win32security.ConvertSidToStringSid(descriptor.GetSecurityDescriptorOwner())
    acl = descriptor.GetSecurityDescriptorDacl()
    if owner not in trusted or acl is None:
        raise PermissionError('Windows path must have a trusted owner and a restrictive DACL')
    for index in range(acl.GetAceCount()):
        ace = acl.GetAce(index)
        kind, flags = ace[0]
        if flags & win32con.INHERIT_ONLY_ACE or kind == win32security.ACCESS_DENIED_ACE_TYPE:
            continue
        if kind != win32security.ACCESS_ALLOWED_ACE_TYPE:
            raise PermissionError('unsupported Windows access control entry')
        if win32security.ConvertSidToStringSid(ace[2]) in trusted:
            continue
        # Public ancestors may be readable, but must not allow replacement or
        # mutation. Private leaves must not grant any access to another user.
        # FILE_ADD_SUBDIRECTORY on a public ancestor is common on C:\ and
        # C:\Users; it cannot replace an existing, trusted child. Do not confuse
        # that permission with FILE_DELETE_CHILD or directory mutation rights.
        mutations = 0x10000000 | 0x40000000 | 0x000D0152
        if ace[1] & (0xFFFFFFFF if private else mutations):
            raise PermissionError('Windows path grants unsafe access to another user')


def _open_checked_handle(path, *, directory=False, private=True, access=None, creation=win32con.OPEN_EXISTING):
    path = Path(os.path.abspath(path))
    if path.drive.startswith('\\\\') or ':' in str(path)[2:]:
        raise PermissionError('use a local Windows volume without alternate data streams')
    access = access if access is not None else win32con.GENERIC_READ | win32con.READ_CONTROL
    flags = FILE_FLAG_OPEN_REPARSE_POINT
    if directory:
        flags |= win32con.FILE_FLAG_BACKUP_SEMANTICS
    handle = win32file.CreateFile(str(path), access,
                                 win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE,
                                 private_attributes() if creation != win32con.OPEN_EXISTING else None,
                                 creation, flags, None)
    try:
        info = win32file.GetFileInformationByHandle(handle)
        attributes = info[0]
        if (attributes & win32con.FILE_ATTRIBUTE_REPARSE_POINT
                or bool(attributes & win32con.FILE_ATTRIBUTE_DIRECTORY) != directory
                or not directory and info[7] != 1):
            raise PermissionError('Windows paths must be regular, unlinked files or directories')
        check_acl(handle, private=private)
        return handle
    except BaseException:
        handle.Close()
        if creation == win32con.CREATE_NEW:
            # CreateFile succeeded: this call owns the new file, even when
            # validation refused it. A failed CreateFile never reaches here.
            with suppress(OSError):
                path.unlink()
        raise


@contextmanager
def checked_handle(path, **options):
    with managed_handle(_open_checked_handle(path, **options)) as handle:
        yield handle


@contextmanager
def trusted_directory(path):
    """Hold all components without delete sharing; refuse junctions and UNC."""
    path = Path(os.path.abspath(Path(path).expanduser()))
    if path.drive.startswith('\\\\') or not path.is_absolute() or ':' in str(path)[2:]:
        raise PermissionError('use a local Windows volume without alternate data streams')
    held = []
    try:
        component = Path(path.anchor)
        for part in ('', *path.parts[1:]):
            if part:
                component /= part
            held.append(_open_checked_handle(component, directory=True, private=False,
                                             access=ntsecuritycon.FILE_READ_ATTRIBUTES | win32con.READ_CONTROL))
        yield path
    finally:
        for handle in reversed(held):
            handle.Close()


def read_private(path, *, limit=128 * 1024 * 1024):
    """Read through the verified handle, with bounded input and change checks."""
    path = Path(path)
    with trusted_directory(path.parent):
        with checked_handle(path) as handle:
            before = win32file.GetFileInformationByHandle(handle)
            size = before[5] * 2**32 + before[6]
            if size > limit:
                raise ValueError('Windows private file exceeds the input budget')
            data = bytearray()
            while len(data) < size:
                _, chunk = win32file.ReadFile(handle, min(1024 * 1024, size - len(data)))
                if not chunk:
                    raise OSError('private file read was incomplete')
                data.extend(chunk)
            after = win32file.GetFileInformationByHandle(handle)
            if (*after[:2], *after[3:]) != (*before[:2], *before[3:]):
                raise OSError('private file changed during read')
            return bytes(data), before


def write_new(path, data):
    """Create and flush one private file, removing it if this call fails."""
    path = Path(path)
    with trusted_directory(Path(path).parent):
        handle = _open_checked_handle(path, access=win32con.GENERIC_WRITE | win32con.READ_CONTROL,
                                      creation=win32con.CREATE_NEW)
        try:
            with managed_handle(handle):
                offset = 0
                while offset < len(data):
                    _, written = win32file.WriteFile(handle, data[offset:offset + 1024 * 1024])
                    if not written:
                        raise OSError('private file write was incomplete')
                    offset += written
                win32file.FlushFileBuffers(handle)
        except BaseException:
            with suppress(OSError):
                path.unlink()
            raise
