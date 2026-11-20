# Secret sinks (0.20.0)

`akdbx deliver-secret --sink NAME` writes a captured protected field into a
`KEY=VALUE` environment file that the operator defined before the broker
started. The agent names a sink; it never names a path, key, owner or
command. Linux only in this release.

## Configuration

Pass the file with `akdbx serve --secret-sinks PATH` or `AKDBX_SECRET_SINKS`.
The broker reads it once at start. The file must be a regular file owned by
root or by the broker account, not group- or other-writable, in directories
that no other account can change. Restart the broker after a change.

```json
{
  "version": 1,
  "helper_socket": "/run/akdbx-secret-sink.sock",
  "broker_uids": [1000],
  "sinks": {
    "example-env": {
      "writer": "root-helper",
      "field": "client_secret",
      "entry_origin": "https://github.com",
      "path": "/var/lib/example/example.env",
      "key": "GITHUB_CLIENT_SECRET",
      "owner": "example",
      "group": "example",
      "mode": "0600",
      "restart": {
        "user": "example",
        "argv": ["/usr/bin/systemctl", "--user", "restart", "example.service"],
        "env": {"XDG_RUNTIME_DIR": "/run/user/990"}
      }
    }
  }
}
```

| Key | Meaning |
| --- | --- |
| sink name | Lowercase letters, digits and inner hyphens; at most 64 characters. |
| `writer` | `direct`: the broker writes a file that its own account owns. `root-helper`: the root helper writes a file of another account. |
| `field` | The only captured field this sink accepts; `deliver-secret --field` must match. |
| `entry_origin` | The entry's main URL origin, or one of its additional URLs, must be exactly this HTTPS origin. |
| `path` | Absolute, normalized file path. No component may be a symlink. Every directory on the path must belong to root or the owner and must not be writable by other accounts (a root-owned sticky ancestor such as `/tmp` is allowed). An existing file must be a single-link regular file of the owner that group and others cannot write. A missing file is created. |
| `key` | Environment variable name. The file must set it at most once, as a plain `KEY=` line (an `export KEY=` line refuses, because systemd does not read it); it is replaced, or appended if absent. All other lines stay unchanged. A file that contains any quote (`"` or `'`) or backslash, even in a comment, is refused rather than parsed. |
| `owner`, `group`, `mode` | Applied to the file on every delivery, also when the value is already present. The mode must include `0600` and must not be group- or other-writable. |
| `restart` | Optional. An absolute `argv` (no shell), an optional `user` to run it as, and optional extra environment (not `PATH`). It runs after each delivery with a fixed `PATH`, no input and discarded output, and is stopped after 60 seconds. The root helper runs it as `user`, or as the sink owner by default, and never as root. |

Values are written unquoted, so delivery refuses any value outside
`A-Z a-z 0-9 . _ + / = : @ % , ^ -` (no `~`, which shells expand). Each write uses a temporary file in the
same directory, `fsync`, `rename` and a directory `fsync`, and refuses if the
file changed during the write. Deliveries take an advisory lock on the sink
directory and wait at most 15 seconds for it; another account that can read the
directory can hold that lock and make deliveries refuse, so keep sink
directories private to their owner. Other editors of the file do not take this
lock: a save that lands in the instant between the final check and the rename
can still be replaced, so do not edit a sink file while delivering to it.

## Root helper for files of another account

The broker service can run with `NoNewPrivileges=true`, so it cannot use
`sudo`. Instead, a root-owned helper listens on a root-owned socket. It reads
only the root-owned `/etc/akdbx/secret-sinks.json`, accepts only connections
from the UIDs in `broker_uids`, accepts only sinks with `"writer":
"root-helper"`, and replies with `{ok, restarted}`. The broker
checks that the socket file and its peer belong to root before it sends a
value. Use the same `/etc/akdbx/secret-sinks.json` for the broker's
`--secret-sinks`.

Install a root-owned copy of `src/akdbx/sink_helper.py`; it uses only the
standard library and does not import from the akdbx installation:

```sh
sudo install -o root -g root -m 0755 src/akdbx/sink_helper.py /usr/local/libexec/akdbx-secret-sink
sudo install -d -o root -g root -m 0755 /etc/akdbx
sudo install -o root -g root -m 0644 sinks.json /etc/akdbx/secret-sinks.json
```

`/etc/systemd/system/akdbx-secret-sink.socket`:

```ini
[Unit]
Description=akdbx secret sink helper socket

[Socket]
ListenStream=/run/akdbx-secret-sink.sock
SocketUser=root
SocketGroup=BROKER_GROUP
SocketMode=0660
Accept=yes
MaxConnections=4

[Install]
WantedBy=sockets.target
```

`/etc/systemd/system/akdbx-secret-sink@.service`:

```ini
[Unit]
Description=akdbx secret sink helper

[Service]
ExecStart=/usr/local/libexec/akdbx-secret-sink
StandardInput=socket
StandardOutput=socket
StandardError=null
RuntimeMaxSec=120
UMask=0077
PrivateTmp=yes
ProtectSystem=full
ProtectHome=read-only
```

`ProtectSystem=full` makes `/usr`, `/boot`, `/efi` and `/etc` read-only, and
`ProtectHome=read-only` does the same for `/home`, `/root` and `/run/user`, for
the helper. `PrivateTmp=yes` also gives the helper its own `/tmp` and `/var/tmp`, so a sink
there is never the host file, and `ReadWritePaths=` does not change that. Move
such a sink to a service directory such as `/var/lib/NAME`, which needs no
change. For a
sink in one of the read-only trees above, add `ReadWritePaths=` with only that
sink's directory in a drop-in for `akdbx-secret-sink@.service`.

Then `sudo systemctl daemon-reload && sudo systemctl enable --now
akdbx-secret-sink.socket`. Any process of the broker group can ask the helper
to write a value into a configured sink. It cannot read a value back, choose
another path or run another command. Keep the helper copy, its configuration
and both units owned by root.
