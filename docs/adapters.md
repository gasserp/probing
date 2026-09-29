# Source adapters

Adapters normalize server-specific log entries into
`probing.observation/v1`. They do not classify, aggregate, sign, or publish
data and must not receive the core agent's credentials.

## Nginx

The Nginx parser accepts a deliberately minimal JSON access-log format:

```nginx
log_format probing escape=json
  '{"time":"$time_iso8601","remote_addr":"$remote_addr",'
  '"request_uri":"$request_uri","status":$status}';
```

The eventual tailer supplies a stable cursor composed from file identity and
byte offset. Unknown JSON fields are rejected so accidentally adding headers,
bodies, or other sensitive fields cannot silently widen collection.

## OpenSSH

The OpenSSH parser consumes `journalctl -o json` records and accepts only
`Failed password`, `Failed publickey`, and `Failed keyboard-interactive/pam`
messages. It deliberately ignores separate `Invalid user` messages because
OpenSSH can emit both messages for one authentication attempt. The systemd
journal cursor is the durable source cursor.

The username is attacker-chosen and sshd logs it verbatim, spaces included.
The parser therefore anchors the whole message and takes the address from the
final `from ADDR port N ssh2` that sshd appends, so a username such as
`x from 192.0.2.1 port 22` cannot substitute its own address. Publickey
failures may end with the key type and SHA256 fingerprint; certificate
details, which embed client-chosen IDs, do not match and are skipped.

## Cowrie

The Cowrie parser consumes JSON log entries and accepts only
`cowrie.login.failed`. It copies the source IP, username, and attempted
password. The password is dropped when it is empty, longer than 256 bytes, not
valid UTF-8, or contains control characters. Other Cowrie fields, including
session contents, are ignored. Central ingestion publishes passwords only for
sources registered as `decoy` (see
[`data-repository.md`](data-repository.md#source-kinds)). The file tailer
supplies a stable file cursor.

## Installation boundary

Nginx and Cowrie JSON files can be followed by the standalone adapter:

```sh
probing-file-adapter --format nginx --file /var/log/nginx/probing.jsonl
probing-file-adapter --format cowrie --file /var/log/cowrie/cowrie.json
```

Production also requires `--socket /ipc/adapter.sock`. The reference Compose
deployment runs Nginx and Cowrie adapters in separate `network_mode: none`
containers under UIDs 65533 and 65534. Each receives only its own read-only log
mount and private socket directory. The signing key, SQLite state, outbox, and
the other adapter's files are absent from its mount namespace.

It identifies files by device and inode, resumes at the last acknowledged byte
offset, detects rotation or truncation, bounds lines before parsing, and waits
for a durable core acknowledgement after every observation or checkpoint.

OpenSSH uses `probing-journal-adapter`, because journal cursors are not file
offsets:

```sh
probing-journal-adapter -directory /journal -unit ssh.service -socket /ipc/adapter.sock
```

It runs `journalctl` (never a shell) against the host's `/var/log/journal`,
mounted read-only, and selects records by `_SYSTEMD_UNIT`, a field journald
sets and local processes cannot forge. It emits a checkpoint for every record
and an observation for each failed login. On resume it first drains every
stored record after the acknowledged cursor without `--follow`, then follows
from the last one: `journalctl --follow` can skip records that sit in an
earlier boot's journal file. Without a cursor it starts at the end of the
journal. The [`deploy/openssh/`](../deploy/openssh/) stack runs it networkless
under UID 65533, with the host's `systemd-journal` group as its only extra
privilege.
