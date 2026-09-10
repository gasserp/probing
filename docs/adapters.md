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

## Cowrie

The Cowrie parser consumes JSON log entries and accepts only
`cowrie.login.failed`. Additional Cowrie fields are ignored; passwords and
session contents are never copied into normalized observations. The eventual
file tailer supplies a stable file cursor.

## Installation boundary

Nginx and Cowrie JSON files can be followed by the standalone adapter:

```sh
probing-file-adapter --format nginx --file /var/log/nginx/probing.jsonl
probing-file-adapter --format cowrie --file /var/log/cowrie/cowrie.json
```

It identifies files by device and inode, resumes at the last acknowledged byte
offset, detects rotation or truncation, bounds lines before parsing, and waits
for a durable core acknowledgement after every observation or checkpoint.
OpenSSH will use a separate journal adapter because journal cursors are not file
offsets.
