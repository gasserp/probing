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

The parser packages are currently library components. The next milestone wraps
them in standalone adapter processes with protocol negotiation, durable cursor
resume, acknowledgements, backpressure, and restart behavior.
