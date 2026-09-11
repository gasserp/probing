# Agent daemon

`probing-agent` supervises trusted adapter executables. Adapters receive no
publishing credentials. Each process must:

1. emit one `hello` frame on stdout;
2. read one `resume` frame from stdin;
3. emit `observation` or `checkpoint` frames; and
4. wait for the matching `ack` before advancing.

The agent stops if an adapter violates the protocol or if durable state and
classifier state might diverge.

## Configuration

```json
{
  "database_path": "/var/lib/probing/state.db",
  "adapters": [
    {
      "id": "nginx-main",
      "command": "/usr/local/bin/probing-adapter-nginx",
      "args": ["--file", "/var/log/nginx/probing.jsonl"]
    }
  ],
  "ssh": {
    "window_seconds": 900,
    "pair_threshold": 6,
    "distinct_username_threshold": 6,
    "excluded_usernames": ["deploy"],
    "trusted_cidrs": ["2001:db8:1234::/48"]
  },
  "http": {
    "eligible_statuses": [400, 403, 404],
    "excluded_exact_paths": ["/health"],
    "excluded_path_prefixes": ["/downloads/"]
  },
  "publication": {
    "source_id": "gasserp-azure-weu-01",
    "source_epoch_path": "/var/lib/probing/source-epoch",
    "private_key_path": "/var/lib/probing/source-private-key.pem",
    "key_id": "gasserp-azure-weu-01-ed25519-1",
    "classifier_version": "probing-classifier-v1",
    "outbox_directory": "/var/lib/probing/outbox"
  }
}
```

Run:

```sh
go run ./cmd/probing-agent -config /etc/probing/config.json
```

Adapter commands are trusted local configuration and are executed directly,
never through a shell. Diagnostics are quoted and line-bounded before logging.
The daemon handles `SIGINT` and `SIGTERM`.

Publication is optional outside the reference deployment. When configured, the
agent runs an hourly UTC batch pump. At hour `H`, only observations older than
`H - ssh.window_seconds` are eligible. The pump writes the exact signed
envelope bytes by temporary-file, `fsync`, and rename, and never modifies them
on retry. It accepts only a canonical, bounded receipt matching the source,
epoch, sequence, payload hash, envelope hash, and deterministic blob name.

The PKCS#8 Ed25519 private-key file must be a regular file with mode `0600`.
Neither the key nor the SQLite database belongs on a networked mount. A receipt
is only an upload acknowledgement; the local database remains authoritative
until it durably records the receipt digest.
