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
