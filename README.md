# probing

`probing` is a portable telemetry agent for collecting and publishing
self-reported suspected SSH and HTTP probes. Azure is a reference deployment;
the agent and adapter protocol are the product.

The project is protocol-first. The current milestone provides:

- versioned observation and immutable batch models;
- RFC 8785 canonicalization and Ed25519 batch signatures;
- precise SSH threshold and HTTP traversal classifiers;
- a bounded NDJSON adapter framing contract;
- normalized parsers for Nginx JSON, OpenSSH journal JSON, and Cowrie JSON;
- SQLite/WAL-backed atomic cursor, observation, and promotion storage;
- immutable, hash-chained pending batches with exact-byte retry; and
- JSON Schemas and threat-model documentation.

Publishing exact source IP addresses, attempted usernames, and eligible
suspected-probe paths is intentionally disabled until the GitHub registry,
acceptance ledger, privacy gate, and bounded ingestion workflow are complete.

## Development

Go 1.24 or newer is required.

```sh
go test ./...
```

See [`docs/protocol-v1.md`](docs/protocol-v1.md) for wire semantics and
[`docs/threat-model.md`](docs/threat-model.md) for trust boundaries.
