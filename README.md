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
- a fail-closed processor connecting classification and durable commits;
- immutable, hash-chained pending batches with exact-byte retry;
- a networkless collector outbox and managed-identity Azure Blob uploader;
- strict central acceptance, replay-ledger, and UTC rollup tooling;
- a dependency-free public Pages dashboard; and
- JSON Schemas and threat-model documentation.

Accepted promoted observations intentionally publish exact source IP addresses,
attempted usernames, and eligible suspected-probe paths. They are prominently
labeled **self-reported suspected probes**: source signatures establish
provenance, not truth, intent, ownership, compromise, or abuse.

## Development

Go 1.24 or newer is required.

```sh
go test ./...
go build ./cmd/...
```

See [`docs/protocol-v1.md`](docs/protocol-v1.md) for wire semantics and
[`docs/threat-model.md`](docs/threat-model.md) for trust boundaries. Agent
configuration is documented in [`docs/agent.md`](docs/agent.md). Publication
operations and the dependent data-repository contract are documented in
[`docs/publication.md`](docs/publication.md) and
[`docs/data-repository.md`](docs/data-repository.md).
