# probing

An open deny list of IP addresses that probe SSH and HTTP services, built
from signed reports sent by sensors that admins run on non-production hosts.

Collect on dev, test, and decoy systems. Block in production.

## How it works

1. You run the `probing` agent on a host that no real user should touch.
   Each sensor is registered as one of two kinds:
   - `decoy`: a dedicated host with no legitimate users, such as a Cowrie
     honeypot;
   - `host`: a dev, test, or staging machine running real services.
2. Adapters read local Nginx and Cowrie logs (OpenSSH journal support is
   in progress). The agent flags every failed SSH login, except for
   usernames and networks you exclude, and HTTP path-traversal or
   sensitive-file requests.
3. Every hour the agent signs a batch of flagged observations with its
   Ed25519 key and uploads it.
4. Central ingestion checks the signature, sequence number, and hash chain
   of every batch, rejects anything malformed, and publishes aggregated
   results.
5. You pull the resulting list into production firewalls, reverse proxies,
   or fail2ban.

## Why not production

A production host sees legitimate users. Mistyped passwords, stale
credentials, and broken clients would put real customers on a public list,
together with the usernames they tried. Exact source IPs, usernames, and
request paths are published. Attempted passwords are published only from
`decoy` sensors, where no real user should ever type one.

A dev, test, or decoy host has little or no legitimate traffic, so almost
everything that fails there is a scanner. That keeps false positives low.

Production consumes the list. It never feeds it.

## Status

Early. Working today:

- adapter protocol, SSH and HTTP classifiers, signed hash-chained batches;
- a hardened Docker Compose sensor with Nginx and Cowrie decoys;
- central validation, replay protection, and hourly to yearly rollups;
- a public dashboard: <https://gasserp.github.io/probing/>.

Not yet available:

- a downloadable deny list (plain text, nftables, ipset);
- onboarding for sensors outside the reference Azure deployment.

Until those land, the published data is useful for research, not for
automated blocking.

## Caveats

Everything published is labeled **self-reported suspected probes**. A
signature proves which sensor sent a report, not that the traffic was
malicious or that the address still belongs to the same party. Treat
entries as evidence with an expiry date, not a verdict.

## Running a sensor

- [`docs/agent.md`](docs/agent.md): agent configuration and exclusions
- [`docs/adapters.md`](docs/adapters.md): supported log formats
- [`deploy/`](deploy/): reference Docker Compose stack
- [`infra/README.md`](infra/README.md): Azure reference deployment

Exclude your own usernames, service accounts, and trusted networks in the
agent config before enabling publication.

## Development

Requires Go 1.24 or newer.

```sh
go test ./...
go build ./cmd/...
```

Design documents:

- [`docs/protocol-v1.md`](docs/protocol-v1.md): wire format and batch rules
- [`docs/threat-model.md`](docs/threat-model.md): trust boundaries
- [`docs/publication.md`](docs/publication.md): publication operations
- [`docs/data-repository.md`](docs/data-repository.md): central data repository contract
