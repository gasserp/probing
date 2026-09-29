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
2. Adapters read local Nginx and Cowrie logs, or the systemd journal of a
   real OpenSSH server. The agent flags every failed SSH login, except for
   usernames and networks you exclude, and HTTP path-traversal or
   sensitive-file requests.
3. Every hour the agent signs a batch of flagged observations with its
   Ed25519 key and commits it to a public GitHub repository that you own.
4. You register the sensor's public key and batch repository with a pull
   request to [`probing-data`](https://github.com/gasserp/probing-data).
   From then on, central ingestion pulls your batches every hour, checks the
   signature, sequence number, and hash chain of each one, rejects anything
   malformed, and publishes aggregated results.
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
- a `host` sensor for a machine's real OpenSSH server, read from the
  systemd journal, with a Raspberry Pi install script;
- publication to your own public GitHub repository, pulled centrally, so
  contributing needs no access to anyone else's infrastructure;
- central validation, replay protection, and hourly to yearly rollups;
- a public dashboard: <https://gasserp.github.io/probing/>.

Not yet available:

- a downloadable deny list (plain text, nftables, ipset);
- a GitHub publishing option for the Cowrie decoy stack in
  [`deploy/`](deploy/). Today only the OpenSSH host sensor supports it.

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
- [`docs/raspberry-pi.md`](docs/raspberry-pi.md): Raspberry Pi `host` sensor
  on a real OpenSSH server
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
