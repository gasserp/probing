# Threat model

## Trust boundaries

Adapters, server logs, contributor repositories, batch contents, repository
paths, commit metadata, diagnostics, usernames, passwords, IP addresses, and
HTTP paths are untrusted. The core agent, protected registry, validator code from the
default branch, acceptance ledger, and publication workflow are trusted.

An adapter runs under a distinct OS identity with read-only access to only its
input logs. It has no publishing credential and no network access by default.
Only the core identity may access its signing and repository credential.

## Primary threats and controls

| Threat | Required control |
| --- | --- |
| Adapter compromise | Separate OS users, narrow log permissions, no credential inheritance, no shell execution |
| Log replay or rotation | Stable event IDs, durable source cursor, acknowledge only after durable commit |
| Fabricated sensor data | Visible per-source provenance; describe values as self-reported observations |
| Batch replacement or replay | Signed source/epoch/sequence, previous-hash chain, independent central acceptance ledger |
| Repository takeover | Challenge-based ownership proof, key rotation, revocation, epoch recovery |
| Workflow compromise | Never execute contributor code or workflows; validate data with fixed protected code |
| Resource exhaustion | Pre-download tree/blob limits plus bounded frames, records, bytes, runtime, diagnostics, and quarantine |
| Injection in UI or logs | Treat every external string as text; reject control characters and escape at every renderer |
| Legitimate SSH activity | Exclude successful auth, legitimate usernames, service accounts, and trusted CIDRs before thresholds |
| Real passwords from real users | Publish passwords only for registry sources of kind `decoy`; unset kind defaults to `host` |
| Legitimate HTTP paths | Require status plus signature and deployment-specific route exclusions |
| Sensitive public path data | Strip query/fragment, apply content exclusions, cap length, and document residual risk |
| Spot VM eviction | External checkpoint, idempotent recovery, explicit data-loss window, no availability claim |

## Non-goals

- Proving that an observation was malicious.
- Proving that different sensors observed the same human or machine.
- Running attacker-supplied commands or intentionally vulnerable production
  services.
- Publishing passwords from sources not registered as decoys.
- Storing successful login identities, request bodies, headers, cookies, query
  strings, or ordinary HTTP paths.
- Guaranteeing deletion of information already cloned or forked from public
  Git history.

## Public-data gate

Exact source IPs, attempted usernames, attempted passwords, and eligible paths
may be personal or sensitive data. Attempted passwords warrant particular care:
credential-stuffing traffic can replay secrets that are valid elsewhere, and a
misdirected legitimate login can deposit a real password against a sensor.
Passwords are therefore published only from sources the registry marks as
`decoy`: dedicated hosts that no legitimate user should log in to.
Public publishing must remain disabled until an operator explicitly accepts the
documented legal/privacy obligations and configures legitimate identities,
trusted networks, route exclusions, retention, and an emergency revocation
contact.
