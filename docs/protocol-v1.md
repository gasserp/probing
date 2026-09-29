# Protocol v1

## Terminology

- **Observation:** one normalized failed SSH authentication or HTTP request
  emitted by an adapter.
- **Promotion:** a classifier decision that an observation is a suspected
  probe and eligible for publication. Promotions are upserts keyed by event ID.
- **Batch:** an immutable, signed collection of locally aggregated promoted
  observations.
- **Reported observation:** data asserted by a registered source. A signature
  proves provenance, not that the underlying network event occurred.

All timestamps are RFC 3339 UTC values with a `Z` suffix. All aggregation
intervals are half-open. Hour, day, month, and year views use observation time,
never ingestion or publication time.

## Adapter transport

The local transport is UTF-8 NDJSON over one full-duplex Unix stream socket per
adapter. Adapter stderr is reserved for bounded container diagnostics. The
same socket carries acknowledgements and control frames from the core.

The first frame must be `hello` and list supported protocol versions. Every
subsequent line contains exactly one JSON object. The default maximum line size
is 64 KiB and is enforced before JSON decoding. Unknown properties, extra JSON
values, invalid UTF-8, and unsupported versions are rejected. The core records
the selected version before it accepts observation frames.

The core acknowledges an observation only after its event ID, source cursor,
content, and every classifier promotion caused by that observation are durably
committed in one transaction. On every socket reconnect, an adapter must resume
from the durable cursor sent by the core. Socket filesystem permissions and
per-adapter mount namespaces are part of the deployment boundary; framing
limits do not replace that isolation.

## SSH classifier

The classifier is stateless: every failed authentication is promoted
immediately under rule `ssh/all-attempts-v1`. There is no event-time window,
attempt threshold, or episode state. One observation may carry multiple rule
IDs but is counted once. Promotion updates use the stable event ID so adding a
later rule does not increase counts.

Adapters emit only failed authentications. The classifier drops configured
legitimate usernames and trusted CIDRs before promotion. When
the source captures the attempted password (Cowrie does; the OpenSSH journal
never exposes it) it is retained on the observation as an optional field.
Central ingestion aggregates it into its own published dimension only when the
registry marks the source as `decoy`. A password
that is empty, oversized, or non-printable is dropped without discarding the
failed authentication it accompanies.

Only observations older than the batch watermark, 30 seconds after the UTC
hour boundary, are eligible for a batch. Promotion changes to an observation
already assigned to an immutable
batch are rejected. This makes classifier finality an explicit precondition of
batch creation.

## HTTP classifier

The query and fragment are removed and never retained. Classification inspects
the raw path and at most two percent-decoding passes. It requires:

1. a configured eligible response status;
2. a traversal or sensitive-file signature; and
3. no match against legitimate-route or sensitive-content exclusions.

The published value is the exact request path after query/fragment removal,
not the decoded representation. It is an exact eligible suspected-probe path;
the system does not claim that intent or absence of personal data can be
inferred from a status code and path.

The local collision hash also uses this privacy-safe path projection. It never
hashes the discarded query or fragment.

## Immutable batches

A batch identity is `(source_id, source_epoch, sequence)`. Sequence is a
canonical unsigned decimal string scoped to the epoch. Sequence zero has no
predecessor; every later batch names the previous accepted payload hash.
Retries must publish byte-identical content. The deterministic Azure blob name
is
`source_id/source_epoch/<sequence-digit-count>-<sequence>/<payload-hash>.json`.
The length prefix preserves lexical sequence order without weakening canonical
decimal validation. Conflicting content at an accepted identity is rejected.

Payloads are canonicalized with RFC 8785. Ed25519 signs:

```text
"probing-batch-v1\0" || canonical_json(payload)
```

The SHA-256 payload hash covers the same bytes. The signature envelope is not
part of the signed payload.

Counts are limited to 9,007,199,254,740,991 so every signed JSON integer is
exactly representable by the IEEE-754 data model required by RFC 8785. A batch
payload is at most 1 MiB, has at most 10,000 records, 744 hourly buckets per
record, 16 rule IDs per record, and a maximum 31-day observation window.

Late observations are carried by a later sequence with their original
observation timestamps. Derived calendar views are rebuilt from accepted
batches. The central acceptance ledger, not contributor Git history, is
authoritative for accepted identity/hash pairs.

## Git volume policy

The central repository stores only the compact acceptance ledger and derived
rollups. Exact immutable envelopes remain in Azure Blob for 30 days, then the
lifecycle policy deletes them. GitHub ingestion deletes accepted or
byte-identical replay blobs only after the resulting data-repository commit.
Invalid blobs remain for investigation until retention applies. Acceptance is
bounded to 256 files, 64 MiB, 64 registered sources, 100,000 accepted batches,
and two minutes per invocation. Pending-batch retrieval is one batch at a time,
and the local store refuses to create more than 128 unpublished batches.

## Registration and recovery

A registry entry in `probing-data` reserves a unique source ID and records its
epoch, key ID, public signing key, blob prefix, kind (`decoy` or `host`), and
whether it is `enabled`. Registration is a reviewed pull request to that
registry. Setting `enabled` to false revokes the entry: later batches for it
are quarantined, but historical observations are not removed.

Each epoch has exactly one key. Rotating a key, whether planned or after a
loss, means registering a new epoch with the new key, which is an explicit,
reviewed discontinuity, and disabling the old entry.

Planned, not yet implemented: proof of repository control through a
committed challenge nonce, key rotation within an epoch authorized by both
old-key and new-key signatures, and emergency deletion through an audited
tombstone with a separately approved history-removal procedure.
