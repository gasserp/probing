# Protocol v1

## Terminology

- **Observation:** one normalized failed SSH authentication or HTTP request
  emitted by an adapter.
- **Promotion:** a classifier decision that an observation belongs to a
  suspected-probe episode. Promotions are upserts keyed by event ID.
- **Batch:** an immutable, signed collection of locally aggregated promoted
  observations.
- **Reported observation:** data asserted by a registered source. A signature
  proves provenance, not that the underlying network event occurred.

All timestamps are RFC 3339 UTC values with a `Z` suffix. All aggregation
intervals are half-open. Hour, day, month, and year views use observation time,
never ingestion or publication time.

## Adapter transport

The subprocess transport is UTF-8 NDJSON over adapter stdout to the core
reader. Adapter stderr is reserved for bounded diagnostics. Adapter stdin is
reserved for acknowledgements and control frames.

The first frame must be `hello` and list supported protocol versions. Every
subsequent line contains exactly one JSON object. The default maximum line size
is 64 KiB and is enforced before JSON decoding. Unknown properties, extra JSON
values, invalid UTF-8, and unsupported versions are rejected. The core records
the selected version before it accepts observation frames.

The core acknowledges an observation only after its event ID, source cursor,
content, and every classifier promotion caused by that observation are durably
committed in one transaction. An adapter must resume from its last acknowledged
cursor. A Unix-domain socket is a distinct, length-prefixed transport and will
have its own specification before implementation.

## SSH classifier

The defaults are:

- a 15-minute sliding event-time window;
- promotion on the sixth failure for one source-IP/username pair; and
- promotion when one source IP tries a sixth distinct username.

Crossing a threshold promotes the complete triggering window. A promoted
episode remains active until 15 minutes pass without a qualifying observation.
One observation may carry multiple rule IDs but is counted once. Promotion
updates use the stable event ID so adding a later rule does not increase counts.

Adapters emit only failed authentications. The classifier excludes configured
legitimate usernames and trusted CIDRs before they affect threshold state.
Events for a source must arrive in event-time order; the future ingestion layer
will buffer within a configured lateness watermark and quarantine older events.
Classifier state is bounded by configured source, per-source event, and total
event limits. Crossing a limit produces an error for quarantine rather than
silently dropping or promoting input.

Only observations older than the classifier watermark are eligible for a
batch. Promotion changes to an observation already assigned to an immutable
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

A registry entry reserves a unique source ID and records its public repository,
branch, active epoch, public signing key, classifier policy, and trust state.
Repository control is proven using a challenge nonce committed at a fixed path.

Key rotation requires old-key and new-key signatures. Lost-key recovery creates
a reviewed epoch discontinuity. Revocation prevents future acceptance but does
not silently remove historical observations. Emergency deletion uses an
audited tombstone and a separately approved history-removal procedure.
