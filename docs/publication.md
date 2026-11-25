# Publication operations

## Trust and privacy

Every public value is labeled **self-reported suspected probes**. An Ed25519
signature proves that the registered key signed a canonical batch; it does not
prove the event happened, establish who controlled an IP address, infer intent,
or show compromise. Classifier rules can produce false positives.

Accepted promoted observations intentionally preserve exact source IPs,
attempted SSH usernames, and eligible HTTP paths. Attempted SSH passwords are
published only for sources registered as `decoy`. HTTP query strings and
fragments are removed before durable storage. Operators must treat even paths
and usernames as potentially personal or hostile text. The dashboard inserts
all values with `textContent` and loads no third-party scripts.

## Dashboard

The hourly `pages` workflow publishes the dashboard from the committed
`probing-data` ledger and rollups. Besides copying the rollups, it runs
`probing-insights`, which writes `data/insights.json`: per-window totals for
the last 24 hours, 7 days, 30 days, and all time, split by attack vector
(SSH or HTTP), sensor, address family, source country, and origin network
(ASN), plus hourly and daily series.

Each window also lists, under `rules`, the 25 HTTP classifier rules with the
most observations. Published paths never include the query string, so
different exploit probes against `/index.php` or `/` look the same in
`paths`; the rule ID tells them apart, and the dashboard links each
`http/cve-…` rule to its CVE record. A probe that matched several rules
counts under each, so rule counts can add up to more than the HTTP total.
Rules are counted only for batches accepted after rule counting was added to
the ledger, so windows reaching back before that undercount them.

The rollups list only the top 100 values of each dimension per period, so
summing their `source_ips` undercounts. `insights.json` instead reads the
ledger's full per-period counters, so its IPv4 and IPv6 counts add up to the
total. The only exception is a period with more than 10,000 distinct source
addresses: the ledger folds the rest into an overflow count, which the
insights report as `unattributed`.

Countries and networks come from the DB-IP IP to Country Lite and IP to ASN
Lite databases (CC BY 4.0), which the workflow downloads once a month and
caches. A location describes where an address is registered or routed, not
who controls it, and VPNs, proxies, and cloud hosts make it a weak signal of
the operator's origin. If the download fails, the previous month's files are
used; with none at all, the dashboard is published without countries and
networks. The world map in `pages/world.json` is generated from Natural Earth
by `pages/tools/world-map.mjs`.

## Latency and retries

The collector closes work on UTC hour boundaries and waits a fixed 30-second
watermark before finalizing a batch. Normal latency is therefore one hour plus
up to that watermark, the uploader poll interval, the data workflow schedule,
and the Pages schedule. Spot eviction, GitHub delays, or a sequence
gap make staleness visible rather than silently dropping data.

SQLite/WAL commits observations, sequence state, payload hashes, and exact
signed envelope bytes. Outbox publication and receipts use atomic rename and
directory `fsync`. Azure creation uses `If-None-Match: *`, and GitHub
creation uses the contents API without a `sha`, which likewise never replaces
a file. Either way, an existing blob or file is success only when a bounded GET
is byte-identical. The data workflow deletes an Azure blob only after its
acceptance commit is pushed, and never deletes anything from a source's GitHub
repository.

Central acceptance simulates every batch against a deep copy of the ledger; a
batch that would cross the 64 MiB serialized ledger limit is quarantined
before sequence, chain, count, or dimension state changes. Each
source/IP/username/path/rule period dimension is capped at 10,000 distinct
values, but reaching the cap never quarantines a batch: values past the cap
roll into that dimension's overflow count so the period total stays exact.
Periods more than 31 days past their end are retained at reduced
resolution — non-hourly periods keep only their top 100 values per
dimension (the rest folded into overflow), and hourly periods are dropped
from the ledger and `hourly.json` entirely. The written ledger is
size-checked again before atomic replacement.

## Key lifecycle

The versioned migration script used by cloud-init and the `deploy` workflow creates the Ed25519 PKCS#8
key and lowercase UUID epoch once under
`/var/lib/probing`. The private key is mode `0600`, owned by UID/GID 65532,
mounted only into the networkless collector, and never placed in Git, Bicep,
environment variables, logs, or the uploader. The generated public key is safe
to copy into the registry after conversion to raw base64url.

Back up `state.db`, `state.db-wal`, `state.db-shm` when present, the source
epoch, the private key, and pending outbox files together while the collector
is stopped. Losing only the key makes unpublished and future batches
unrecoverable. Restore the complete set with original ownership and modes.

Each epoch has exactly one key; rotation within an epoch is not implemented
yet. Both planned rotation and lost-key recovery therefore create a new reviewed
source epoch with a new key, an explicit discontinuity. Never reset sequence
zero inside an existing epoch. Revoke the old registry entry by setting
`enabled` to false, without rewriting accepted history.

## Retention, cost, and recovery

Azure keeps uploaded envelopes for at most 30 days and enables seven-day soft
delete. Accepted data persists in compact Git rollups; exact envelope archival
is not promised. Storage capacity and operations, Blob egress to GitHub, the
VM, public IPv6, and Logic App may incur charges. Standard_LRS is locally
redundant, not regionally durable.

Manual recovery:

1. Stop `collector`, both adapters, and `uploader`; inspect disk space, file ownership, and
   bounded outbox contents without printing envelope fields.
2. Preserve `/var/lib/probing` before replacing the VM or OS disk.
3. Restore the complete state set, ensure the private key is `0600`, and start
   the collector before the uploader.
4. For an existing blob conflict, compare SHA-256 and exact bytes out of band.
   Never overwrite or delete the remote object merely to advance the source.
5. For sequence gaps, restore the missing envelope or perform reviewed epoch
   recovery. Do not edit the central ledger by hand.
6. If Pages is stale but ingestion is current, manually dispatch the `pages`
   workflow; it reads only the committed `probing-data` ledger and rollups,
   plus the cached geolocation databases.
7. If ingest runs succeed but the rollups stop advancing and
   `data/quarantine.json` gains `invalid_envelope` entries, the collector and
   acceptance disagree on the batch wire format. See
   [`infra/README.md`](../infra/README.md#redeploying-from-github-actions).
   Once acceptance matches, the next run accepts the retained blobs.
