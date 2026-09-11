# Publication operations

## Trust and privacy

Every public value is labeled **self-reported suspected probes**. An Ed25519
signature proves that the registered key signed a canonical batch; it does not
prove the event happened, establish who controlled an IP address, infer intent,
or show compromise. Classifier rules can produce false positives.

Accepted promoted observations intentionally preserve exact source IPs,
attempted SSH usernames, and eligible HTTP paths. HTTP query strings and
fragments are removed before durable storage. Operators must treat even paths
and usernames as potentially personal or hostile text. The dashboard inserts
all values with `textContent` and loads no third-party scripts.

## Latency and retries

The collector closes work on UTC hour boundaries and uses the SSH classifier
window as its finality watermark. Normal latency is therefore one hour plus up
to the classifier window, the uploader poll interval, the data workflow
schedule, and the Pages schedule. Spot eviction, GitHub delays, or a sequence
gap make staleness visible rather than silently dropping data.

SQLite/WAL commits observations, sequence state, payload hashes, and exact
signed envelope bytes. Outbox publication and receipts use atomic rename and
directory `fsync`. Azure creation uses `If-None-Match: *`; an existing blob is
success only when a bounded GET is byte-identical. The data workflow deletes a
blob only after its acceptance commit is pushed.

## Key lifecycle

Cloud-init creates the Ed25519 PKCS#8 key and lowercase UUID epoch once under
`/var/lib/probing`. The private key is mode `0600`, owned by UID/GID 65532,
mounted only into the networkless collector, and never placed in Git, Bicep,
environment variables, logs, or the uploader. The generated public key is safe
to copy into the registry after conversion to raw base64url.

Back up `state.db`, `state.db-wal`, `state.db-shm` when present, the source
epoch, the private key, and pending outbox files together while the collector
is stopped. Losing only the key makes unpublished and future batches
unrecoverable. Restore the complete set with original ownership and modes.

Planned rotation registers a new key ID and requires the existing protocol's
old-key/new-key authorization before deployment. Lost-key recovery creates a
new reviewed source epoch and an explicit discontinuity; never reset sequence
zero inside an existing epoch. Revoke the old registry entry without rewriting
accepted history.

## Retention, cost, and recovery

Azure keeps uploaded envelopes for at most 30 days and enables seven-day soft
delete. Accepted data persists in compact Git rollups; exact envelope archival
is not promised. Storage capacity and operations, Blob egress to GitHub, the
VM, public IPv6, and Logic App may incur charges. Standard_LRS is locally
redundant, not regionally durable.

Manual recovery:

1. Stop `collector` and `uploader`; inspect disk space, file ownership, and
   bounded outbox contents without printing envelope fields.
2. Preserve `/var/lib/probing` before replacing the VM or OS disk.
3. Restore the complete state set, ensure the private key is `0600`, and start
   the collector before the uploader.
4. For an existing blob conflict, compare SHA-256 and exact bytes out of band.
   Never overwrite or delete the remote object merely to advance the source.
5. For sequence gaps, restore the missing envelope or perform reviewed epoch
   recovery. Do not edit the central ledger by hand.
6. If Pages is stale but ingestion is current, manually dispatch the `pages`
   workflow; it reads only committed `probing-data` rollups.
