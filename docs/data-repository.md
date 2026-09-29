# `gasserp/probing-data` contract

The data repository is a separate public repository. This repository supplies
the validator and renderer; it does not create or deploy `probing-data`.

## Required tree

```text
registry/sources.json
data/acceptance-ledger.json       # created by probing-ingest if absent
data/quarantine.json              # generated
data/rollups/hourly.json          # generated
data/rollups/daily.json           # generated
data/rollups/monthly.json         # generated
data/rollups/yearly.json          # generated
```

`registry/sources.json` is strict JSON:

```json
{
  "schema_version": "probing.registry/v1",
  "repository": "gasserp/probing-data",
  "sources": [
    {
      "source_id": "gasserp-azure-weu-01",
      "source_epoch": "replace-with-persistent-lowercase-uuid",
      "key_id": "gasserp-azure-weu-01-ed25519-1",
      "public_key": "base64url-without-padding-of-the-raw-32-byte-ed25519-key",
      "blob_prefix": "gasserp-azure-weu-01/replace-with-persistent-lowercase-uuid/",
      "kind": "decoy",
      "enabled": true
    }
  ]
}
```

### Source kinds

`kind` classifies the sensor and is set by the registry maintainer, not by
the sensor:

| Kind | Meaning | Passwords published |
|---|---|---|
| `decoy` | Dedicated host with no legitimate users (e.g. Cowrie) | Yes |
| `host` | Dev, test, or staging machine running real services | No |

An omitted `kind` is treated as `host`. Any other value makes the registry
invalid. Batches from a `host` source are accepted in full, but their
passwords are not added to the ledger or rollups. A kind change applies to
batches accepted after the change; passwords already published from a source
reclassified away from `decoy` require the emergency deletion procedure.

Before a live source key exists, the accepted bootstrap registry is:

```json
{"schema_version":"probing.registry/v1","repository":"gasserp/probing-data","sources":[]}
```

An empty registry is valid and causes every downloaded blob to quarantine as
unregistered. Running `probing-ingest` with this registry and an empty input
directory creates the canonical empty ledger, quarantine file, four rollup
files, and accepted manifest.

Convert the generated PEM public key to the required raw base64url value:

```sh
openssl pkey -pubin -in source-public-key.pem -outform DER |
  tail -c 32 |
  basenc --base64url |
  tr -d '='
```

Repository identity is passed separately to the CLI and must exactly match the
registry. Unknown JSON fields, disabled or unknown source epochs, unknown key
IDs, invalid signatures, noncanonical envelope bytes, wrong blob names, replay
conflicts, sequence gaps, hash-chain mismatches, observation windows ending
after batch creation, and creation times more than five minutes in the future
are quarantined using only a bounded relative filename, size, SHA-256, and
reason code. Quarantine never copies hostile batch content.

## Ingestion workflow

The `main` workflow in `probing-data` must have `id-token: write` and
`contents: write`. It logs in with `azure/login`, downloads the configured Blob
container using `--auth-mode login`, checks out `gasserp/probing`, builds
`./cmd/probing-ingest`, then runs:

```sh
probing-ingest \
  -repo "$GITHUB_WORKSPACE" \
  -input "$RUNNER_TEMP/probing-blobs" \
  -repository "$GITHUB_REPOSITORY" \
  -accepted-manifest "$RUNNER_TEMP/accepted.json"
```

Exit `0` means every candidate was accepted or was a byte-identical replay.
Exit `3` means valid candidates were processed but at least one candidate was
quarantined; commit the generated ledger, rollups, and quarantine metadata, but
leave the job visibly failed after cleanup. Any other nonzero exit is fatal.

Commit and push generated changes before deleting blobs. After the push
succeeds, iterate only `.blobs[]` from `accepted.json` and delete those exact
names with `az storage blob delete --auth-mode login`. Never use
`delete-batch`: quarantined blobs must remain available until the 30-day
lifecycle rule removes them. A crash before deletion produces a harmless
byte-identical replay on the next run.

Required GitHub repository variables are:

| Variable | Bicep output |
|---|---|
| `AZURE_CLIENT_ID` | `githubClientId` |
| `AZURE_TENANT_ID` | `githubTenantId` |
| `AZURE_SUBSCRIPTION_ID` | `githubSubscriptionId` |
| `PROBING_STORAGE_ACCOUNT` | `storageAccountName` |
| `PROBING_STORAGE_CONTAINER` | `storageContainerName` |
| `PROBING_STORAGE_RESOURCE_GROUP` | `resourceGroupName` |

There are no account keys, SAS values, PATs, or other publication secrets.
GitHub's branch subject is fixed to
`repo:gasserp@13432519/probing-data@1365491239:ref:refs/heads/main` — GitHub's
stable-ID subject format (`owner@owner_id/repo@repo_id`), not the plain
`owner/repo` form.

## Acceptance and rollups

The acceptance identity is `(source_id, source_epoch, sequence)`. The ledger
stores one payload hash and deterministic blob name per accepted sequence plus
compact dimension accumulators. It is the replay authority; Git history is
not. Each batch record is added once regardless of how many `rule_ids` it
contains.

UTC hourly buckets feed hourly, daily, monthly, and yearly accumulators.
Generated public files expose totals, source ID/epoch/kind provenance, and the
top 100 exact source IPs, attempted usernames, attempted passwords, and
eligible paths per period. Passwords come only from `decoy` sources that
capture them (such as Cowrie); the OpenSSH journal never exposes them.
Ledger and generated files are written through `fsync` plus atomic rename, with
the ledger written last.
