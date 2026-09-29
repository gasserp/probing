# Azure deployment

This template creates the collector VM and managed-identity Blob publication
path. Public ports 22 and 80 are decoys; real SSH is disabled from first boot
and administration uses Azure Run Command.

Set the target subscription:

```sh
subscription=18d04159-3160-4eff-8437-3a87b95374ef
computeProfile=spot-low-cost
repositoryRef=<reviewed-full-commit-sha>
```

Preview the deployment. `dual-stack` is the steady-state network profile (see
below):

```sh
az deployment sub what-if \
  --subscription "$subscription" \
  --location westeurope \
  --template-file infra/main.bicep \
  --parameters \
    networkProfile=dual-stack \
    computeProfile="$computeProfile" \
    repositoryRef="$repositoryRef" \
    adminSshPublicKey="$(cat ~/.ssh/id_ed25519.pub)"
```

Deploy after reviewing the preview:

```sh
az deployment sub create \
  --subscription "$subscription" \
  --name probing-first-collector \
  --location westeurope \
  --template-file infra/main.bicep \
  --parameters \
    networkProfile=dual-stack \
    computeProfile="$computeProfile" \
    repositoryRef="$repositoryRef" \
    adminSshPublicKey="$(cat ~/.ssh/id_ed25519.pub)"
```

When the VM already exists, add `includeCloudInit=false` to both commands:
Azure refuses to change `osProfile.customData` on an existing VM, and
cloud-init only runs at first boot anyway. Code updates reach an existing VM
through the `deploy` workflow described below, not through Bicep.

Custom role names must be unique in the Entra ID directory. If a deployment
fails with `RoleDefinitionWithSameNameExists`, a role with that name exists
under a different ID, for example one created by hand. Remove its assignments
and delete it, then redeploy:

```sh
az role definition list --custom-role-only true \
  --query "[?starts_with(roleName, 'probing-collector-')].{roleName:roleName, id:name}" -o table
```

Confirm cloud-init and every container succeeded:

```sh
az vm run-command invoke \
  --subscription "$subscription" \
  --resource-group probing-collector \
  --name probing-collector-01 \
  --command-id RunShellScript \
  --scripts 'set -eu; cloud-init status --wait --long; cd /opt/probing; docker compose -f deploy/docker-compose.yml config --format json | python3 deploy/validate-compose.py; running="$(docker compose -f deploy/docker-compose.yml ps --services --status running)"; for service in collector uploader nginx-adapter cowrie-adapter cowrie ingress nginx; do printf "%s\n" "$running" | grep -qx "$service"; done; test "$(stat -c %a /var/lib/probing/source-private-key.pem)" = 600; curl --fail --silent --show-error http://127.0.0.1/health; timeout 5 bash -c "exec 3<>/dev/tcp/127.0.0.1/22"; docker compose -f deploy/docker-compose.yml ps'
```

## Existing VM migration

`infra/migrate-v2.sh` is the authoritative idempotent fresh-install and
existing-VM mechanism. It refuses tracked checkout modifications and
half-present key/epoch identity, preserves SQLite/WAL/outbox/key files, creates
the two UID-owned IPC directories, atomically writes only non-secret storage
configuration, checks out the explicit ref detached, builds/pulls images,
starts services, and verifies Compose mounts, UIDs, network modes, key modes,
health, and decoy ports.

After deploying Bicep with `includeCloudInit=false`, invoke the reviewed local
script through Run Command:

```sh
storageAccount=$(az deployment sub show --subscription "$subscription" \
  --name probing-first-collector \
  --query properties.outputs.storageAccountName.value -o tsv)
storageContainer=$(az deployment sub show --subscription "$subscription" \
  --name probing-first-collector \
  --query properties.outputs.storageContainerName.value -o tsv)

# Run Command exports each --parameters entry as an environment variable and
# rejects hyphenated names, so migrate-v2.sh's --flags are passed by feeding the
# script to `sh` on stdin instead (the deploy workflow does the same).
az vm run-command invoke \
  --subscription "$subscription" \
  --resource-group probing-collector \
  --name probing-collector-01 \
  --command-id RunShellScript \
  --scripts "$(printf '/bin/sh -s -- --storage-account %q --storage-container %q --repository-ref %q <<'\''PROBING_MIGRATE_EOF'\''\n' \
      "$storageAccount" "$storageContainer" "$repositoryRef"; cat infra/migrate-v2.sh; printf 'PROBING_MIGRATE_EOF\n')"
```

Run the same command again to prove idempotency before registering the emitted
epoch/public key.

`networkProfile=dual-stack` is also the permanent steady-state profile: most
scanners only probe IPv4, so the public IPv4 address stays attached instead of
being torn down after bootstrap. To fall back to IPv6-only, redeploy with
`networkProfile=ipv6-only` and then delete the now-detached IPv4 resource
(subscription deployments are incremental, so it won't be removed for you):

```sh
az deployment sub create \
  --subscription "$subscription" \
  --name probing-first-collector \
  --location westeurope \
  --template-file infra/main.bicep \
  --parameters \
    networkProfile=ipv6-only \
    computeProfile="$computeProfile" \
    includeCloudInit=false \
    repositoryRef="$repositoryRef" \
    adminSshPublicKey="$(cat ~/.ssh/id_ed25519.pub)"
az network public-ip delete \
  --subscription "$subscription" \
  --resource-group probing-collector \
  --name probing-collector-01-ipv4
az network public-ip show \
  --subscription "$subscription" \
  --resource-group probing-collector \
  --name probing-collector-01-ipv4
```

Use `computeProfile=spot-low-cost` for `Standard_A1_v2` Spot with a default
maximum price of USD 0.02/hour. Spot has no SLA. This profile also creates a
consumption Logic App whose managed identity can only manage this VM. It calls
the idempotent VM start operation every 15 minutes, so an evicted VM retries
when Spot capacity becomes available while retaining its disk and IPv6 address.

Capture the non-secret outputs for GitHub repository variables (`-o json`
matters if your default output format is `table`, which prints nothing for
nested objects):

```sh
az deployment sub show \
  --subscription "$subscription" \
  --name probing-first-collector \
  --query properties.outputs -o json
```

Two repositories consume them, each with its own identity: `probing-data`'s
ingest workflow ([`docs/data-repository.md`](../docs/data-repository.md#ingestion-workflow),
with `AZURE_CLIENT_ID` = `githubClientId`) and this repository's `deploy`
workflow (below, with `AZURE_CLIENT_ID` = `githubDeployClientId`). No output
is a credential. Extract the source epoch and public key with Azure Run
Command; never print the private key:

```sh
az vm run-command invoke \
  --subscription "$subscription" \
  --resource-group probing-collector \
  --name probing-collector-01 \
  --command-id RunShellScript \
  --scripts 'cat /var/lib/probing/source-epoch; cat /var/lib/probing/source-public-key.pem'
```

## Redeploying from GitHub Actions

The `deploy` workflow (`.github/workflows/deploy.yml`) redeploys this VM without
a human running `az`. It re-runs the same authoritative `infra/migrate-v2.sh`
through Azure Run Command, so it inherits every safety check and preserves the
key, epoch, SQLite, and outbox state. Run it from the repository's **Actions →
deploy → Run workflow** and either leave `ref` blank — deploying the ref pinned
in [`deploy/VERSION`](../deploy/VERSION) (default `main`, i.e. latest) — or type
a branch, tag, or full commit SHA to deploy a specific artefact version. The VM
checks out that ref and rebuilds the collector, uploader, and adapter images
from source, so the git ref *is* the artefact version. To change the default
deployed version, edit `deploy/VERSION` in a PR (pin it to a reviewed full SHA
for production).

`deploy/VERSION` on `main` is also what `probing-data`'s ingest workflow builds
its acceptance binary from, so the collector and acceptance move together. The
collector must never emit a batch wire format (`protocol/`, `schemas/`) that
acceptance cannot validate — acceptance quarantines every such batch as
`invalid_envelope` and the rollups freeze. The workflow resolves the requested
ref to a commit and refuses to deploy it unless it matches the acceptance
commit, is an ancestor of it (a rollback), or leaves `protocol/` and `schemas/`
unchanged. Land wire-format changes on `main` first; acceptance picks them up on
its next hourly run, and any batches quarantined in between are accepted then,
because quarantined blobs stay in the container.

One-time setup in the **`gasserp/probing`** repository (distinct from the
`probing-data` variables above):

1. Deploy `infra/main.bicep` so the deploy identity, its custom
   `probing-collector-deployer` role (start + Run Command on this VM only), and
   its GitHub federation exist. The default federation subject,
   `repo:gasserp@13432519/probing@1364631664:environment:production`, uses the
   stable-ID form GitHub issues for this repository
   (`owner@owner_id/repo@repo_id`), like the `probing-data` credential. For a
   fork, override `githubDeploySubject` with your own owner and repository IDs.
   If the workflow's Azure login fails, the error prints the `sub` GitHub
   actually sent.
2. Create a GitHub **Environment** named `production` in this repo (Settings →
   Environments). Add required reviewers there if you want an approval gate
   before each redeploy. The environment name must match `githubDeploySubject`.
3. Set these **repository variables** (Settings → Secrets and variables →
   Actions → Variables) from the Bicep outputs:

   | Variable | Source output |
   |---|---|
   | `AZURE_CLIENT_ID` | `githubDeployClientId` (the deploy identity — **not** `githubClientId`) |
   | `AZURE_TENANT_ID` | `githubTenantId` |
   | `AZURE_SUBSCRIPTION_ID` | `githubSubscriptionId` |
   | `PROBING_STORAGE_ACCOUNT` | `storageAccountName` |
   | `PROBING_STORAGE_CONTAINER` | `storageContainerName` |
   | `PROBING_RESOURCE_GROUP` | `resourceGroupName` (optional; defaults to `probing-collector`) |
   | `PROBING_VM_NAME` | the VM name (optional; defaults to `probing-collector-01`) |

The workflow logs in with OIDC (no stored secret), starts the VM if Spot
eviction deallocated it, runs the migration, and fails unless the script prints
its completion sentinel.

Sensors outside Azure, such as the Raspberry Pi `host` sensor, upload to the
same container with their own service principal instead of a managed identity;
see [`docs/raspberry-pi.md`](../docs/raspberry-pi.md#4-create-the-upload-credential-workstation).

Standard_LRS capacity, Blob operations, public endpoint egress, the VM, IPv6
address, and the Spot-restarter Logic App can all incur charges. The 30-day
lifecycle policy is a cost ceiling, not an archival promise.

Delete every resource:

```sh
az group delete \
  --subscription "$subscription" \
  --name probing-collector
```
