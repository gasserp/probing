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

Preview the deployment. A temporary dual-stack bootstrap can still be used for
package installation, GitHub, and GHCR:

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

az vm run-command invoke \
  --subscription "$subscription" \
  --resource-group probing-collector \
  --name probing-collector-01 \
  --command-id RunShellScript \
  --scripts @infra/migrate-v2.sh \
  --parameters \
    storage-account="$storageAccount" \
    storage-container="$storageContainer" \
    repository-ref="$repositoryRef"
```

Run the same command again to prove idempotency before registering the emitted
epoch/public key. A temporary dual-stack profile may be needed for GitHub,
GHCR, and package access; remove it immediately after both runs succeed.

Then remove public IPv4 from the NIC by redeploying the IPv6-only profile:

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
```

Subscription deployments are incremental, so explicitly delete the now
detached IPv4 resource and confirm it is gone:

```sh
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

Capture the non-secret outputs for GitHub repository variables:

```sh
az deployment sub show \
  --subscription "$subscription" \
  --name probing-first-collector \
  --query properties.outputs
```

The outputs map to `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`,
`AZURE_SUBSCRIPTION_ID`, `PROBING_STORAGE_ACCOUNT`,
`PROBING_STORAGE_CONTAINER`, and `PROBING_STORAGE_RESOURCE_GROUP`. No output is
a credential. Extract the source epoch and public key with Azure Run Command;
never print the private key:

```sh
az vm run-command invoke \
  --subscription "$subscription" \
  --resource-group probing-collector \
  --name probing-collector-01 \
  --command-id RunShellScript \
  --scripts 'cat /var/lib/probing/source-epoch; cat /var/lib/probing/source-public-key.pem'
```

Standard_LRS capacity, Blob operations, public endpoint egress, the VM, IPv6
address, and the Spot-restarter Logic App can all incur charges. The 30-day
lifecycle policy is a cost ceiling, not an archival promise.

Delete every resource:

```sh
az group delete \
  --subscription "$subscription" \
  --name probing-collector
```
