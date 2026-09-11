# Azure deployment

This template creates the collector VM and managed-identity Blob publication
path. Public ports 22 and 80 are decoys; real SSH is disabled from first boot
and administration uses Azure Run Command.

Set the target subscription:

```sh
subscription=18d04159-3160-4eff-8437-3a87b95374ef
computeProfile=spot-low-cost
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
    adminSshPublicKey="$(cat ~/.ssh/id_ed25519.pub)"
```

Confirm cloud-init and every container succeeded:

```sh
az vm run-command invoke \
  --subscription "$subscription" \
  --resource-group probing-collector \
  --name probing-collector-01 \
  --command-id RunShellScript \
  --scripts 'set -eu; cloud-init status --wait --long; cd /opt/probing; running="$(docker compose -f deploy/docker-compose.yml ps --services --status running)"; for service in collector uploader cowrie ingress nginx; do printf "%s\n" "$running" | grep -qx "$service"; done; test "$(stat -c %a /var/lib/probing/source-private-key.pem)" = 600; curl --fail --silent --show-error http://127.0.0.1/health; timeout 5 bash -c "exec 3<>/dev/tcp/127.0.0.1/22"; docker compose -f deploy/docker-compose.yml ps'
```

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
