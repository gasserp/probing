# Azure reference deployment

The reference sensor exposes two explicit network profiles:

- `ipv6-only` uses one IPv6 Standard public IP and measures IPv6 scanning.
- `dual-stack` adds IPv4 and records address family as an aggregation
  dimension.

The publication storage account uses Standard_LRS StorageV2, disables shared
keys and anonymous blobs, requires TLS 1.2, and gives the VM system identity a
container-scoped custom role, `probing-collector-blob-uploader`, that can only
create blobs and read them back, with no delete, list, or container
management. The subnet has a Microsoft
Storage service endpoint, so the IPv6-only VM reaches the Blob public endpoint
over Azure's private backbone using its private IPv4 address; no public IPv4 is
restored.

The endpoint remains publicly reachable for authenticated GitHub-hosted
runners. Azure Storage firewalls cannot simultaneously restrict the endpoint
to the collector subnet and admit GitHub's changing hosted-runner addresses.
Authorization therefore supplies the external boundary: shared keys/SAS are
disabled, and each GitHub identity is federated to one repository and scoped
narrowly:

- `probing-collector-01-github-data` is used by `probing-data`'s ingest
  workflow. It holds Storage Blob Data Contributor on the batch container only.
- `probing-collector-01-github-deploy` is used by this repository's `deploy`
  workflow. It holds the custom `probing-collector-deployer` role on the VM
  only: read, start, and Run Command.

Moving to a private endpoint requires a self-hosted runner in the VNet and is
intentionally not introduced here.

Compute has two mutually exclusive `computeProfile` values:

- `burstable-free` (default) uses a non-Spot `Standard_B1s`. Whether it falls
  within a free allowance depends on your subscription; the template does not
  check.
- `spot-low-cost` uses a `Standard_A1_v2` Spot VM with a default maximum price
  of USD 0.02/hour (`maxSpotPrice`), plus a Logic App that calls the
  idempotent VM start operation every 15 minutes, so an evicted VM restarts
  once capacity returns.

B-family VMs are not supported as Azure Spot VMs. Spot provides no SLA and may
give only 30 seconds' eviction notice. The OS disk is retained on Spot deallocation and contains the SQLite/WAL state,
source epoch, signing key, and outbox. Deleting the VM or resource group deletes
that state unless it is backed up first. Blob retention is 30 days; soft delete
for blobs and containers is seven days.
