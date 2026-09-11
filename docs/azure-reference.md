# Azure reference deployment

The reference sensor exposes two explicit network profiles:

- `ipv6-only` uses one IPv6 Standard public IP and measures IPv6 scanning.
- `dual-stack` adds IPv4 and records address family as an aggregation
  dimension.

The publication storage account uses Standard_LRS StorageV2, disables shared
keys and anonymous blobs, requires TLS 1.2, and gives the VM system identity
container-scoped Blob Data Contributor access. The subnet has a Microsoft
Storage service endpoint, so the IPv6-only VM reaches the Blob public endpoint
over Azure's private backbone using its private IPv4 address; no public IPv4 is
restored.

The endpoint remains publicly reachable for authenticated GitHub-hosted
runners. Azure Storage firewalls cannot simultaneously restrict the endpoint
to the collector subnet and admit GitHub's changing hosted-runner addresses.
Authorization therefore supplies the external boundary: shared keys/SAS are
disabled and the federated GitHub identity is container-scoped. Moving to a
private endpoint requires a self-hosted runner in the VNet and is intentionally
not introduced here.

Compute has two mutually exclusive profiles:

- `burstable` uses a small non-Spot B-family VM and checks whether the selected
  subscription, SKU, and region qualify for a free allowance.
- `spot` selects the least expensive supported x64 or Arm64 SKU that satisfies
  the measured memory requirement, current price ceiling, and acceptable
  eviction rate.

B-family VMs are not supported as Azure Spot VMs. Spot provides no SLA and may
give only 30 seconds' eviction notice. The OS disk is retained on Spot deallocation and contains the SQLite/WAL state,
source epoch, signing key, and outbox. Deleting the VM or resource group deletes
that state unless it is backed up first. Blob retention is 30 days; soft delete
for blobs and containers is seven days.
