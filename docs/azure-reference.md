# Azure reference deployment

The reference sensor will expose two explicit network profiles:

- `ipv6-only` uses one IPv6 Standard public IP and measures IPv6 scanning.
- `dual-stack` adds IPv4 and records address family as an aggregation
  dimension.

Infrastructure code must query the selected region's current prices rather than
assuming an IPv6 public IP is free.

Compute also has two mutually exclusive profiles:

- `burstable` uses a small non-Spot B-family VM and checks whether the selected
  subscription, SKU, and region qualify for a free allowance.
- `spot` selects the least expensive supported x64 or Arm64 SKU that satisfies
  the measured memory requirement, current price ceiling, and acceptable
  eviction rate.

B-family VMs are not supported as Azure Spot VMs. Spot provides no SLA and may
give only 30 seconds' eviction notice. Its OS instance is disposable; source
identity, cursor, sequence, hash-chain head, and unpublished observations need
an external checkpoint. Recovery must be idempotent and the deployment must
declare its maximum acceptable data-loss interval.
