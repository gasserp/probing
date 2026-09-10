targetScope = 'subscription'

@description('Azure region for the collector.')
param location string = 'westeurope'

@allowed([
  'ipv6-only'
  'dual-stack'
])
param networkProfile string = 'ipv6-only'

@allowed([
  'burstable-free'
  'spot-low-cost'
])
param computeProfile string = 'burstable-free'

@secure()
param adminSshPublicKey string

param resourceGroupName string = 'probing-collector'
param vmName string = 'probing-collector-01'
param maxSpotPrice string = '0.02'
param includeCloudInit bool = true

var isSpot = computeProfile == 'spot-low-cost'
var vmSize = isSpot ? 'Standard_A1_v2' : 'Standard_B1s'

resource resourceGroup 'Microsoft.Resources/resourceGroups@2024-03-01' = {
  name: resourceGroupName
  location: location
}

module collector 'modules/collector.bicep' = {
  scope: resourceGroup
  name: 'collector'
  params: {
    location: location
    vmName: vmName
    vmSize: vmSize
    isSpot: isSpot
    maxSpotPrice: maxSpotPrice
    dualStack: networkProfile == 'dual-stack'
    adminSshPublicKey: adminSshPublicKey
    includeCloudInit: includeCloudInit
  }
}

output publicIPv6 string = collector.outputs.publicIPv6
output publicIPv4 string = collector.outputs.publicIPv4
