targetScope = 'subscription'

@description('Azure region for the collector.')
param location string = 'westeurope'

@allowed([
  'ipv6-only'
  'dual-stack'
])
param networkProfile string = 'dual-stack'

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
@description('Git ref or commit used by the versioned collector migration.')
param repositoryRef string = 'main'
@description('GitHub OIDC subject allowed to run the deploy workflow: the "production" environment of gasserp/probing, in the stable-ID form GitHub issues for this repo (owner@owner_id/repo@repo_id; see infra/README.md).')
param githubDeploySubject string = 'repo:gasserp@13432519/probing@1364631664:environment:production'

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
    repositoryRef: repositoryRef
    githubDeploySubject: githubDeploySubject
  }
}

output publicIPv6 string = collector.outputs.publicIPv6
output publicIPv4 string = collector.outputs.publicIPv4
output storageAccountName string = collector.outputs.storageAccountName
output storageContainerName string = collector.outputs.storageContainerName
output githubClientId string = collector.outputs.githubClientId
output githubDeployClientId string = collector.outputs.githubDeployClientId
output githubTenantId string = tenant().tenantId
output githubSubscriptionId string = subscription().subscriptionId
output resourceGroupName string = resourceGroup.name
