param location string
param vmName string
param vmSize string
param isSpot bool
param maxSpotPrice string
param dualStack bool
param includeCloudInit bool
@secure()
param adminSshPublicKey string

var rawCloudInit = loadTextContent('../cloud-init.yml')
var storageAccountName = take('probing${uniqueString(subscription().id, resourceGroup().id, location)}', 24)
var storageContainerName = 'pending-batches'
var cloudInit = replace(
  replace(rawCloudInit, '__STORAGE_ACCOUNT_NAME__', storageAccountName),
  '__STORAGE_CONTAINER_NAME__',
  storageContainerName
)

resource networkSecurityGroup 'Microsoft.Network/networkSecurityGroups@2024-05-01' = {
  name: '${vmName}-nsg'
  location: location
  properties: {
    securityRules: [
      {
        name: 'allow-ssh-honeypot'
        properties: {
          priority: 100
          access: 'Allow'
          direction: 'Inbound'
          protocol: 'Tcp'
          sourcePortRange: '*'
          destinationPortRange: '22'
          sourceAddressPrefix: 'Internet'
          destinationAddressPrefix: '*'
        }
      }
      {
        name: 'allow-http-honeypot'
        properties: {
          priority: 110
          access: 'Allow'
          direction: 'Inbound'
          protocol: 'Tcp'
          sourcePortRange: '*'
          destinationPortRange: '80'
          sourceAddressPrefix: 'Internet'
          destinationAddressPrefix: '*'
        }
      }
    ]
  }
}

resource virtualNetwork 'Microsoft.Network/virtualNetworks@2024-05-01' = {
  name: '${vmName}-vnet'
  location: location
  properties: {
    addressSpace: {
      addressPrefixes: [
        '10.42.0.0/16'
        'fd00:42::/48'
      ]
    }
  }
}

resource subnet 'Microsoft.Network/virtualNetworks/subnets@2024-05-01' = {
  parent: virtualNetwork
  name: 'collector'
  properties: {
    addressPrefixes: [
      '10.42.0.0/24'
      'fd00:42::/64'
    ]
    networkSecurityGroup: {
      id: networkSecurityGroup.id
    }
    serviceEndpoints: [
      {
        service: 'Microsoft.Storage'
        locations: [
          location
        ]
      }
    ]
  }
}

resource storageAccount 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: storageAccountName
  location: location
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
  properties: {
    accessTier: 'Hot'
    allowBlobPublicAccess: false
    allowCrossTenantReplication: false
    allowSharedKeyAccess: false
    defaultToOAuthAuthentication: true
    minimumTlsVersion: 'TLS1_2'
    publicNetworkAccess: 'Enabled'
    supportsHttpsTrafficOnly: true
    networkAcls: {
      bypass: 'AzureServices'
      defaultAction: 'Allow'
      ipRules: []
      virtualNetworkRules: [
        {
          action: 'Allow'
          id: subnet.id
        }
      ]
    }
  }
}

resource blobService 'Microsoft.Storage/storageAccounts/blobServices@2023-05-01' = {
  parent: storageAccount
  name: 'default'
  properties: {
    containerDeleteRetentionPolicy: {
      enabled: true
      days: 7
    }
    deleteRetentionPolicy: {
      enabled: true
      days: 7
    }
  }
}

resource batchContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  parent: blobService
  name: storageContainerName
  properties: {
    publicAccess: 'None'
  }
}

resource lifecyclePolicy 'Microsoft.Storage/storageAccounts/managementPolicies@2023-05-01' = {
  parent: storageAccount
  name: 'default'
  properties: {
    policy: {
      rules: [
        {
          enabled: true
          name: 'delete-ingested-batches-after-30-days'
          type: 'Lifecycle'
          definition: {
            actions: {
              baseBlob: {
                delete: {
                  daysAfterModificationGreaterThan: 30
                }
              }
            }
            filters: {
              blobTypes: [
                'blockBlob'
              ]
              prefixMatch: [
                '${storageContainerName}/'
              ]
            }
          }
        }
      ]
    }
  }
}

resource publicIPv6 'Microsoft.Network/publicIPAddresses@2024-05-01' = {
  name: '${vmName}-ipv6'
  location: location
  sku: {
    name: 'Standard'
  }
  properties: {
    publicIPAllocationMethod: 'Static'
    publicIPAddressVersion: 'IPv6'
  }
}

resource publicIPv4 'Microsoft.Network/publicIPAddresses@2024-05-01' = if (dualStack) {
  name: '${vmName}-ipv4'
  location: location
  sku: {
    name: 'Standard'
  }
  properties: {
    publicIPAllocationMethod: 'Static'
    publicIPAddressVersion: 'IPv4'
  }
}

var ipConfigurations = concat([
  {
    name: 'private-ipv4'
    properties: {
      primary: true
      privateIPAllocationMethod: 'Dynamic'
      privateIPAddressVersion: 'IPv4'
      publicIPAddress: dualStack ? {
        id: publicIPv4.id
      } : null
      subnet: {
        id: subnet.id
      }
    }
  }
], [
  {
    name: 'public-ipv6'
    properties: {
      privateIPAllocationMethod: 'Dynamic'
      privateIPAddressVersion: 'IPv6'
      publicIPAddress: {
        id: publicIPv6.id
      }
      subnet: {
        id: subnet.id
      }
    }
  }
])

resource networkInterface 'Microsoft.Network/networkInterfaces@2024-05-01' = {
  name: '${vmName}-nic'
  location: location
  properties: {
    ipConfigurations: ipConfigurations
  }
}

resource virtualMachine 'Microsoft.Compute/virtualMachines@2024-07-01' = {
  name: vmName
  location: location
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    hardwareProfile: {
      vmSize: vmSize
    }
    priority: isSpot ? 'Spot' : 'Regular'
    evictionPolicy: isSpot ? 'Deallocate' : null
    billingProfile: isSpot ? {
      maxPrice: json(maxSpotPrice)
    } : null
    networkProfile: {
      networkInterfaces: [
        {
          id: networkInterface.id
        }
      ]
    }
    osProfile: union({
      computerName: vmName
      adminUsername: 'probeadmin'
      linuxConfiguration: {
        disablePasswordAuthentication: true
        ssh: {
          publicKeys: [
            {
              path: '/home/probeadmin/.ssh/authorized_keys'
              keyData: adminSshPublicKey
            }
          ]
        }
      }
    }, includeCloudInit ? {
      customData: base64(cloudInit)
    } : {})
    storageProfile: {
      imageReference: {
        publisher: 'Canonical'
        offer: isSpot ? '0001-com-ubuntu-server-jammy' : 'ubuntu-24_04-lts'
        sku: isSpot ? '22_04-lts' : 'server'
        version: 'latest'
      }
      osDisk: {
        createOption: 'FromImage'
        diskSizeGB: 32
        managedDisk: {
          storageAccountType: 'Standard_LRS'
        }
      }
    }
  }
}

resource githubDataIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: '${vmName}-github-data'
  location: location
}

resource githubFederatedCredential 'Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials@2023-01-31' = {
  parent: githubDataIdentity
  name: 'probing-data-main'
  properties: {
    audiences: [
      'api://AzureADTokenExchange'
    ]
    issuer: 'https://token.actions.githubusercontent.com'
    subject: 'repo:gasserp/probing-data:ref:refs/heads/main'
  }
}

var storageBlobDataContributorRole = subscriptionResourceId(
  'Microsoft.Authorization/roleDefinitions',
  'ba92f5b4-2d11-453d-a403-e96b0029c9fe'
)

resource virtualMachineBlobRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: batchContainer
  name: guid(batchContainer.id, virtualMachine.id, 'storage-blob-data-contributor')
  properties: {
    principalId: virtualMachine.identity.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: storageBlobDataContributorRole
  }
}

resource githubBlobRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: batchContainer
  name: guid(batchContainer.id, githubDataIdentity.id, 'storage-blob-data-contributor')
  properties: {
    principalId: githubDataIdentity.properties.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: storageBlobDataContributorRole
  }
}

resource spotRestarter 'Microsoft.Logic/workflows@2019-05-01' = if (isSpot) {
  name: '${vmName}-spot-restarter'
  location: location
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    state: 'Enabled'
    definition: {
      '$schema': 'https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#'
      contentVersion: '1.0.0.0'
      parameters: {}
      triggers: {
        retry: {
          type: 'Recurrence'
          recurrence: {
            frequency: 'Minute'
            interval: 15
          }
        }
      }
      actions: {
        start_vm: {
          type: 'Http'
          inputs: {
            method: 'POST'
            uri: 'https://management.azure.com${virtualMachine.id}/start?api-version=2024-07-01'
            authentication: {
              type: 'ManagedServiceIdentity'
              audience: 'https://management.azure.com/'
            }
          }
          runtimeConfiguration: {
            contentTransfer: {
              transferMode: 'Chunked'
            }
          }
        }
      }
      outputs: {}
    }
  }
}

resource spotRestarterRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (isSpot) {
  scope: virtualMachine
  name: guid(virtualMachine.id, spotRestarter.id, 'virtual-machine-contributor')
  properties: {
    principalId: spotRestarter.identity.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId(
      'Microsoft.Authorization/roleDefinitions',
      '9980e02c-c2be-4d73-94e8-173b1dc7cf3c'
    )
  }
}

output publicIPv6 string = publicIPv6.properties.ipAddress
output publicIPv4 string = dualStack ? publicIPv4.properties.ipAddress : ''
output storageAccountName string = storageAccount.name
output storageContainerName string = batchContainer.name
output githubClientId string = githubDataIdentity.properties.clientId
