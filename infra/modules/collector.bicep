param location string
param vmName string
param vmSize string
param isSpot bool
param maxSpotPrice string
param dualStack bool
@secure()
param adminSshPublicKey string

var cloudInit = loadTextContent('../cloud-init.yml')

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
    osProfile: {
      computerName: vmName
      adminUsername: 'probeadmin'
      customData: base64(cloudInit)
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
    }
    storageProfile: {
      imageReference: {
        publisher: 'Canonical'
        offer: 'ubuntu-24_04-lts'
        sku: 'server'
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

output publicIPv6 string = publicIPv6.properties.ipAddress
output publicIPv4 string = dualStack ? publicIPv4.properties.ipAddress : ''
