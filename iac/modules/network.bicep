// iac/modules/network.bicep
// Virtual Network with two subnets:
//   - Container Apps subnet (/23 — minimum required by Container Apps)
//   - MySQL subnet (/28 — minimum required by MySQL Flexible Server)

param env      string
param location string

var vnetName = 'vnet-cloudrisk-${env}'

resource vnet 'Microsoft.Network/virtualNetworks@2023-09-01' = {
  name:     vnetName
  location: location
  properties: {
    addressSpace: {
      addressPrefixes: ['10.0.0.0/16']
    }
    subnets: [
      {
        name: 'snet-containerapps'
        properties: {
          addressPrefix: '10.0.0.0/23'
          // Container Apps Environment requires this delegation
          delegations: [
            {
              name: 'containerApps'
              properties: {
                serviceName: 'Microsoft.App/environments'
              }
            }
          ]
        }
      }
      {
        name: 'snet-mysql'
        properties: {
          addressPrefix: '10.0.2.0/28'
          // MySQL Flexible Server requires this delegation
          delegations: [
            {
              name: 'mysql'
              properties: {
                serviceName: 'Microsoft.DBforMySQL/flexibleServers'
              }
            }
          ]
        }
      }
      {
        name: 'snet-aci'
        properties: {
          addressPrefix: '10.0.4.0/27'
          delegations: [
            {
              name: 'aci'
              properties: {
                serviceName: 'Microsoft.ContainerInstance/containerGroups'
              }
            }
          ]
        }
      }
    ]
  }
}

output vnetId               string = vnet.id
output containerAppsSubnetId string = vnet.properties.subnets[0].id
output mysqlSubnetId         string = vnet.properties.subnets[1].id
output aciSubnetId string = vnet.properties.subnets[2].id
