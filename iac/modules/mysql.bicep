// iac/modules/mysql.bicep
param env           string
@secure()
param adminPassword string

var serverName    = 'mysql-cloudrisk-${env}'
var mysqlLocation = 'eastus2'

resource mysqlServer 'Microsoft.DBforMySQL/flexibleServers@2023-12-30' = {
  name:     serverName
  location: mysqlLocation
  sku: {
    name: 'Standard_B1ms'
    tier: 'Burstable'
  }
  properties: {
    administratorLogin:         'cloudrisk'
    administratorLoginPassword: adminPassword
    storage: {
      storageSizeGB: 20
      autoIoScaling: 'Disabled'
    }
    backup: {
      backupRetentionDays: 7
      geoRedundantBackup:  'Disabled'
    }
    highAvailability: {
      mode: 'Disabled'
    }
    network: {
      publicNetworkAccess: 'Enabled'
    }
    version: '8.0.21'
  }
}

resource allowAzureServices 'Microsoft.DBforMySQL/flexibleServers/firewallRules@2023-12-30' = {
  parent: mysqlServer
  name:   'AllowAzureServices'
  properties: {
    startIpAddress: '0.0.0.0'
    endIpAddress:   '0.0.0.0'
  }
}

resource database 'Microsoft.DBforMySQL/flexibleServers/databases@2023-12-30' = {
  parent:  mysqlServer
  name:    'cloudrisk'
  properties: {
    charset:   'utf8mb4'
    collation: 'utf8mb4_unicode_ci'
  }
}

output mysqlHost       string = mysqlServer.properties.fullyQualifiedDomainName
output mysqlServerName string = mysqlServer.name
