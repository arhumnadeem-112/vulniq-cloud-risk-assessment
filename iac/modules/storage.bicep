// iac/modules/storage.bicep
// Storage Account with two Azure Files shares:
//   - cloudrisk-data  → mounted by pipeline job at /data
//   - chroma-data     → mounted by ChromaDB ACI at /chroma/chroma

param env      string
param location string

// Storage account names must be globally unique, 3-24 chars, lowercase alphanumeric only
var storageAccountName = 'stcloudrisk${env}'

resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name:     storageAccountName
  location: location
  sku: {
    name: 'Standard_LRS'   // Locally redundant — cheapest option
  }
  kind: 'StorageV2'
  properties: {
    minimumTlsVersion:        'TLS1_2'
    supportsHttpsTrafficOnly: true
    allowBlobPublicAccess:    false
  }
}

resource fileService 'Microsoft.Storage/storageAccounts/fileServices@2023-01-01' = {
  parent: storageAccount
  name:   'default'
}

// Share for pipeline job outputs — scores, ETL, manifests, reports, config
resource cloudriskDataShare 'Microsoft.Storage/storageAccounts/fileServices/shares@2023-01-01' = {
  parent: fileService
  name:   'cloudrisk-data'
  properties: {
    shareQuota: 100   // GB
    enabledProtocols: 'SMB'
  }
}

// Share for ChromaDB persistent vector index
resource chromaDataShare 'Microsoft.Storage/storageAccounts/fileServices/shares@2023-01-01' = {
  parent: fileService
  name:   'chroma-data'
  properties: {
    shareQuota: 50    // GB
    enabledProtocols: 'SMB'
  }
}

output storageAccountName string = storageAccount.name
output storageAccountKey  string = storageAccount.listKeys().keys[0].value
