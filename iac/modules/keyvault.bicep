// iac/modules/keyvault.bicep
// Azure Key Vault — stores all secrets and injects them into the pipeline
// job at runtime via managed identity. No secrets stored in code or config.

param env                string
param location           string
@secure()
param mysqlAdminPassword string
@secure()
param githubToken        string
@secure()
param nvdApiKey          string
@secure()
param storageAccountKey  string

var kvName = 'kv-cloudrisk-${env}'

resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name:     kvName
  location: location
  properties: {
    sku: {
      family: 'A'
      name:   'standard'
    }
    tenantId:               tenant().tenantId
    enableRbacAuthorization: true    // Use RBAC not access policies
    enableSoftDelete:        true
    softDeleteRetentionInDays: 7     // Minimum retention — saves cost vs default 90
    publicNetworkAccess:    'Enabled'
  }
}

// ── Secrets ───────────────────────────────────────────────────────────────────

resource secretDbUrl 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = {
  parent: keyVault
  name:   'cloudrisk-database-url'
  properties: {
    value: 'mysql+pymysql://cloudrisk:${mysqlAdminPassword}@mysql-cloudrisk-${env}.mysql.database.azure.com:3306/cloudrisk'
  }
}

resource secretMysqlPassword 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = {
  parent: keyVault
  name:   'cloudrisk-mysql-password'
  properties: {
    value: mysqlAdminPassword
  }
}

resource secretGithubToken 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = {
  parent: keyVault
  name:   'cloudrisk-github-token'
  properties: {
    value: githubToken
  }
}

resource secretNvdApiKey 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = {
  parent: keyVault
  name:   'cloudrisk-nvd-api-key'
  properties: {
    value: nvdApiKey == '' ? 'not-set' : nvdApiKey
  }
}

resource secretStorageKey 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = {
  parent: keyVault
  name:   'cloudrisk-storage-key'
  properties: {
    value: storageAccountKey
  }
}

// Chroma host and port — will be updated after ChromaDB ACI deploys
// and gets its private IP. Update manually with:
//   az keyvault secret set --vault-name kv-cloudrisk-dev \
//     --name cloudrisk-chroma-host --value <ACI_PRIVATE_IP>
resource secretChromaHost 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = {
  parent: keyVault
  name:   'cloudrisk-chroma-host'
  properties: {
    value: 'pending'   // Updated after ChromaDB ACI deploys
  }
}

resource secretChromaPort 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = {
  parent: keyVault
  name:   'cloudrisk-chroma-port'
  properties: {
    value: '8000'
  }
}

output keyVaultName string = keyVault.name
output keyVaultId   string = keyVault.id
output keyVaultUri  string = keyVault.properties.vaultUri
