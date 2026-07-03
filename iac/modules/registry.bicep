// iac/modules/registry.bicep
// Azure Container Registry (Basic SKU) — stores the cloudrisk Docker image
// Pipeline job authenticates via managed identity (no stored credentials)

param env      string
param location string

// ACR names must be globally unique, 5-50 chars, alphanumeric only
var acrName = 'acrCloudrisk${env}'

resource acr 'Microsoft.ContainerRegistry/registries@2023-07-01' = {
  name:     acrName
  location: location
  sku: {
    name: 'Basic'   // Cheapest tier — sufficient for one image at dev scale
  }
  properties: {
    adminUserEnabled: false   // Use managed identity only — no admin credentials
  }
}

output acrName      string = acr.name
output loginServer  string = acr.properties.loginServer
output acrId        string = acr.id
