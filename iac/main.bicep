// iac/main.bicep
// Entry point — deploys all capstone-cloudrisk resources
// Deploy with:
//   az deployment group create \
//     --resource-group rg-capstone-cloudrisk \
//     --template-file iac/main.bicep \
//     --parameters iac/parameters/dev.bicepparam \
//     --parameters mysqlAdminPassword=$MYSQL_PASS githubToken=$GITHUB_TOKEN

targetScope = 'resourceGroup'

// ── Parameters ────────────────────────────────────────────────────────────────
@description('Environment suffix — dev or prod')
param env string = 'dev'

@description('Azure region — must match resource group location')
param location string = resourceGroup().location

@description('MySQL administrator password')
@secure()
param mysqlAdminPassword string

@description('GitHub Personal Access Token for collection scripts')
@secure()
param githubToken string

@description('NVD API key (optional — leave blank if not yet registered)')
@secure()
param nvdApiKey string = ''

@description('Cron schedule for automated pipeline runs (2am UTC daily)')
param pipelineCronSchedule string = '0 2 * * *'

// ── Modules ───────────────────────────────────────────────────────────────────
module network 'modules/network.bicep' = {
  name: 'network'
  params: {
    env:      env
    location: location
  }
}

module storage 'modules/storage.bicep' = {
  name: 'storage'
  params: {
    env:      env
    location: location
  }
}

module registry 'modules/registry.bicep' = {
  name: 'registry'
  params: {
    env:      env
    location: location
  }
}

module keyvault 'modules/keyvault.bicep' = {
  name: 'keyvault'
  params: {
    env:                env
    location:           location
    mysqlAdminPassword: mysqlAdminPassword
    githubToken:        githubToken
    nvdApiKey:          nvdApiKey
    storageAccountKey:  storage.outputs.storageAccountKey
  }
}

module mysql 'modules/mysql.bicep' = {
  name: 'mysql'
  params: {
    env:           env
    adminPassword: mysqlAdminPassword
  }
}

module chromadb 'modules/chromadb.bicep' = {
  name: 'chromadb'
  params: {
    env:                env
    location:           location
    storageAccountName: storage.outputs.storageAccountName
    storageAccountKey:  storage.outputs.storageAccountKey
    subnetId:           network.outputs.aciSubnetId
  }
}

module monitoring 'modules/monitoring.bicep' = {
  name: 'monitoring'
  params: {
    env:      env
    location: location
  }
}

module containerapps 'modules/container-apps.bicep' = {
  name: 'containerapps'
  params: {
    env:                  env
    location:             location
    subnetId:             network.outputs.containerAppsSubnetId
    acrLoginServer:       registry.outputs.loginServer
    keyVaultName:         keyvault.outputs.keyVaultName
    logAnalyticsId:       monitoring.outputs.logAnalyticsId
    logAnalyticsKey:      monitoring.outputs.logAnalyticsKey
    storageAccountName:   storage.outputs.storageAccountName
    storageAccountKey:    storage.outputs.storageAccountKey
    pipelineCronSchedule: pipelineCronSchedule
  }
}

// ── Outputs ───────────────────────────────────────────────────────────────────
output resourceGroup    string = resourceGroup().name
output acrLoginServer   string = registry.outputs.loginServer
output keyVaultName     string = keyvault.outputs.keyVaultName
output mysqlHost        string = mysql.outputs.mysqlHost
output containerAppsJob string = containerapps.outputs.jobName
