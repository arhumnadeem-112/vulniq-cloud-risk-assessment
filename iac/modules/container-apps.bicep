// iac/modules/container-apps.bicep
// Container Apps Environment + Pipeline Container Apps Job

param env                  string
param location             string
param subnetId             string
param acrLoginServer       string
param keyVaultName         string
param logAnalyticsId       string
param logAnalyticsKey      string
param storageAccountName   string
@secure()
param storageAccountKey    string
param pipelineCronSchedule string = '0 2 * * *'

var caeName = 'cae-cloudrisk-${env}'
var jobName  = 'caj-cloudrisk-pipeline-${env}'

// ── Container Apps Environment ────────────────────────────────────────────────
resource cae 'Microsoft.App/managedEnvironments@2024-03-01' = {
  name:     caeName
  location: location
  properties: {
    appLogsConfiguration: {
      destination: 'log-analytics'
      logAnalyticsConfiguration: {
        customerId: reference(logAnalyticsId, '2023-09-01').customerId
        sharedKey:  logAnalyticsKey
      }
    }
    vnetConfiguration: {
      infrastructureSubnetId: subnetId
      internal:               false
    }
    workloadProfiles: [
      {
        name:                'Consumption'
        workloadProfileType: 'Consumption'
      }
    ]
  }
}

// Azure Files storage mount for the environment
resource storageMount 'Microsoft.App/managedEnvironments/storages@2024-03-01' = {
  parent: cae
  name:   'cloudrisk-data-mount'
  properties: {
    azureFile: {
      accountName: storageAccountName
      accountKey:  storageAccountKey
      shareName:   'cloudrisk-data'
      accessMode:  'ReadWrite'
    }
  }
}

// ── Pipeline Container Apps Job ───────────────────────────────────────────────
resource pipelineJob 'Microsoft.App/jobs@2024-03-01' = {
  name:     jobName
  location: location
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    environmentId: cae.id
    configuration: {
      triggerType:    'Schedule'
      replicaTimeout: 3600
      replicaRetryLimit: 2
      scheduleTriggerConfig: {
        cronExpression:         pipelineCronSchedule
        parallelism:            1
        replicaCompletionCount: 1
      }
      registries: [
        {
          server:   acrLoginServer
          identity: 'system'
        }
      ]
      secrets: [
        {
          name:        'database-url'
          keyVaultUrl: 'https://${keyVaultName}${environment().suffixes.keyvaultDns}/secrets/cloudrisk-database-url'
          identity:    'system'
        }
        {
          name:        'chroma-host'
          keyVaultUrl: 'https://${keyVaultName}${environment().suffixes.keyvaultDns}/secrets/cloudrisk-chroma-host'
          identity:    'system'
        }
        {
          name:        'chroma-port'
          keyVaultUrl: 'https://${keyVaultName}${environment().suffixes.keyvaultDns}/secrets/cloudrisk-chroma-port'
          identity:    'system'
        }
        {
          name:        'github-token'
          keyVaultUrl: 'https://${keyVaultName}${environment().suffixes.keyvaultDns}/secrets/cloudrisk-github-token'
          identity:    'system'
        }
        {
          name:        'nvd-api-key'
          keyVaultUrl: 'https://${keyVaultName}${environment().suffixes.keyvaultDns}/secrets/cloudrisk-nvd-api-key'
          identity:    'system'
        }
      ]
    }
    template: {
      containers: [
        {
          name:  'pipeline'
          image: '${acrLoginServer}/cloudrisk:latest'
          resources: {
            cpu:    json('1.0')
            memory: '2Gi'
          }
          env: [
            { name: 'DATABASE_URL',   secretRef: 'database-url'  }
            { name: 'CHROMA_HOST',    secretRef: 'chroma-host'   }
            { name: 'CHROMA_PORT',    secretRef: 'chroma-port'   }
            { name: 'GITHUB_TOKEN',   secretRef: 'github-token'  }
            { name: 'NVD_API_KEY',    secretRef: 'nvd-api-key'   }
            { name: 'DATA_DIR',       value:     '/data'          }
            { name: 'VULNIQ_COMMAND', value:     'collect --service stripe --source nvd' }
          ]
          volumeMounts: [
            {
              volumeName: 'cloudrisk-data'
              mountPath:  '/data'
            }
          ]
        }
      ]
      volumes: [
        {
          name:        'cloudrisk-data'
          storageType: 'AzureFile'
          storageName: 'cloudrisk-data-mount'
        }
      ]
    }
  }
  dependsOn: [storageMount]
}

// ── Role Assignments ──────────────────────────────────────────────────────────


output jobName        string = pipelineJob.name
output caeId          string = cae.id
output jobId          string = pipelineJob.id
output jobPrincipalId string = pipelineJob.identity.principalId
