// iac/modules/monitoring.bicep
// Log Analytics Workspace + Application Insights
// Pay-as-you-go — near zero cost at dev log volumes

param env      string
param location string

var logAnalyticsName   = 'log-cloudrisk-${env}'
var appInsightsName    = 'appi-cloudrisk-${env}'

resource logAnalytics 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name:     logAnalyticsName
  location: location
  properties: {
    sku: {
      name: 'PerGB2018'   // Pay-as-you-go — cheapest option
    }
    retentionInDays: 30   // Minimum retention
    features: {
      dailyQuotaGb: 1     // Cap at 1 GB/day to avoid surprise costs
    }
  }
}

resource appInsights 'Microsoft.Insights/components@2020-02-02' = {
  name:     appInsightsName
  location: location
  kind:     'web'
  properties: {
    Application_Type:                'web'
    WorkspaceResourceId:             logAnalytics.id
    RetentionInDays:                 30
    IngestionMode:                   'LogAnalytics'
    publicNetworkAccessForIngestion: 'Enabled'
    publicNetworkAccessForQuery:     'Enabled'
  }
}

output logAnalyticsId   string = logAnalytics.id
output logAnalyticsKey  string = logAnalytics.listKeys().primarySharedKey
output appInsightsKey   string = appInsights.properties.InstrumentationKey
