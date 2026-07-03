using '../main.bicep'

param env                  = 'dev'
param location             = 'westus'
param pipelineCronSchedule = '0 2 * * *'
param mysqlAdminPassword   = ''
param githubToken          = ''
param nvdApiKey            = ''
