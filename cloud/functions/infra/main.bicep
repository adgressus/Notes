targetScope = 'subscription'

// ─── Parameters ──────────────────────────────────────────────

@description('Azure region for all resources')
param location string = 'eastus2'

@description('Base name used to derive resource names')
@minLength(3)
@maxLength(12)
param baseName string = 'notes'

// ─── Derived Names ───────────────────────────────────────────

var resourceGroupName = '${baseName}-auth-rg'
var storageAccountName = '${baseName}authstorage'
var planName = '${baseName}-auth-plan'
var functionAppName = '${baseName}-auth-func'
var logAnalyticsName = '${baseName}-auth-logs'
var appInsightsName = '${baseName}-auth-insights'
var deploymentContainerName = 'deployments'

// ─── Resource Group ──────────────────────────────────────────

resource rg 'Microsoft.Resources/resourceGroups@2024-03-01' = {
  name: resourceGroupName
  location: location
}

// ─── All resources scoped to the Resource Group ──────────────

module resources 'resources.bicep' = {
  name: 'resources'
  scope: rg
  params: {
    location: location
    storageAccountName: storageAccountName
    planName: planName
    functionAppName: functionAppName
    logAnalyticsName: logAnalyticsName
    appInsightsName: appInsightsName
    deploymentContainerName: deploymentContainerName
  }
}

// ─── Outputs ─────────────────────────────────────────────────

output resourceGroupName string = rg.name
output functionAppName string = resources.outputs.functionAppName
output functionAppUrl string = resources.outputs.functionAppUrl
output storageAccountName string = resources.outputs.storageAccountName
output appInsightsName string = resources.outputs.appInsightsName
