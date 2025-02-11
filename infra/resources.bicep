// Copyright 2024 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

@minLength(1)
@maxLength(64)
@description('Name of the environment that can be used as part of naming resource convention')
param environmentName string

@minLength(1)
@description('Primary location for all resources')
param location string = resourceGroup().location

@description('User principal ID')
param principalId string

@description('The vault name; default is a unique string based on the resource group ID')
param vaultName string = ''

resource kv 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: empty(vaultName) ? 't${uniqueString(resourceGroup().id, environmentName)}' : vaultName
  location: location
  properties: {
    tenantId: subscription().tenantId
    sku: {
      name: 'standard'
      family: 'A'
    }
    enableRbacAuthorization: true
    softDeleteRetentionInDays: 7
  }

  resource secret 'secrets' = {
    name: 'my-secret'
    properties: {
      contentType: 'text/plain'
      value: 'secret-value'
    }
  }
}

var kvSecretsOfficerDefinitionId = subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'b86a8fe4-44ce-4948-aee5-eccb2c155cd7')

resource rbac 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(resourceGroup().id, environmentName, principalId, kvSecretsOfficerDefinitionId)
  scope: kv
  properties: {
    roleDefinitionId: kvSecretsOfficerDefinitionId
    principalId: principalId
  }
}

output AZURE_PRINCIPAL_ID string = principalId
output AZURE_KEYVAULT_NAME string = kv.name
output AZURE_KEYVAULT_URL string = kv.properties.vaultUri
