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

@description('Optional client ID of blob data reader')
param clientId string = ''

@description('The vault name; default is a unique string based on the resource group ID')
param vaultName string = ''

@description('The vault SKU; default is "standard"')
@allowed(['standard', 'premium'])
param vaultSku string = 'standard'

var jwtPayload = '''{
  sub: 'github.com/heaths/akv-cli-rs'
  name: 'Heath Stewart'
  iat: 1516239022
}'''

// cspell:disable-next-line
var jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJnaXRodWIuY29tL2hlYXRocy9ha3YtY2xpLXJzIiwibmFtZSI6IkhlYXRoIFN0ZXdhcnQiLCJpYXQiOjE1MTYyMzkwMjJ9.9iUv6gA75ODCBVL6wEon9jwATOXojzUerxxCh8TZSHA'

resource kv 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: empty(vaultName) ? 't${uniqueString(resourceGroup().id, environmentName)}' : vaultName
  location: location
  properties: {
    tenantId: subscription().tenantId
    sku: {
      name: vaultSku
      family: 'A'
    }
    enableRbacAuthorization: true
    softDeleteRetentionInDays: 7
  }

  resource secretNumbers 'secrets' = [
    for i in range(1, 4): {
      name: 'secret-${i}'
      properties: {
        contentType: 'text/plain'
        value: uniqueString('secret', string(i))
      }
    }
  ]

  resource secretJson 'secrets' = {
    name: 'secret-json'
    properties: {
      contentType: 'application/json'
      value: jwtPayload
    }
  }

  resource secretJwt 'secrets' = {
    name: 'secret-jws'
    properties: {
      contentType: 'application/jwt'
      value: jwt
    }
  }

  resource dek 'keys' = {
    name: 'dek'
    properties: {
      kty: 'RSA'
      keySize: 2048
    }
  }
}

resource stg 'Microsoft.Storage/storageAccounts@2025-01-01' = {
  name: 't${uniqueString(resourceGroup().id, environmentName)}'
  location: location
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
  properties: {
    allowSharedKeyAccess: false
    isLocalUserEnabled: false
    minimumTlsVersion: 'TLS1_2'
    publicNetworkAccess: 'Enabled'
  }

  resource blobs 'blobServices' = {
    name: 'default'
    resource container 'containers' = {
      name: 'examples'
    }
  }
}

var kvAdminDefinitionId = subscriptionResourceId(
  'Microsoft.Authorization/roleDefinitions',
  '00482a5a-887f-4fb3-b363-3b7fe8e74483'
)
var stgBlobDataContributorDefinitionId = subscriptionResourceId(
  'Microsoft.Authorization/roleDefinitions',
  'ba92f5b4-2d11-453d-a403-e96b0029c9fe'
)
var stgBlobDataReaderDefinitionId = subscriptionResourceId(
  'Microsoft.Authorization/roleDefinitions',
  '2a2b9908-6ea1-4ae2-8e65-a410df84e7d1'
)

resource kvAdminRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(resourceGroup().id, environmentName, principalId, kvAdminDefinitionId)
  scope: kv
  properties: {
    roleDefinitionId: kvAdminDefinitionId
    principalId: principalId
  }
}

resource stgBlobDataContributorRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(resourceGroup().id, environmentName, principalId, stgBlobDataContributorDefinitionId)
  scope: stg
  properties: {
    roleDefinitionId: stgBlobDataContributorDefinitionId
    principalId: principalId
  }
}

resource stgBlobDataReaderRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (!empty(clientId)) {
  name: guid(resourceGroup().id, environmentName, clientId, stgBlobDataReaderDefinitionId)
  scope: stg
  properties: {
    roleDefinitionId: stgBlobDataReaderDefinitionId
    principalId: clientId
    principalType: 'ServicePrincipal'
  }
}

output AZURE_PRINCIPAL_ID string = principalId
output AZURE_KEYVAULT_NAME string = kv.name
output AZURE_KEYVAULT_SKU string = kv.properties.sku.name
output AZURE_KEYVAULT_URL string = kv.properties.vaultUri
output AZURE_KEYVAULT_DEK_URL string = kv::dek.properties.keyUri
output AZURE_STORAGE_ACCOUNT string = stg.name
output AZURE_STORAGE_AUTH_MODE string = 'login'
output AZURE_STORAGE_SERVICE_ENDPOINT string = stg.properties.primaryEndpoints.blob
