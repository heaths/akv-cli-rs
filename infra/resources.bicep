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
      name: 'standard'
      family: 'A'
    }
    enableRbacAuthorization: true
    softDeleteRetentionInDays: 7
  }

  resource secretNumbers 'secrets' = [for i in range(1, 4): {
    name: 'secret-${i}'
    properties: {
      contentType: 'text/plain'
      value: uniqueString('secret', string(i))
    }
  }]

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
