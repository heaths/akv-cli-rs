// Copyright 2024 Heath Stewart.
// Licensed under the MIT License. See LICENSE.txt in the project root for license information.

using './main.bicep'

// cspell:ignore westus
param environmentName = readEnvironmentVariable('AZURE_ENV_NAME', 'akv-cli-dev')
param location = readEnvironmentVariable('AZURE_LOCATION', 'westus')
param principalId = readEnvironmentVariable('AZURE_PRINCIPAL_ID', '')
param clientId = readEnvironmentVariable('AZURE_CLIENT_OID', '')
param vaultName = readEnvironmentVariable('AZURE_KEYVAULT_NAME', '')
