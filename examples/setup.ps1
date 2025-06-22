# Copyright 2025 Heath Stewart.
# Licensed under the MIT License. See LICENSE.txt in the project root for license information.

$AZURE_KEYVAULT_URL = (azd env get-value AZURE_KEYVAULT_URL).TrimEnd('/')
$env:X_SECRET_1 = "$AZURE_KEYVAULT_URL/secrets/secret-1"
$env:X_SECRET_2 = "$AZURE_KEYVAULT_URL/secrets/secret-2"
$env:X_JWE = cargo run -- encrypt --vault "$AZURE_KEYVAULT_URL" --name 'dek' 'Hello, world!'
$env:X_JWE_BIN = [BitConverter]::GetBytes((Get-Random)) | cargo run -- encrypt --vault "$AZURE_KEYVAULT_URL" --name 'dek' --in-file '-'
