# Copyright 2025 Heath Stewart.
# Licensed under the MIT License. See LICENSE.txt in the project root for license information.

AZURE_KEYVAULT_URL="$(azd env get-value AZURE_KEYVAULT_URL)"
export X_SECRET_1="${AZURE_KEYVAULT_URL%/}/secrets/secret-1"
export X_SECRET_2="${AZURE_KEYVAULT_URL%/}/secrets/secret-2"
export X_JWE=$(cargo run -- encrypt --vault "${AZURE_KEYVAULT_URL}" --name 'dek' 'Hello, world!')
export X_JWE_BIN=$(dd if=/dev/random bs=4 count=1 2>/dev/null | cargo run -- encrypt --vault "${AZURE_KEYVAULT_URL}" --name 'dek' --in-file '-')
