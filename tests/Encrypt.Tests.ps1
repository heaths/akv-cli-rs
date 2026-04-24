# Copyright 2026 Heath Stewart.
# Licensed under the MIT License. See LICENSE.txt in the project root for license information.

#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

# Run with: Invoke-Pester tests/Encrypt.Tests.ps1
# Pass -Release to test a release build:
#   $config = New-PesterConfiguration
#   $config.Run.Path = 'tests/Encrypt.Tests.ps1'
#   $config.Run.ScriptParameters = @{ Release = $true }
#   Invoke-Pester -Configuration $config
#
# Requires a provisioned Key Vault via `azd up` or AZURE_KEYVAULT_URL set in the environment.

param(
    [switch] $Release
)

# cspell:ignore LASTEXITCODE
Describe 'Encrypt' -Tag 'Keys', 'Certificates' {
    BeforeAll {
        # Build the binary before running tests.
        $repoRoot = Join-Path $PSScriptRoot '..' -Resolve
        if ($Release) {
            Write-Host 'Building release binary...'
            cargo build --release 2>&1
            $script:akv = Join-Path $repoRoot 'target' 'release' 'akv'
        } else {
            Write-Host 'Building debug binary...'
            cargo build 2>&1
            $script:akv = Join-Path $repoRoot 'target' 'debug' 'akv'
        }

        if ($LASTEXITCODE -ne 0) {
            throw "cargo build failed with exit code $LASTEXITCODE"
        }

        # Resolve AZURE_KEYVAULT_URL from the environment or via azd.
        $script:AZURE_KEYVAULT_URL = if ($env:AZURE_KEYVAULT_URL) {
            $env:AZURE_KEYVAULT_URL
        } else {
            azd env get-value AZURE_KEYVAULT_URL 2>$null
        }

        if (-not $script:AZURE_KEYVAULT_URL) {
            throw "AZURE_KEYVAULT_URL is not set. Run 'azd up' to provision resources first."
        }

        $script:AZURE_KEYVAULT_URL = $script:AZURE_KEYVAULT_URL.TrimEnd('/')
    }

    Context 'RSA key' -Tag 'Keys' {
        BeforeAll {
            # Create an RSA key and capture the versioned key URL.
            $key = & $script:akv key create --name 'encrypt-test-key' --vault $script:AZURE_KEYVAULT_URL --type rsa --size 2048 --output json | ConvertFrom-Json
            $script:keyUrl = $key.key.kid
        }

        It 'encrypts and decrypts using --value' {
            $plaintext = 'Hello, world!'
            $jwe = & $script:akv encrypt $script:keyUrl --value $plaintext
            $LASTEXITCODE | Should -Be 0
            $decrypted = & $script:akv decrypt $jwe -n
            $LASTEXITCODE | Should -Be 0
            $decrypted | Should -Be $plaintext
        }

        It 'encrypts and decrypts using --in-file -' {
            $plaintext = 'Hello, world!'
            $jwe = $plaintext | & $script:akv encrypt $script:keyUrl --in-file -
            $LASTEXITCODE | Should -Be 0
            $decrypted = & $script:akv decrypt $jwe -n
            $LASTEXITCODE | Should -Be 0
            $decrypted | Should -Be $plaintext
        }
    }

    Context 'RSA certificate' -Tag 'Certificates' {
        BeforeAll {
            # Create an RSA certificate with data-encipherment key usage (polls until ready, may take ~30s).
            # The associated key URL is in .kid of the certificate JSON output.
            $cert = & $script:akv certificate create --name 'encrypt-test-cert' --vault $script:AZURE_KEYVAULT_URL --type rsa --size 2048 --key-usage key-encipherment --output json | ConvertFrom-Json
            $script:certUrl = $cert.id
        }

        It 'encrypts and decrypts using --value' {
            $plaintext = 'Hello, world!'
            $jwe = & $script:akv encrypt $script:certUrl --value $plaintext
            $LASTEXITCODE | Should -Be 0
            $decrypted = & $script:akv decrypt $jwe -n
            $LASTEXITCODE | Should -Be 0
            $decrypted | Should -Be $plaintext
        }

        It 'encrypts and decrypts using --in-file -' {
            $plaintext = 'Hello, world!'
            $jwe = $plaintext | & $script:akv encrypt $script:certUrl --in-file -
            $LASTEXITCODE | Should -Be 0
            $decrypted = & $script:akv decrypt $jwe -n
            $LASTEXITCODE | Should -Be 0
            $decrypted | Should -Be $plaintext
        }
    }
}
