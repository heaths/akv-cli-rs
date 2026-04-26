# Copyright 2026 Heath Stewart.
# Licensed under the MIT License. See LICENSE.txt in the project root for license information.

#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

# Run with: Invoke-Pester tests/Read.Tests.ps1
# Pass -Release to test a release build:
#   $container = New-PesterContainer -Path ./tests/Read.Tests.ps1 -Data @{ Release = $true }
#   $config = New-PesterConfiguration
#   $config.Run.Container = $container
#   Invoke-Pester -Configuration $config
#
# Requires a provisioned Key Vault via `azd up` or AZURE_KEYVAULT_URL set in the environment.

param(
    [switch] $Release
)

# cspell:ignore LASTEXITCODE
Describe 'Read' -Tag 'Secrets' {
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

        $script:secretName = 'test-read-secret'

        # Create first version and capture the versioned ID.
        $v1 = & $script:akv secret create "${script:secretName}=version1" --vault $script:AZURE_KEYVAULT_URL --output json | ConvertFrom-Json
        $script:secretV1Url = $v1.id

        # Create second version by setting the same secret name with a new value.
        & $script:akv secret create "${script:secretName}=version2" --vault $script:AZURE_KEYVAULT_URL | Out-Null
    }

    Context 'Args' -Tag 'Args' {
        It 'rejects URL with --name' {
            & $script:akv read $script:secretV1Url --name $script:secretName 2>$null
            $LASTEXITCODE | Should -Be 2
        }

        It 'rejects URL with --version' {
            $version = $script:secretV1Url.Split('/')[-1]
            & $script:akv read $script:secretV1Url --version $version 2>$null
            $LASTEXITCODE | Should -Be 2
        }

        It 'rejects --version without --name' {
            $version = $script:secretV1Url.Split('/')[-1]
            & $script:akv read --vault $script:AZURE_KEYVAULT_URL --version $version 2>$null
            $LASTEXITCODE | Should -Be 2
        }
    }

    Context 'Select by URL' -Tag 'URL' {
        It 'reads a versioned secret using URL form' {
            $value = & $script:akv read $script:secretV1Url -n
            $LASTEXITCODE | Should -Be 0
            $value | Should -Be 'version1'
        }

        It 'reads the latest (versionless) secret using URL form' {
            $versionlessUrl = "${script:AZURE_KEYVAULT_URL}/secrets/${script:secretName}"
            $value = & $script:akv read $versionlessUrl -n
            $LASTEXITCODE | Should -Be 0
            $value | Should -Be 'version2'
        }
    }

    Context 'Select by --name' -Tag 'Name' {
        It 'reads the latest (versionless) secret using --name' {
            $value = & $script:akv read --name $script:secretName --vault $script:AZURE_KEYVAULT_URL -n
            $LASTEXITCODE | Should -Be 0
            $value | Should -Be 'version2'
        }

        It 'reads a versioned secret using --name and --version' {
            $version = $script:secretV1Url.Split('/')[-1]
            $value = & $script:akv read --name $script:secretName --vault $script:AZURE_KEYVAULT_URL --version $version -n
            $LASTEXITCODE | Should -Be 0
            $value | Should -Be 'version1'
        }
    }
}
