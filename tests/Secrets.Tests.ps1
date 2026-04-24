# Copyright 2026 Heath Stewart.
# Licensed under the MIT License. See LICENSE.txt in the project root for license information.

#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

# Run with: Invoke-Pester tests/Secrets.Tests.ps1
# Pass -Release to test a release build:
#   $container = New-PesterContainer -Path ./tests/Secrets.Tests.ps1 -Data @{ Release = $true }
#   $config = New-PesterConfiguration
#   $config.Run.Container = $container
#   Invoke-Pester -Configuration $config
#
# Requires a provisioned Key Vault via `azd up` or AZURE_KEYVAULT_URL set in the environment.

param(
    [switch] $Release
)

# cspell:ignore LASTEXITCODE
Describe 'Secrets' -Tag 'Secrets' {
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

        $script:secretName = 'test-secret'

        # Create first version and capture the versioned ID.
        $v1 = & $script:akv secret create "${script:secretName}=version1" --vault $script:AZURE_KEYVAULT_URL --output json | ConvertFrom-Json
        $script:secretV1Url = $v1.id

        # Create second version by setting the same secret name with a new value.
        $v2 = & $script:akv secret create "${script:secretName}=version2" --vault $script:AZURE_KEYVAULT_URL --output json | ConvertFrom-Json
        $script:secretV2Url = $v2.id
    }

    Context 'Select by URL' -Tag 'URL' {
        It 'edits a secret using URL form' {
            $result = & $script:akv secret edit $script:secretV1Url --tags env=test --output json | ConvertFrom-Json
            $LASTEXITCODE | Should -Be 0
            $result.id | Should -Match "/secrets/${script:secretName}/"
        }

        It 'lists versions using URL form' {
            $versions = & $script:akv secret list-versions $script:secretV1Url --output json | ConvertFrom-Json
            $LASTEXITCODE | Should -Be 0
            $versions.Count | Should -BeGreaterOrEqual 2
        }

        It 'gets a versioned secret using URL form' {
            $result = & $script:akv secret get $script:secretV1Url --output json | ConvertFrom-Json
            $LASTEXITCODE | Should -Be 0
            $result.id | Should -Be $script:secretV1Url
        }

        It 'gets the latest (versionless) secret using URL form' {
            $versionlessUrl = "${script:AZURE_KEYVAULT_URL}/secrets/${script:secretName}"
            $result = & $script:akv secret get $versionlessUrl --output json | ConvertFrom-Json
            $LASTEXITCODE | Should -Be 0
            $result.id | Should -Match "/secrets/${script:secretName}/"
        }

        It 'reads a versioned secret using URL form' {
            $value = & $script:akv read $script:secretV1Url -n
            $LASTEXITCODE | Should -Be 0
            $value | Should -Be 'version1'
        }
    }

    Context 'Select by --name' -Tag 'Name' {
        It 'edits a secret using --name' {
            $result = & $script:akv secret edit --name $script:secretName --vault $script:AZURE_KEYVAULT_URL --tags env=test --output json | ConvertFrom-Json
            $LASTEXITCODE | Should -Be 0
            $result.id | Should -Match "/secrets/${script:secretName}/"
        }

        It 'lists versions using --name' {
            $versions = & $script:akv secret list-versions --name $script:secretName --vault $script:AZURE_KEYVAULT_URL --output json | ConvertFrom-Json
            $LASTEXITCODE | Should -Be 0
            $versions.Count | Should -BeGreaterOrEqual 2
        }

        It 'gets the latest (versionless) secret using --name' {
            # Latest version (v2) should differ from v1 URL.
            $result = & $script:akv secret get --name $script:secretName --vault $script:AZURE_KEYVAULT_URL --output json | ConvertFrom-Json
            $LASTEXITCODE | Should -Be 0
            $result.id | Should -Match "/secrets/${script:secretName}/"
            $result.id | Should -Not -Be $script:secretV1Url
        }

        It 'reads the latest secret using --name' {
            $value = & $script:akv read --name $script:secretName --vault $script:AZURE_KEYVAULT_URL -n
            $LASTEXITCODE | Should -Be 0
            $value | Should -Be 'version2'
        }
    }
}
