# Copyright 2026 Heath Stewart.
# Licensed under the MIT License. See LICENSE.txt in the project root for license information.

#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

# Run with: Invoke-Pester tests/Keys.Tests.ps1
# Pass -Release to test a release build:
#   $config = New-PesterConfiguration
#   $config.Run.Path = 'tests/Keys.Tests.ps1'
#   $config.Run.ScriptParameters = @{ Release = $true }
#   Invoke-Pester -Configuration $config
#
# Requires a provisioned Key Vault via `azd up` or AZURE_KEYVAULT_URL set in the environment.

param(
    [switch] $Release
)

# cspell:ignore LASTEXITCODE
Describe 'Keys' -Tag 'Keys' {
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

        $script:keyName = 'test-key'

        # Create first key version. JSON output: versioned URL is at .key.kid.
        $v1 = & $script:akv key create --name $script:keyName --vault $script:AZURE_KEYVAULT_URL --type rsa --size 2048 --output json | ConvertFrom-Json
        $script:keyV1Url = $v1.key.kid

        # Create second key version by issuing create again with the same name.
        & $script:akv key create --name $script:keyName --vault $script:AZURE_KEYVAULT_URL --type rsa --size 2048 | Out-Null
    }

    Context 'Select by URL' -Tag 'URL' {
        It 'edits a key using URL form' {
            $result = & $script:akv key edit $script:keyV1Url --tags env=test --output json | ConvertFrom-Json
            $LASTEXITCODE | Should -Be 0
            $result.key.kid | Should -Match "/keys/${script:keyName}/"
        }

        It 'lists versions using URL form' {
            $versions = & $script:akv key list-versions $script:keyV1Url --output json | ConvertFrom-Json
            $LASTEXITCODE | Should -Be 0
            $versions.Count | Should -BeGreaterOrEqual 2
        }

        It 'gets a versioned key using URL form' {
            $result = & $script:akv key get $script:keyV1Url --output json | ConvertFrom-Json
            $LASTEXITCODE | Should -Be 0
            $result.key.kid | Should -Be $script:keyV1Url
        }

        It 'gets the latest (versionless) key using URL form' {
            $versionlessUrl = "${script:AZURE_KEYVAULT_URL}/keys/${script:keyName}"
            $result = & $script:akv key get $versionlessUrl --output json | ConvertFrom-Json
            $LASTEXITCODE | Should -Be 0
            $result.key.kid | Should -Match "/keys/${script:keyName}/"
        }
    }

    Context 'Select by --name' -Tag 'Name' {
        It 'edits a key using --name' {
            $result = & $script:akv key edit --name $script:keyName --vault $script:AZURE_KEYVAULT_URL --tags env=test --output json | ConvertFrom-Json
            $LASTEXITCODE | Should -Be 0
            $result.key.kid | Should -Match "/keys/${script:keyName}/"
        }

        It 'lists versions using --name' {
            $versions = & $script:akv key list-versions --name $script:keyName --vault $script:AZURE_KEYVAULT_URL --output json | ConvertFrom-Json
            $LASTEXITCODE | Should -Be 0
            $versions.Count | Should -BeGreaterOrEqual 2
        }

        It 'gets the latest key using --name' {
            $result = & $script:akv key get --name $script:keyName --vault $script:AZURE_KEYVAULT_URL --output json | ConvertFrom-Json
            $LASTEXITCODE | Should -Be 0
            $result.key.kid | Should -Match "/keys/${script:keyName}/"
            $result.key.kid | Should -Not -Be $script:keyV1Url
        }
    }
}
