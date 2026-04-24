# Copyright 2026 Heath Stewart.
# Licensed under the MIT License. See LICENSE.txt in the project root for license information.

#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

# Run with: Invoke-Pester tests/Certificates.Tests.ps1
# Pass -Release to test a release build:
#   $config = New-PesterConfiguration
#   $config.Run.Path = 'tests/Certificates.Tests.ps1'
#   $config.Run.ScriptParameters = @{ Release = $true }
#   Invoke-Pester -Configuration $config
#
# Requires a provisioned Key Vault via `azd up` or AZURE_KEYVAULT_URL set in the environment.

param(
    [switch] $Release
)

# cspell:ignore LASTEXITCODE
Describe 'Certificates' -Tag 'Certificates' {
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

        $script:certName = 'test-cert'

        # Create certificate (polls until ready, may take ~30s).
        # JSON output: versioned URL is at .id.
        $v1 = & $script:akv certificate create --name $script:certName --vault $script:AZURE_KEYVAULT_URL --type ec --curve p256 --output json | ConvertFrom-Json
        $script:certV1Url = $v1.id
    }

    Context 'Select by URL' -Tag 'URL' {
        It 'edits a certificate using URL form' {
            $result = & $script:akv certificate edit $script:certV1Url --tags env=test --output json | ConvertFrom-Json
            $LASTEXITCODE | Should -Be 0
            $result.id | Should -Match "/certificates/${script:certName}/"
            $result.tags | Should -Not -BeNullOrEmpty
            $result.tags.env | Should -Be 'test'
        }

        It 'lists versions using URL form' {
            $versions = & $script:akv certificate list-versions $script:certV1Url --output json | ConvertFrom-Json
            $LASTEXITCODE | Should -Be 0
            $versions.Count | Should -BeGreaterOrEqual 1
        }

        It 'gets a versioned certificate using URL form' {
            $result = & $script:akv certificate get $script:certV1Url --output json | ConvertFrom-Json
            $LASTEXITCODE | Should -Be 0
            $result.id | Should -Be $script:certV1Url
            $result.cer | Should -Not -BeNullOrEmpty
        }

        It 'gets the latest (versionless) certificate using URL form' {
            $versionlessUrl = "${script:AZURE_KEYVAULT_URL}/certificates/${script:certName}"
            $result = & $script:akv certificate get $versionlessUrl --output json | ConvertFrom-Json
            $LASTEXITCODE | Should -Be 0
            $result.id | Should -Match "/certificates/${script:certName}/"
            $result.tags | Should -Not -BeNullOrEmpty
            $result.tags.env | Should -Be 'test'
        }
    }

    Context 'Select by --name' -Tag 'Name' {
        It 'edits a certificate using --name' {
            $result = & $script:akv certificate edit --name $script:certName --vault $script:AZURE_KEYVAULT_URL --tags env=test --output json | ConvertFrom-Json
            $LASTEXITCODE | Should -Be 0
            $result.id | Should -Match "/certificates/${script:certName}/"
            $result.tags | Should -Not -BeNullOrEmpty
            $result.tags.env | Should -Be 'test'
        }

        It 'lists versions using --name' {
            $versions = & $script:akv certificate list-versions --name $script:certName --vault $script:AZURE_KEYVAULT_URL --output json | ConvertFrom-Json
            $LASTEXITCODE | Should -Be 0
            $versions.Count | Should -BeGreaterOrEqual 1
        }

        It 'gets the latest certificate using --name' {
            $result = & $script:akv certificate get --name $script:certName --vault $script:AZURE_KEYVAULT_URL --output json | ConvertFrom-Json
            $LASTEXITCODE | Should -Be 0
            $result.id | Should -Match "/certificates/${script:certName}/"
            $result.tags | Should -Not -BeNullOrEmpty
            $result.tags.env | Should -Be 'test'
        }
    }
}
