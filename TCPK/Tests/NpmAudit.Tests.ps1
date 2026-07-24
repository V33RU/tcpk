#requires -Version 5.1
# Asar-tab "npm audit": Get-TcpkAsarNpmAudit orchestrates the bundled-npm inventory
# through the shared OSV engine (CVEs) and the npm registry (deprecations), and
# Format-TcpkNpmAuditReport renders it. The formatter is pure (no network), so it is
# tested directly; the orchestrator is tested with the three I/O helpers mocked, so
# the whole file is offline + deterministic.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
}

Describe 'Format-TcpkNpmAuditReport (pure formatter)' {
    It 'renders vulnerabilities, deprecations, counts and the target name' {
        $result = [ordered]@{
            packages = 3; uniqueNames = 3
            vulns = @(
                [pscustomobject]@{ Package = 'minimist'; ShippedVersion = '1.2.0'; FixedVersion = '1.2.6'; Severity = 'high';     Cve = 'CVE-2021-44906'; Title = 'prototype pollution' }
                [pscustomobject]@{ Package = 'lodash';   ShippedVersion = '4.17.4'; FixedVersion = '4.17.21'; Severity = 'critical'; Cve = 'CVE-2019-10744'; Title = 'prototype pollution' }
            )
            deprecated = @(
                [pscustomobject]@{ Name = 'request'; Version = '2.88.0'; Message = 'request has been deprecated, see https://github.com/request/request/issues/3142' }
            )
            deprecatedChecked = 3; deprecatedCapped = $false
        }
        $txt = InModuleScope TCPK -Parameters @{ r = $result } { param($r) Format-TcpkNpmAuditReport -Result $r -TargetName 'MyApp.exe' }
        $txt | Should -Match 'target: MyApp\.exe'
        $txt | Should -Match 'bundled npm packages: 3'
        $txt | Should -Match 'VULNERABILITIES \(2\)'
        $txt | Should -Match 'CVE-2019-10744'
        $txt | Should -Match 'fixed in 4\.17\.21'
        # critical must sort above high
        $iCrit = $txt.IndexOf('CVE-2019-10744'); $iHigh = $txt.IndexOf('CVE-2021-44906')
        $iCrit | Should -BeLessThan $iHigh
        $txt | Should -Match '2 vulnerabilities: 1 critical, 1 high'
        $txt | Should -Match 'DEPRECATED / UNMAINTAINED \(1\)'
        $txt | Should -Match 'request 2\.88\.0'
    }

    It 'states clean when there are no vulns and no deprecations' {
        $result = [ordered]@{ packages = 2; uniqueNames = 2; vulns = @(); deprecated = @(); deprecatedChecked = 2; deprecatedCapped = $false }
        $txt = InModuleScope TCPK -Parameters @{ r = $result } { param($r) Format-TcpkNpmAuditReport -Result $r }
        $txt | Should -Match 'VULNERABILITIES: none found'
        $txt | Should -Match 'DEPRECATED: none among'
    }

    It 'explains an empty inventory instead of showing zero-count sections' {
        $result = [ordered]@{ packages = 0; uniqueNames = 0; vulns = @(); deprecated = @(); deprecatedChecked = 0; deprecatedCapped = $false
            note = 'No bundled npm packages found -- not an Electron app.asar, or its node_modules were not packed into the asar.' }
        $txt = InModuleScope TCPK -Parameters @{ r = $result } { param($r) Format-TcpkNpmAuditReport -Result $r }
        $txt | Should -Match 'No bundled npm packages found'
        $txt | Should -Not -Match 'VULNERABILITIES'
    }

    It 'surfaces an error result plainly' {
        $txt = InModuleScope TCPK -Parameters @{ r = ([ordered]@{ error = 'path not found: X' }) } { param($r) Format-TcpkNpmAuditReport -Result $r }
        $txt | Should -Match 'error: path not found: X'
    }
}

Describe 'Get-TcpkAsarNpmAudit (orchestrator, mocked I/O)' {
    It 'combines OSV CVEs with registry deprecations for the bundled packages' {
        $dir = Join-Path ([IO.Path]::GetTempPath()) ("tcpk-npm-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        try {
            $res = InModuleScope TCPK -Parameters @{ dir = $dir } {
                param($dir)
                Mock Get-TcpkAsarNpmComponents {
                    @(
                        [pscustomobject]@{ Name = 'minimist'; Version = '1.2.0'; File = 'app.asar' }
                        [pscustomobject]@{ Name = 'request';  Version = '2.88.0'; File = 'app.asar' }
                        [pscustomobject]@{ Name = 'lodash';   Version = '4.17.21'; File = 'app.asar' }
                    )
                }
                Mock Get-TcpkOsvMatches {
                    @([pscustomobject]@{ Package = 'minimist'; ShippedVersion = '1.2.0'; FixedVersion = '1.2.6'; Severity = 'high'; Cve = 'CVE-2021-44906'; Title = 'prototype pollution' })
                }
                # only 'request' is flagged deprecated by the registry
                Mock Get-TcpkNpmDeprecation { param($Name, $Version, $TimeoutSec) if ($Name -eq 'request') { 'request has been deprecated' } else { $null } }
                Get-TcpkAsarNpmAudit -Path $dir
            }
            $res.packages | Should -Be 3
            @($res.vulns).Count | Should -Be 1
            $res.vulns[0].Cve | Should -Be 'CVE-2021-44906'
            @($res.deprecated).Count | Should -Be 1
            $res.deprecated[0].Name | Should -Be 'request'
            $res.deprecatedChecked | Should -Be 3
            $res.deprecatedCapped | Should -BeFalse
        } finally {
            Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'returns an empty-inventory note (no network) when no packages are bundled' {
        $dir = Join-Path ([IO.Path]::GetTempPath()) ("tcpk-npm-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        try {
            $res = InModuleScope TCPK -Parameters @{ dir = $dir } {
                param($dir)
                Mock Get-TcpkAsarNpmComponents { @() }
                Mock Get-TcpkOsvMatches { throw 'OSV must not be called for an empty inventory' }
                Mock Get-TcpkNpmDeprecation { throw 'registry must not be called for an empty inventory' }
                Get-TcpkAsarNpmAudit -Path $dir
            }
            $res.packages | Should -Be 0
            $res.note | Should -Match 'No bundled npm packages'
            Assert-MockCalled -ModuleName TCPK Get-TcpkOsvMatches -Times 0
        } finally {
            Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'caps the deprecation checks at MaxDeprecatedChecks' {
        $dir = Join-Path ([IO.Path]::GetTempPath()) ("tcpk-npm-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        try {
            $res = InModuleScope TCPK -Parameters @{ dir = $dir } {
                param($dir)
                Mock Get-TcpkAsarNpmComponents { 1..5 | ForEach-Object { [pscustomobject]@{ Name = "pkg$_"; Version = '1.0.0'; File = 'app.asar' } } }
                Mock Get-TcpkOsvMatches { @() }
                Mock Get-TcpkNpmDeprecation { $null }
                Get-TcpkAsarNpmAudit -Path $dir -MaxDeprecatedChecks 2
            }
            $res.deprecatedChecked | Should -Be 2
            $res.deprecatedCapped | Should -BeTrue
        } finally {
            Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}
