#requires -Version 5.1
# Pester 5: optional OSV online CVE enrichment (Get-TcpkCveMatches / Invoke-TcpkAudit -OnlineCve).
# Tests the PURE OSV->match mapper (no network) and that the enrichment is strictly opt-in
# (a switch, default OFF, so the audit stays offline unless asked).

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
}

Describe 'OSV vuln mapping (pure, no network)' {
    It 'maps an OSV / GHSA record to a CVE-match object (prefers the CVE alias)' {
        $m = & (Get-Module TCPK) {
            $vuln = [pscustomobject]@{
                id      = 'GHSA-aaaa-bbbb-cccc'
                aliases = @('CVE-2024-99999')
                summary = 'Example deserialization DoS'
                details = 'Longer details here.'
                database_specific = [pscustomobject]@{ severity = 'high' }
                affected = @([pscustomobject]@{ ranges = @([pscustomobject]@{ events = @(
                    [pscustomobject]@{ introduced = '0' }, [pscustomobject]@{ fixed = '13.0.1' }) }) })
                references = @([pscustomobject]@{ url = 'https://github.com/advisories/GHSA-aaaa-bbbb-cccc' })
            }
            ConvertFrom-TcpkOsvVuln -Vuln $vuln -Package 'Newtonsoft.Json' -ShippedVersion '12.0.1'
        }
        $m.Cve            | Should -Be 'CVE-2024-99999'
        $m.Package        | Should -Be 'Newtonsoft.Json'
        $m.ShippedVersion | Should -Be '12.0.1'
        $m.FixedVersion   | Should -Be '13.0.1'
        $m.Severity       | Should -Be 'HIGH'
        $m.Status         | Should -Be 'Vulnerable'
        $m.Confidence     | Should -Be 'Confirmed (OSV)'
        $m.Source         | Should -Be 'osv.dev'
    }
    It 'falls back to the OSV id + an osv.dev link when no CVE alias / refs are present' {
        $m = & (Get-Module TCPK) {
            ConvertFrom-TcpkOsvVuln -Vuln ([pscustomobject]@{ id = 'GHSA-zzzz'; summary = 'x' }) -Package 'Foo' -ShippedVersion '1.0.0'
        }
        $m.Cve              | Should -Be 'GHSA-zzzz'
        $m.Severity         | Should -Be 'UNKNOWN'
        @($m.References)[0] | Should -Match 'osv\.dev'
    }
}

Describe 'OnlineCve enrichment is strictly opt-in' {
    It 'Get-TcpkCveMatches exposes -OnlineCve as a switch (default OFF)' {
        (Get-Command Get-TcpkCveMatches).Parameters.Keys | Should -Contain 'OnlineCve'
        (Get-Command Get-TcpkCveMatches).Parameters['OnlineCve'].SwitchParameter | Should -BeTrue
    }
    It 'Invoke-TcpkAudit exposes -OnlineCve' {
        (Get-Command Invoke-TcpkAudit).Parameters.Keys | Should -Contain 'OnlineCve'
    }
}
