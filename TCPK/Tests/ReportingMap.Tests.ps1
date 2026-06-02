#requires -Version 5.1
# Pester 5: reporting batch - CVSS v4.0 banding (v3.1 dropped), per-finding Impact,
# and OWASP TASVS / Desktop App Top 10 mapping (Get-TcpkTasvsMap).

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
}

Describe 'CVSS is v4.0 only' {
    It 'returns a CVSS:4.0 vector and no v3.1' {
        $b = & (Get-Module TCPK) { Get-TcpkCvssBand 'CRITICAL' }
        $b | Should -Match 'CVSS:4\.0/'
        $b | Should -Not -Match 'CVSS:3\.'
    }
}

Describe 'Per-finding Impact' {
    It 'derives a default impact from severity when none is set' {
        $t = & (Get-Module TCPK) {
            $f = New-TcpkFinding -Module 'static' -RuleId 'x' -Severity 'CRITICAL' -Title 't'
            Get-TcpkImpactText $f
        }
        $t | Should -Not -BeNullOrEmpty
    }
    It 'uses an explicit Impact when provided' {
        $t = & (Get-Module TCPK) {
            $f = New-TcpkFinding -Module 'static' -RuleId 'x' -Severity 'LOW' -Title 't' -Impact 'Custom.'
            Get-TcpkImpactText $f
        }
        $t | Should -Be 'Custom.'
    }
}

Describe 'Get-TcpkTasvsMap' {
    It 'is exported' {
        Get-Command Get-TcpkTasvsMap -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
    }
    It 'maps a storage rule to TASVS-STORAGE + DA3' {
        $m = Get-TcpkTasvsMap -RuleId 'secrets.azure-key'
        $m.Tasvs | Should -Match 'TASVS-STORAGE'
        $m.DesktopTop10 | Should -Match 'DA3'
    }
    It 'maps a TLS rule to TASVS-NETWORK + DA7' {
        $m = Get-TcpkTasvsMap -RuleId 'tls-bypass.foo'
        $m.Tasvs | Should -Match 'TASVS-NETWORK'
        $m.DesktopTop10 | Should -Match 'DA7'
    }
    It 'dumps the full table with no args' {
        @(Get-TcpkTasvsMap).Count | Should -BeGreaterThan 10
    }
    It 'maps piped findings' {
        $rows = & (Get-Module TCPK) { New-TcpkFinding -Module 'creds' -RuleId 'localdb.sqlite-unencrypted' -Severity 'HIGH' -Title 'db' } | Get-TcpkTasvsMap
        $rows.Tasvs | Should -Match 'TASVS-STORAGE'
    }
}
