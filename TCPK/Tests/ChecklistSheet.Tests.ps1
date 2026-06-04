#requires -Version 5.1
# Pester 5: Get-TcpkChecklistStatus correlates findings to the 40-case thick-client
# test plan. Auto Status must be honest -- a no-finding is NOT a pass.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
}

Describe 'Get-TcpkChecklistStatus' {
    BeforeAll {
        $script:rows = & (Get-Module TCPK) {
            $f = @(
                (New-TcpkFinding -Module 'static' -RuleId 'tls-bypass.cert-callback-accepts-all' -Severity 'CRITICAL' -Title 't'),
                (New-TcpkFinding -Module 'static' -RuleId 'callsites.uac-bypass-registry' -Severity 'HIGH' -Title 't'),
                (New-TcpkFinding -Module 'recon'  -RuleId 'attacksurface.summary' -Severity 'INFO' -Title 't')
            )
            Get-TcpkChecklistStatus -Findings $f
        }
    }
    It 'returns the imported 40-case plan plus the extended cases' {
        @($script:rows).Count | Should -BeGreaterOrEqual 54
        ($script:rows | Where-Object Id -eq 'TC01') | Should -Not -BeNullOrEmpty
        ($script:rows | Where-Object Id -eq 'TC40') | Should -Not -BeNullOrEmpty
        ($script:rows | Where-Object Id -eq 'TC41') | Should -Not -BeNullOrEmpty   # extended: deserialization
        ($script:rows | Where-Object Id -eq 'TC43') | Should -Not -BeNullOrEmpty   # extended: dangerous call sites
    }
    It 'marks a case with a matching finding as REVIEW' {
        ($script:rows | Where-Object Id -eq 'TC09').AutoStatus | Should -Be 'REVIEW'
        ($script:rows | Where-Object Id -eq 'TC25').AutoStatus | Should -Be 'REVIEW'
    }
    It 'maps extended families too (deserialization finding -> TC41 REVIEW)' {
        $r = & (Get-Module TCPK) {
            $f = @((New-TcpkFinding -Module 'static' -RuleId 'deser.binaryformatter' -Severity 'CRITICAL' -Title 't'))
            Get-TcpkChecklistStatus -Findings $f
        }
        ($r | Where-Object Id -eq 'TC41').AutoStatus | Should -Be 'REVIEW'
    }
    It 'marks a GAP case as MANUAL-ONLY regardless of findings' {
        ($script:rows | Where-Object Id -eq 'TC12').AutoStatus | Should -Be 'MANUAL-ONLY'
        ($script:rows | Where-Object Id -eq 'TC18').AutoStatus | Should -Be 'MANUAL-ONLY'
    }
    It 'marks a case with no matching finding as NO FINDINGS (never auto-PASS)' {
        ($script:rows | Where-Object Id -eq 'TC04').AutoStatus | Should -Be 'NO FINDINGS'
        @($script:rows | Where-Object AutoStatus -eq 'PASS').Count | Should -Be 0
    }
    It 'ignores INFO / recon noise when correlating' {
        # attacksurface.summary (INFO) must not push any case to REVIEW on its own
        ($script:rows | Where-Object Id -eq 'TC04').Findings | Should -Be 0
    }
    It 'leaves the tester Result column blank' {
        @($script:rows | Where-Object { $_.Result -ne '' }).Count | Should -Be 0
    }
}
