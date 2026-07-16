#requires -Version 5.1
# Pester 5: Get-TcpkAssuranceSplit is the precision view -- Confirmed* tiers are 'proven'
# (act on these), Inferred/Unverified are 'leads' (triage), and Likely-FP/Skipped/other are
# neither. Pure logic, runs anywhere.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
}

Describe 'Get-TcpkAssuranceSplit' {
    It 'counts every Confirmed* tier as proven and Inferred/Unverified as leads' {
        $r = & (Get-Module TCPK) {
            Get-TcpkAssuranceSplit -Findings @(
                [pscustomobject]@{ Confidence = 'Confirmed (IL)' }
                [pscustomobject]@{ Confidence = 'Confirmed (exploit)' }
                [pscustomobject]@{ Confidence = 'Confirmed (dynamic)' }
                [pscustomobject]@{ Confidence = 'Confirmed' }
                [pscustomobject]@{ Confidence = 'Inferred' }
                [pscustomobject]@{ Confidence = 'Unverified' }
                [pscustomobject]@{ Confidence = 'Likely-FP (IL)' }
                [pscustomobject]@{ Confidence = 'Skipped' }
            )
        }
        $r.ProvenCount | Should -Be 4
        $r.LeadCount   | Should -Be 2
    }
    It 'returns empty splits for no findings' {
        $r = & (Get-Module TCPK) { Get-TcpkAssuranceSplit -Findings @() }
        $r.ProvenCount | Should -Be 0
        $r.LeadCount   | Should -Be 0
    }
}
