#requires -Version 5.1
# Pester 5: Resolve-TcpkFindings cross-rule dedupe must keep the IL-PROVEN cert-bypass
# (tls-bypass.cert-callback-accepts-all, Confirmed) as the authoritative finding, and
# never let a co-located weaker rule demote it. Regression for the bug where the proven
# CRITICAL was silently demoted to INFO when callsites.disabled-cert-validation fired on
# the same file.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
}

Describe 'Resolve-TcpkFindings - proven cert-bypass dedupe' {
    It 'keeps the IL-proven tls-bypass CRITICAL and supersedes the Inferred callsite on the same file' {
        $out = & (Get-Module TCPK) {
            $file = 'C:\app\Some.Plugin.dll'
            $proven   = New-TcpkFinding -Module 'static' -RuleId 'tls-bypass.cert-callback-accepts-all' -Severity 'CRITICAL' -Confidence 'Confirmed' -Title 'accepts all' -File $file
            $callsite = New-TcpkFinding -Module 'static' -RuleId 'callsites.disabled-cert-validation'   -Severity 'CRITICAL' -Confidence 'Inferred'  -Title 'cert callback present' -File $file
            @($proven, $callsite) | Resolve-TcpkFindings
        }
        $p = $out | Where-Object RuleId -eq 'tls-bypass.cert-callback-accepts-all'
        $c = $out | Where-Object RuleId -eq 'callsites.disabled-cert-validation'
        $p.Severity   | Should -Be 'CRITICAL'      # proven verdict survives
        $p.Confidence | Should -Be 'Confirmed'
        $c.Severity   | Should -Be 'INFO'           # weaker, co-located rule is superseded
    }
    It 'still demotes a WEAK (Inferred) tls-bypass when a callsite covers the same file' {
        $out = & (Get-Module TCPK) {
            $file = 'C:\app\Other.dll'
            $weak     = New-TcpkFinding -Module 'static' -RuleId 'tls-bypass.servercert-callback' -Severity 'CRITICAL' -Confidence 'Inferred' -Title 'regex hit' -File $file
            $callsite = New-TcpkFinding -Module 'static' -RuleId 'callsites.disabled-cert-validation' -Severity 'CRITICAL' -Confidence 'Inferred' -Title 'callsite' -File $file
            @($weak, $callsite) | Resolve-TcpkFindings
        }
        ($out | Where-Object RuleId -eq 'tls-bypass.servercert-callback').Severity | Should -Be 'INFO'
    }
}
