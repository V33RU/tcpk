#requires -Version 5.1
# Markdown report exporter (v1.8.x report-excellence slice) -- the client-facing report.md
# deliverable: exec summary + severity-grouped findings carrying the full standards mapping.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
    $script:out = Join-Path ([IO.Path]::GetTempPath()) ("tcpk-md-" + [guid]::NewGuid().ToString('N') + ".md")
    $script:findings = & (Get-Module TCPK) {
        @(
            New-TcpkFinding -Module static -RuleId 'electron.cert-validation-bypass' -Severity HIGH -Confidence Inferred `
                -Title 'Electron cert verification accepts any cert' `
                -Description 'No reject path was found. [TCPK note: heuristic]' -Cwe @('CWE-295') `
                -File 'C:\app\resources\app.asar' -Evidence 'setCertificateVerifyProc; no callback(-2)' `
                -Fix 'Return callback(-2) on a fingerprint mismatch.'
            New-TcpkFinding -Module static -RuleId 'crypto.weak-hash' -Severity MEDIUM -Confidence Confirmed `
                -Title 'MD5 used for integrity' -Description 'MD5 is collision-broken.' -Cwe @('CWE-327')
            New-TcpkFinding -Module static -RuleId 'pe.unsigned' -Severity LOW -Confidence Inferred -Title 'Unsigned DLL'
        )
    }
    $script:findings | Export-TcpkReportMarkdown -OutFile $script:out -Target 'TestApp' | Out-Null
    $script:md = [IO.File]::ReadAllText($script:out)
}
AfterAll { if ($script:out -and (Test-Path -LiteralPath $script:out)) { Remove-Item -LiteralPath $script:out -Force } }

Describe 'Export-TcpkReportMarkdown' {
    It 'writes a report file' { Test-Path -LiteralPath $script:out | Should -BeTrue }
    It 'has the title and an executive summary with a severity table' {
        $script:md | Should -Match '# TCPK Security Audit Report'
        $script:md | Should -Match '## Executive summary'
        $script:md | Should -Match '\| Severity \| Count \|'
    }
    It 'groups findings by severity' {
        $script:md | Should -Match '### HIGH \(1\)'
        $script:md | Should -Match 'Electron cert verification accepts any cert'
    }
    It 'carries the standards mapping (CVSS v4.0, CWE, OWASP Desktop Top 10)' {
        $script:md | Should -Match 'CVSS v4.0:'
        $script:md | Should -Match 'CWE-295'
        $script:md | Should -Match 'OWASP Desktop Top 10: DA7'
    }
    It 'strips internal [TCPK] process notes from the description' {
        $script:md | Should -Not -Match '\[TCPK note'
    }
    It 'includes a verify block and the fix' {
        $script:md | Should -Match 'Verify:'
        $script:md | Should -Match 'Fix: Return callback'
    }
    It 'ends with the authorized-use disclaimer' {
        $script:md | Should -Match 'FOR AUTHORIZED TESTING ONLY'
    }
    It 'is pure ASCII' {
        ([regex]::Matches($script:md, '[^\x00-\x7F]')).Count | Should -Be 0
    }
}
