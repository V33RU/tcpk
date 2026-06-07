#requires -Version 5.1
# Test-TcpkCsvInjection (A39 / CWE-1236): flags CSV/Excel export sinks that lack a
# formula-neutralization marker. Marker strings are embedded as managed string
# literals (Read-TcpkAllText surfaces them) and as a shipped .js file.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force

    $script:work = Join-Path ([IO.Path]::GetTempPath()) ("tcpk-csv-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:work -Force | Out-Null

    # 1) PE that references a CSV export sink, NO neutralization marker
    $script:d1 = Join-Path $script:work 'd1'; New-Item -ItemType Directory -Path $script:d1 -Force | Out-Null
    Add-Type -TypeDefinition 'public class Exp1 { public string s = "uses CsvHelper CsvWriter WriteRecords"; }' -OutputAssembly (Join-Path $script:d1 'Exp1.dll') -OutputType Library

    # 2) PE with an export sink AND a neutralization marker -> suppressed
    $script:d2 = Join-Path $script:work 'd2'; New-Item -ItemType Directory -Path $script:d2 -Force | Out-Null
    Add-Type -TypeDefinition 'public class Exp2 { public string s = "CsvHelper export"; public string n = "SanitizeForInjection enabled"; }' -OutputAssembly (Join-Path $script:d2 'Exp2.dll') -OutputType Library

    # 3) Shipped JS export (Electron) -> json2csv, no neutralization
    $script:d3 = Join-Path $script:work 'd3'; New-Item -ItemType Directory -Path $script:d3 -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $script:d3 'export.js') -Encoding ASCII -Value "const { Parser } = require('json2csv'); function e(rows){ return new Parser().parse(rows); }"

    # 4) PE with NO export sink at all -> nothing
    $script:d4 = Join-Path $script:work 'd4'; New-Item -ItemType Directory -Path $script:d4 -Force | Out-Null
    Add-Type -TypeDefinition 'public class Plain { public int X(){ return 1; } }' -OutputAssembly (Join-Path $script:d4 'Plain.dll') -OutputType Library
}

AfterAll {
    if ($script:work -and (Test-Path -LiteralPath $script:work)) {
        try { [System.IO.Directory]::Delete($script:work, $true) } catch {}
    }
}

Describe 'Test-TcpkCsvInjection' {
    It 'flags a CSV/Excel export sink with no neutralization marker' {
        $r = @(Test-TcpkCsvInjection -Path $script:d1)
        $r.Count | Should -Be 1
        $r[0].RuleId     | Should -Be 'csv.formula-injection-risk'
        $r[0].Severity   | Should -Be 'LOW'
        $r[0].Confidence | Should -Be 'Inferred'
        ($r[0].Cwe -join ',') | Should -Match 'CWE-1236'
    }

    It 'is suppressed when a formula-neutralization marker is present' {
        $r = @(Test-TcpkCsvInjection -Path $script:d2)
        $r.Count | Should -Be 0
    }

    It 'flags a shipped JS json2csv export with no neutralization' {
        $r = @(Test-TcpkCsvInjection -Path $script:d3)
        $r.Count | Should -Be 1
        $r[0].RuleId | Should -Be 'csv.formula-injection-risk'
    }

    It 'does not fire when there is no export sink' {
        $r = @(Test-TcpkCsvInjection -Path $script:d4)
        $r.Count | Should -Be 0
    }

    It 'has report mappings (ATT&CK + TASVS + verify hint) wired for csv.*' {
        & (Get-Module TCPK) {
            (Get-TcpkAttackText 'csv.formula-injection-risk') | Should -Not -BeNullOrEmpty
            (Get-TcpkTasvsText  'csv.formula-injection-risk') | Should -Match 'DA1 Injection'
            (Get-TcpkVerifyHint -RuleId 'csv.formula-injection-risk' -File 'x.dll' -Evidence 'e') | Should -Match 'formula'
        }
    }
}
