#requires -Version 5.1
# Delta / re-test report (v1.8.x report-excellence slice): Compare-TcpkAudit diffs two audits
# into NEW / FIXED / REGRESSED / unchanged at (RuleId + location) granularity.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
    $script:work = Join-Path ([IO.Path]::GetTempPath()) ("tcpk-delta-" + [guid]::NewGuid().ToString('N'))
    $script:bd = Join-Path $script:work 'base'
    $script:cd = Join-Path $script:work 'cur'
    New-Item -ItemType Directory -Path $script:bd, $script:cd -Force | Out-Null
    $mk = {
        param($objs, $dir)
        ($objs | ConvertTo-Json -Depth 6) | Set-Content -LiteralPath (Join-Path $dir 'findings.json') -Encoding UTF8
    }
    & $mk @(
        [pscustomobject]@{ RuleId = 'r1.alpha'; Severity = 'HIGH'; Confidence = 'Confirmed'; Title = 'Alpha'; File = 'C:\a\1.dll' }
        [pscustomobject]@{ RuleId = 'r2.beta';  Severity = 'LOW';  Confidence = 'Inferred';  Title = 'Beta';  File = 'C:\a\2.dll' }
    ) $script:bd
    & $mk @(
        [pscustomobject]@{ RuleId = 'r2.beta';  Severity = 'MEDIUM'; Confidence = 'Inferred';  Title = 'Beta';  File = 'C:\a\2.dll' }
        [pscustomobject]@{ RuleId = 'r3.gamma'; Severity = 'HIGH';   Confidence = 'Confirmed'; Title = 'Gamma'; File = 'C:\a\3.dll' }
    ) $script:cd
    $script:outMd = Join-Path $script:work 'delta.md'
    $script:delta = Compare-TcpkAudit $script:bd $script:cd -OutFile $script:outMd
    $script:md = [IO.File]::ReadAllText($script:outMd)
}
AfterAll { if ($script:work -and (Test-Path -LiteralPath $script:work)) { [IO.Directory]::Delete($script:work, $true) } }

Describe 'Compare-TcpkAudit' {
    It 'detects a new finding' {
        @($script:delta.New).Count | Should -Be 1
        $script:delta.New[0].RuleId | Should -Be 'r3.gamma'
    }
    It 'detects a fixed finding' {
        @($script:delta.Fixed).Count | Should -Be 1
        $script:delta.Fixed[0].RuleId | Should -Be 'r1.alpha'
    }
    It 'detects a regressed (severity-raised) finding' {
        @($script:delta.Regressed).Count | Should -Be 1
        $script:delta.Regressed[0].From | Should -Be 'LOW'
        $script:delta.Regressed[0].To   | Should -Be 'MEDIUM'
    }
    It 'counts unchanged locations' {
        $script:delta.UnchangedCount | Should -Be 1
    }
    It 'summarizes the delta' {
        $script:delta.Summary | Should -Be '+1 new, -1 fixed, 1 regressed, 1 unchanged'
    }
    It 'accepts a findings.json path directly (not just a directory)' {
        $d = Compare-TcpkAudit (Join-Path $script:bd 'findings.json') (Join-Path $script:cd 'findings.json')
        @($d.New).Count | Should -Be 1
    }
    It 'writes a Markdown delta report' {
        $script:md | Should -Match '# TCPK Audit Delta'
        $script:md | Should -Match '## New \(1\)'
        $script:md | Should -Match '## Fixed \(1\)'
        $script:md | Should -Match '## Regressed \(1\)'
    }
    It 'delta report is pure ASCII' {
        ([regex]::Matches($script:md, '[^\x00-\x7F]')).Count | Should -Be 0
    }
}
