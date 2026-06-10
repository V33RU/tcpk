#requires -Version 5.1
# Covers the two coverage/integration additions: app-stack fingerprinting
# (Test-TcpkAppStack) and the SARIF 2.1.0 exporter (Export-TcpkReportSarif).

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
    $script:work = Join-Path ([IO.Path]::GetTempPath()) ("tcpk-as-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:work -Force | Out-Null
}
AfterAll {
    if ($script:work -and (Test-Path -LiteralPath $script:work)) {
        try { [System.IO.Directory]::Delete($script:work, $true) } catch {}
    }
}

Describe 'Test-TcpkAppStack (technology-stack fingerprint)' {
    It 'detects a frozen Python app from its marker files' {
        $d = Join-Path $script:work 'py'; New-Item -ItemType Directory -Path $d -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $d 'python311.dll')   -Value 'stub'
        Set-Content -LiteralPath (Join-Path $d 'base_library.zip') -Value 'stub'
        $r = @(Test-TcpkAppStack -Path $d | Where-Object { $_.RuleId -eq 'appstack.python-frozen' })
        $r.Count | Should -BeGreaterThan 0
        $r[0].Severity | Should -Be 'INFO'
    }
    It 'detects Qt from Qt6Core.dll' {
        $d = Join-Path $script:work 'qt'; New-Item -ItemType Directory -Path $d -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $d 'Qt6Core.dll') -Value 'stub'
        (@(Test-TcpkAppStack -Path $d | Where-Object { $_.RuleId -eq 'appstack.qt' })).Count | Should -BeGreaterThan 0
    }
    It 'stays silent on an unknown / non-marker layout' {
        $d = Join-Path $script:work 'plain'; New-Item -ItemType Directory -Path $d -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $d 'readme.txt') -Value 'hello'
        (@(Test-TcpkAppStack -Path $d)).Count | Should -Be 0
    }
}

Describe 'Export-TcpkReportSarif (SARIF 2.1.0)' {
    It 'writes valid SARIF with rules, results, levels and security-severity' {
        $out = Join-Path $script:work 'report.sarif'
        & (Get-Module TCPK) { param($o)
            $f = @(
                New-TcpkFinding -Module 'static'  -RuleId 'secrets.pem-private-key' -Severity 'HIGH'   -Confidence 'Inferred' -Title 'key'  -File 'C:\a.dll' -Cwe @('CWE-321')
                New-TcpkFinding -Module 'network' -RuleId 'scheme.cleartext-http'   -Severity 'MEDIUM' -Confidence 'Inferred' -Title 'http' -File 'C:\b.dll'
            )
            $f | Export-TcpkReportSarif -OutFile $o -Target 'demo'
        } $out

        Test-Path $out | Should -BeTrue
        $j = Get-Content -Raw $out | ConvertFrom-Json
        $j.version                    | Should -Be '2.1.0'
        $j.runs[0].tool.driver.name   | Should -Be 'TCPK'
        @($j.runs[0].results).Count   | Should -Be 2
        @($j.runs[0].tool.driver.rules).Count | Should -Be 2
        ($j.runs[0].results | Where-Object { $_.ruleId -eq 'secrets.pem-private-key' }).level | Should -Be 'error'
        ($j.runs[0].results | Where-Object { $_.ruleId -eq 'secrets.pem-private-key' }).properties.'security-severity' | Should -Not -BeNullOrEmpty
    }
}
