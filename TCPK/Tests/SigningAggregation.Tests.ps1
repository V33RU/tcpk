#requires -Version 5.1
# DLL signing matrix (info-only) + finding aggregation (same rule -> one finding
# with an Affected list). Deterministic, offline.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
    $script:work = Join-Path ([IO.Path]::GetTempPath()) ("tcpk-sigagg-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:work -Force | Out-Null
}
AfterAll {
    if ($script:work -and (Test-Path -LiteralPath $script:work)) {
        Remove-Item -LiteralPath $script:work -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Describe 'Finding aggregation (same rule -> one finding + Affected list)' {
    It 'collapses N occurrences of the same RuleId+Severity+Confidence into one with Affected=N' {
        $hosts = 'api.example.com','cdn.example.net','www.example.com','telemetry.example.io','login.example.org','update.example.com'
        $res = & (Get-Module TCPK) {
            param($hosts)
            $list = foreach ($h in $hosts) {
                New-TcpkFinding -Module 'network' -RuleId 'scheme.cleartext-http' -Severity 'MEDIUM' -Confidence 'Inferred' `
                    -Title "Cleartext http:// endpoint: $h" -File 'C:\app\x.dll' -Evidence "http://$h/" -Cwe @('CWE-319') -Description 'c'
            }
            @($list | Resolve-TcpkFindings)
        } $hosts
        @($res).Count | Should -Be 1
        $res[0].Title | Should -Match 'Cleartext http:// endpoint \(6 affected\)'
        @($res[0].Affected).Count | Should -Be 6
        ($res[0].Affected -join ',') | Should -Match 'api\.example\.com'
    }

    It 'keeps occurrences separate with -NoAggregate' {
        $res = & (Get-Module TCPK) {
            $list = foreach ($h in 'a.com','b.com','c.com') {
                New-TcpkFinding -Module 'network' -RuleId 'scheme.cleartext-http' -Severity 'MEDIUM' -Confidence 'Inferred' `
                    -Title "Cleartext http:// endpoint: $h" -File 'C:\app\x.dll' -Evidence "http://$h/"
            }
            @($list | Resolve-TcpkFindings -NoAggregate)
        }
        @($res).Count | Should -Be 3
    }

    It 'does NOT merge across different severities or confidences' {
        $res = & (Get-Module TCPK) {
            $a = New-TcpkFinding -Module 'm' -RuleId 'r.x' -Severity 'HIGH'   -Confidence 'Confirmed' -Title 'X: one'   -File 'a.dll'
            $b = New-TcpkFinding -Module 'm' -RuleId 'r.x' -Severity 'MEDIUM' -Confidence 'Confirmed' -Title 'X: two'   -File 'b.dll'
            $c = New-TcpkFinding -Module 'm' -RuleId 'r.x' -Severity 'HIGH'   -Confidence 'Inferred'  -Title 'X: three' -File 'c.dll'
            @(@($a,$b,$c) | Resolve-TcpkFindings)
        }
        # three distinct (Severity,Confidence) buckets -> no aggregation -> 3 findings
        @($res).Count | Should -Be 3
    }
}

Describe 'DLL signing matrix (Get-TcpkSigningMatrix)' {
    It 'reports signed vs unsigned per DLL (information only, no findings)' {
        $dir = Join-Path $script:work 'sig'; New-Item -ItemType Directory -Path $dir -Force | Out-Null
        Copy-Item "$env:WINDIR\System32\winhttp.dll" $dir -ErrorAction SilentlyContinue
        # a fake unsigned "DLL" (not a real PE -> NotSigned)
        [IO.File]::WriteAllBytes((Join-Path $dir 'fake.dll'), [Text.Encoding]::UTF8.GetBytes('not a real PE'))

        $rows = @(Get-TcpkSigningMatrix -Path $dir)
        $rows.Count | Should -BeGreaterThan 0
        # every row is a plain object, NOT a finding (no Severity property)
        ($rows[0].PSObject.Properties.Name -contains 'Severity') | Should -BeFalse
        ($rows[0].PSObject.Properties.Name -contains 'Signed')   | Should -BeTrue

        $fake = $rows | Where-Object { $_.DLL -eq 'fake.dll' }
        $fake.Signed | Should -Be 'NO'

        if (Test-Path "$env:WINDIR\System32\winhttp.dll") {
            $wh = $rows | Where-Object { $_.DLL -eq 'winhttp.dll' }
            $wh.Signed | Should -BeIn @('YES','CATALOG')   # system DLL is catalog-signed
        }
    }
}
