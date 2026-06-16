#requires -Version 5.1
# Pester 5: false-positive hardening (audit #4). The three highest-volume, highest-embarrassment
# FP generators must REJECT out-of-range / placeholder / value-less matches but still CATCH real
# ones. Guards: IPv4 octet+range validation, config placeholder/template skip, log keyword needs a
# real value.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
    function New-FpDir {
        $d = Join-Path ([IO.Path]::GetTempPath()) ("tcpk-fp-" + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $d -Force | Out-Null; $d
    }
}

Describe 'Test-TcpkPiiInLogs IPv4 hardening' {
    It 'does NOT flag out-of-range / private / doc IPv4 (e.g. 999.999.999.999)' {
        $d = New-FpDir
        Set-Content -LiteralPath (Join-Path $d 'a.txt') -Encoding ASCII -Value 'err 999.999.999.999 ; host 192.168.1.10 ; doc 203.0.113.7'
        try { @(Test-TcpkPiiInLogs -Path $d | Where-Object RuleId -eq 'pii.ipv4').Count | Should -Be 0 }
        finally { Remove-Item -LiteralPath $d -Recurse -Force }
    }
    It 'DOES flag a real public IPv4' {
        $d = New-FpDir
        Set-Content -LiteralPath (Join-Path $d 'b.txt') -Encoding ASCII -Value 'client from 8.8.8.8 connected'
        try { @(Test-TcpkPiiInLogs -Path $d | Where-Object RuleId -eq 'pii.ipv4').Count | Should -BeGreaterThan 0 }
        finally { Remove-Item -LiteralPath $d -Recurse -Force }
    }
}

Describe 'Test-TcpkPlaintextConfigs placeholder hardening' {
    It 'does NOT flag a placeholder secret value (password=REDACTED)' {
        $d = New-FpDir
        Set-Content -LiteralPath (Join-Path $d 'app.config') -Encoding ASCII -Value '{"password":"REDACTED"}'
        try { @(Test-TcpkPlaintextConfigs -Path $d | Where-Object { $_.RuleId -like 'config.*' }).Count | Should -Be 0 }
        finally { Remove-Item -LiteralPath $d -Recurse -Force }
    }
    It 'DOES flag a real-looking secret value' {
        $d = New-FpDir
        Set-Content -LiteralPath (Join-Path $d 'app.config') -Encoding ASCII -Value '{"password":"Sup3rSecretValue99"}'
        try { @(Test-TcpkPlaintextConfigs -Path $d | Where-Object { $_.RuleId -like 'config.*' }).Count | Should -BeGreaterThan 0 }
        finally { Remove-Item -LiteralPath $d -Recurse -Force }
    }
}

Describe 'Test-TcpkLogFiles sensitive-keyword hardening' {
    It 'does NOT flag a bare keyword in prose (no value)' {
        $d = New-FpDir
        Set-Content -LiteralPath (Join-Path $d 'app.log') -Encoding ASCII -Value '2026-06-01 12:00:00 INFO user changed password successfully then token refresh started'
        try { @(Test-TcpkLogFiles -Path $d | Where-Object RuleId -eq 'log.sensitive-keywords').Count | Should -Be 0 }
        finally { Remove-Item -LiteralPath $d -Recurse -Force }
    }
    It 'DOES flag a keyword followed by a real value' {
        $d = New-FpDir
        Set-Content -LiteralPath (Join-Path $d 'app.log') -Encoding ASCII -Value '2026-06-01 12:00:00 DEBUG password=hunter2longvalue'
        try { @(Test-TcpkLogFiles -Path $d | Where-Object RuleId -eq 'log.sensitive-keywords').Count | Should -BeGreaterThan 0 }
        finally { Remove-Item -LiteralPath $d -Recurse -Force }
    }
}
