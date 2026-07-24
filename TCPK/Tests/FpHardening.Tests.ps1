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

Describe 'Test-TcpkSecrets AWS rule precision (case-sensitive + .pak skip)' {
    It 'does NOT flag lowercase natural-language text matching an AWS prefix (e.g. German anpassen...)' {
        $d = New-FpDir
        Set-Content -LiteralPath (Join-Path $d 'strings.txt') -Encoding ASCII -Value 'menu anpassenSchriftarten anpassenSeitenleiste options'
        try { @(Test-TcpkSecrets -Path $d | Where-Object RuleId -eq 'secrets.aws-access-key-id').Count | Should -Be 0 }
        finally { Remove-Item -LiteralPath $d -Recurse -Force }
    }
    It 'STILL flags a real UPPERCASE AWS access key in app code' {
        $d = New-FpDir
        Set-Content -LiteralPath (Join-Path $d 'config.json') -Encoding ASCII -Value '{"awsKey":"AKIA1234567890ABCDEF"}'
        try { @(Test-TcpkSecrets -Path $d | Where-Object RuleId -eq 'secrets.aws-access-key-id').Count | Should -BeGreaterThan 0 }
        finally { Remove-Item -LiteralPath $d -Recurse -Force }
    }
    It 'skips Chromium .pak locale packs entirely' {
        $d = New-FpDir
        Set-Content -LiteralPath (Join-Path $d 'de.pak') -Encoding ASCII -Value 'AKIA1234567890ABCDEF'
        try { @(Test-TcpkSecrets -Path $d | Where-Object RuleId -eq 'secrets.aws-access-key-id').Count | Should -Be 0 }
        finally { Remove-Item -LiteralPath $d -Recurse -Force }
    }
}

Describe 'Test-TcpkEndpoints loopback vs non-production (audit-found FP)' {
    It 'treats a loopback URL as INFO recon, not a HIGH non-production leak' {
        $d = New-FpDir
        Set-Content -LiteralPath (Join-Path $d 'config.json') -Encoding ASCII -Value '{"u":"http://127.0.0.1:3000/api","v":"http://localhost:8080/"}'
        try {
            $f = @(Test-TcpkEndpoints -Path $d)
            @($f | Where-Object { $_.RuleId -eq 'endpoints.non-production' }).Count | Should -Be 0
            @($f | Where-Object { $_.RuleId -eq 'endpoints.loopback' -and $_.Severity -eq 'INFO' }).Count | Should -BeGreaterThan 0
        } finally { Remove-Item -LiteralPath $d -Recurse -Force }
    }
    It 'STILL flags a shipped external dev/staging URL (as MEDIUM)' {
        $d = New-FpDir
        Set-Content -LiteralPath (Join-Path $d 'config.json') -Encoding ASCII -Value '{"api":"https://api.staging.corp.example/v1"}'
        try {
            $f = @(Test-TcpkEndpoints -Path $d | Where-Object { $_.RuleId -eq 'endpoints.non-production' })
            $f.Count | Should -BeGreaterThan 0
            $f[0].Severity | Should -Be 'MEDIUM'
        } finally { Remove-Item -LiteralPath $d -Recurse -Force }
    }
}

Describe 'Test-TcpkSecrets credential value hardening (audit-found FPs)' {
    It 'does NOT flag a UI / i18n message whose value is a natural-language phrase' {
        # Real Electron FP: WRONG_PASSWORD: "Wrong Password" (an error string, not a secret).
        $d = New-FpDir
        Set-Content -LiteralPath (Join-Path $d 'app.js') -Encoding ASCII -Value 'const WRONG_PASSWORD = "Wrong Password"; const m = "Enter your password";'
        try { @(Test-TcpkSecrets -Path $d | Where-Object RuleId -eq 'secrets.cleartext-credential').Count | Should -Be 0 }
        finally { Remove-Item -LiteralPath $d -Recurse -Force }
    }
    It 'STILL flags a real hardcoded password (has a digit/symbol)' {
        $d = New-FpDir
        Set-Content -LiteralPath (Join-Path $d 'cfg.js') -Encoding ASCII -Value 'const cfg = { password: "R3alP@ssw0rd2024" };'
        try { @(Test-TcpkSecrets -Path $d | Where-Object RuleId -eq 'secrets.cleartext-credential').Count | Should -BeGreaterThan 0 }
        finally { Remove-Item -LiteralPath $d -Recurse -Force }
    }
    It 'does NOT flag the canonical basic-auth URL placeholder (user:pass@host)' {
        $d = New-FpDir
        Set-Content -LiteralPath (Join-Path $d 'doc.js') -Encoding ASCII -Value '// credentials like https://user:pass@host/ are blocked'
        try { @(Test-TcpkSecrets -Path $d | Where-Object RuleId -eq 'secrets.basic-auth-in-url').Count | Should -Be 0 }
        finally { Remove-Item -LiteralPath $d -Recurse -Force }
    }
    It 'STILL flags real credentials embedded in a URL' {
        $d = New-FpDir
        Set-Content -LiteralPath (Join-Path $d 'db.js') -Encoding ASCII -Value 'const u = "postgres://svcacct:Wint3r2024Pass@10.44.12.9/db";'
        try { @(Test-TcpkSecrets -Path $d | Where-Object RuleId -eq 'secrets.basic-auth-in-url').Count | Should -BeGreaterThan 0 }
        finally { Remove-Item -LiteralPath $d -Recurse -Force }
    }
}
