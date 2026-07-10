#requires -Version 5.1
# Pester 5: Invoke-TcpkSecretRecovery turns a shipped key + IV + ciphertext into a
# DEMONSTRATED plaintext ('Confirmed (exploit)'). The ciphertext is built at runtime with
# .NET AES (no external compiler), so this runs anywhere PowerShell does - including Linux.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force

    $key = 'J8gLXc454o5tW2HEF7HahcXPufj9v8k8'; $iv = 'fq20T0gMnXa6g0l4'
    $script:plain = 'S3cr3tP@ss'
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Mode = 'CBC'; $aes.Padding = 'PKCS7'
    $aes.Key = [System.Text.Encoding]::ASCII.GetBytes($key)
    $aes.IV  = [System.Text.Encoding]::ASCII.GetBytes($iv)
    $enc = $aes.CreateEncryptor()
    $pb  = [System.Text.Encoding]::ASCII.GetBytes($script:plain)
    $script:ct = [Convert]::ToBase64String($enc.TransformFinalBlock($pb, 0, $pb.Length))

    $script:fx = Join-Path ([System.IO.Path]::GetTempPath()) ('tcpk-sr-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:fx | Out-Null
    $cfg = "<configuration><appSettings><add key=`"AESKEY`" value=`"$key`" /><add key=`"IV`" value=`"$iv`" /><add key=`"DBPASSWORD`" value=`"$($script:ct)`" /></appSettings></configuration>"
    Set-Content -LiteralPath (Join-Path $script:fx 'App.exe.config') -Value $cfg

    $script:clean = Join-Path ([System.IO.Path]::GetTempPath()) ('tcpk-sr-clean-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:clean | Out-Null
    Set-Content -LiteralPath (Join-Path $script:clean 'App.exe.config') -Value "<configuration><appSettings><add key=`"DBSERVER`" value=`"localhost`" /></appSettings></configuration>"
}
AfterAll {
    foreach ($d in @($script:fx, $script:clean)) { if ($d -and (Test-Path $d)) { Remove-Item $d -Recurse -Force -ErrorAction SilentlyContinue } } }

Describe 'Invoke-TcpkSecretRecovery' {
    It 'recovers the plaintext from a shipped key + IV + ciphertext (with -Reveal)' {
        $r = Invoke-TcpkSecretRecovery -Target $script:fx -Reveal
        @($r | Where-Object { $_.RuleId -eq 'exploit.secret-recovered' }).Count | Should -BeGreaterThan 0
        ($r.Evidence -join ';') | Should -Match ([regex]::Escape($script:plain))
    }
    It 'reports the recovery as CRITICAL / Confirmed (exploit)' {
        $r = @(Invoke-TcpkSecretRecovery -Target $script:fx -Reveal)[0]
        $r.Severity   | Should -Be 'CRITICAL'
        $r.Confidence | Should -Be 'Confirmed (exploit)'
        $r.Module     | Should -Be 'exploit'
    }
    It 'masks the recovered secret by default (no -Reveal)' {
        $r = Invoke-TcpkSecretRecovery -Target $script:fx
        ($r.Evidence -join ';') | Should -Not -Match ([regex]::Escape($script:plain))
    }
    It 'emits nothing when there is no key/IV/ciphertext material' {
        $r = Invoke-TcpkSecretRecovery -Target $script:clean
        @($r | Where-Object { $_.RuleId -eq 'exploit.secret-recovered' }).Count | Should -Be 0
    }
    It 'New-TcpkFinding accepts the Confirmed (exploit) tier' {
        $f = & (Get-Module TCPK) { New-TcpkFinding -Module 'exploit' -RuleId 'exploit.secret-recovered' -Severity 'CRITICAL' -Confidence 'Confirmed (exploit)' -Title 't' }
        $f.Confidence | Should -Be 'Confirmed (exploit)'
    }
}
