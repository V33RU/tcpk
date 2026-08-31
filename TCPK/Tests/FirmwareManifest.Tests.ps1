#requires -Version 5.1
# Pester 5: Test-TcpkFirmwareManifest.
#
# The parser is a pure function over JSON text, so every case here runs without touching
# Windows-specific APIs. The behaviour that matters most is the NEGATIVE: an unrelated .json
# (settings, telemetry, appsettings) must NOT be reported as a firmware manifest, and a
# manifest that DOES carry a signature must not be reported as unsigned.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force

    $script:work = Join-Path ([IO.Path]::GetTempPath()) ('tcpk-fwm-' + [guid]::NewGuid().ToString('N').Substring(0,10))
    New-Item -ItemType Directory -Force -Path $script:work | Out-Null

    function script:WriteJson([string]$name, [object]$obj) {
        $p = Join-Path $script:work $name
        ($obj | ConvertTo-Json -Depth 6) | Set-Content -LiteralPath $p -Encoding UTF8
        return $p
    }
}
AfterAll {
    if ($script:work -and (Test-Path $script:work)) { Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $script:work }
}

Describe 'Test-TcpkFirmwareManifest: shape gate' {
    It 'ignores a plain settings JSON that has neither version nor url' {
        [void](script:WriteJson 'settings.json' @{ theme='dark'; timeoutSec=30 })
        @(Test-TcpkFirmwareManifest -Path $script:work).Count | Should -Be 0
    }
    It 'ignores a JSON with a url but no version' {
        [void](script:WriteJson 'links.json' @{ url='https://example.com/api'; label='home' })
        @(Test-TcpkFirmwareManifest -Path $script:work).Count | Should -Be 0
    }
    It 'ignores a JSON with a version but no url' {
        [void](script:WriteJson 'about.json' @{ version='1.0.0'; author='vendor' })
        @(Test-TcpkFirmwareManifest -Path $script:work).Count | Should -Be 0
    }
}

Describe 'Test-TcpkFirmwareManifest: signature rules' {
    BeforeEach { Get-ChildItem -LiteralPath $script:work -File | Remove-Item -Force -ErrorAction SilentlyContinue }

    It 'reports no-signature HIGH when manifest has version + url and no signature field' {
        [void](script:WriteJson 'fw.json' @{ version='1.2.3'; downloadUrl='https://cdn.vendor.com/1.2.3/fw.bin' })
        $rows = @(Test-TcpkFirmwareManifest -Path $script:work)
        $sig = $rows | Where-Object { $_.RuleId -eq 'firmware.manifest.no-signature' }
        $sig | Should -Not -BeNullOrEmpty
        $sig.Severity | Should -Be 'HIGH'
    }

    It 'does NOT fire no-signature when a signature field is present' {
        [void](script:WriteJson 'fw.json' @{ version='1.2.3'; url='https://cdn.vendor.com/fw.bin'
                                             signature='MEUCIQDAAAA='; publicKey='-----BEGIN PUBLIC KEY-----' })
        @(Test-TcpkFirmwareManifest -Path $script:work | Where-Object { $_.RuleId -eq 'firmware.manifest.no-signature' }).Count |
            Should -Be 0
    }

    It 'reports hash-only when the manifest has a hash but no pubkey and no signature-like field' {
        [void](script:WriteJson 'fw.json' @{ version='1.2.3'; url='https://cdn.vendor.com/fw.bin'
                                             signature='deadbeef'; sha256='deadbeef' })
        $rows = @(Test-TcpkFirmwareManifest -Path $script:work)
        ($rows | Where-Object { $_.RuleId -eq 'firmware.manifest.hash-only' }) | Should -Not -BeNullOrEmpty
    }

    It 'reports weak-hash HIGH when the algorithm is md5' {
        [void](script:WriteJson 'fw.json' @{ version='1.2.3'; url='https://cdn.vendor.com/fw.bin'
                                             signature='sig'; md5='deadbeef' })
        (@(Test-TcpkFirmwareManifest -Path $script:work) | Where-Object { $_.RuleId -eq 'firmware.manifest.weak-hash' }).Count |
            Should -BeGreaterThan 0
    }
}

Describe 'Test-TcpkFirmwareManifest: transport' {
    BeforeEach { Get-ChildItem -LiteralPath $script:work -File | Remove-Item -Force -ErrorAction SilentlyContinue }

    It 'reports plaintext-url HIGH when the artifact URL is http://' {
        [void](script:WriteJson 'fw.json' @{ version='1.2.3'; url='http://updates.vendor.com/fw.bin' })
        (@(Test-TcpkFirmwareManifest -Path $script:work) | Where-Object { $_.RuleId -eq 'firmware.manifest.plaintext-url' }).Count |
            Should -BeGreaterThan 0
    }

    It 'does NOT fire plaintext-url when the URL is https://' {
        [void](script:WriteJson 'fw.json' @{ version='1.2.3'; url='https://updates.vendor.com/fw.bin' })
        @(Test-TcpkFirmwareManifest -Path $script:work | Where-Object { $_.RuleId -eq 'firmware.manifest.plaintext-url' }).Count |
            Should -Be 0
    }
}

Describe 'Test-TcpkFirmwareManifest: rollback' {
    BeforeEach { Get-ChildItem -LiteralPath $script:work -File | Remove-Item -Force -ErrorAction SilentlyContinue }

    It 'reports no-rollback-guard when the manifest declares no minVersion' {
        [void](script:WriteJson 'fw.json' @{ version='1.2.3'; url='https://x/y' })
        (@(Test-TcpkFirmwareManifest -Path $script:work) | Where-Object { $_.RuleId -eq 'firmware.manifest.no-rollback-guard' }).Count |
            Should -BeGreaterThan 0
    }

    It 'does NOT fire no-rollback-guard when minVersion is present' {
        [void](script:WriteJson 'fw.json' @{ version='1.2.3'; url='https://x/y'; minVersion='1.2.0' })
        @(Test-TcpkFirmwareManifest -Path $script:work | Where-Object { $_.RuleId -eq 'firmware.manifest.no-rollback-guard' }).Count |
            Should -Be 0
    }
}
