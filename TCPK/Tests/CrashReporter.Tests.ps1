#requires -Version 5.1
# Pester 5: Test-TcpkCrashReporter. Electron apps use Crashpad, not WER, so this is the
# crash-exposure check that applies to them. Everything here is offline and cross-platform
# except the ACL-dependent paths, which the detector degrades on rather than failing.

BeforeAll {
    Import-Module "$PSScriptRoot\..\TCPK.psd1" -Force

    $script:root = Join-Path ([System.IO.Path]::GetTempPath()) ("tcpk-crash-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
    New-Item -ItemType Directory -Path $script:root -Force | Out-Null

    # Minimal Electron-shaped target: a crashpad handler, a package.json, and a main.js
    # carrying a crashReporter.start() call with an upload endpoint.
    Set-Content -LiteralPath (Join-Path $script:root 'crashpad_handler.exe') -Value 'MZ stub' -Encoding ASCII
    Set-Content -LiteralPath (Join-Path $script:root 'package.json') `
        -Value '{ "name": "tcpk-crash-fixture", "productName": "TcpkCrashFixture" }' -Encoding ASCII
    Set-Content -LiteralPath (Join-Path $script:root 'main.js') -Encoding ASCII -Value @'
const { crashReporter } = require('electron')
crashReporter.start({
  productName: 'TcpkCrashFixture',
  companyName: 'Example',
  submitURL: 'https://crash.example.com/submit',
  uploadToServer: true,
  extra: { channel: 'stable', userId: 'abc123' }
})
'@
}
AfterAll {
    if ($script:root) { Remove-Item -LiteralPath $script:root -Recurse -Force -ErrorAction SilentlyContinue }
}

Describe 'Test-TcpkCrashReporter' {
    It 'stays silent on a target with no Electron or Crashpad signal' {
        $empty = Join-Path ([System.IO.Path]::GetTempPath()) ("tcpk-crash-empty-" + [guid]::NewGuid().ToString('N').Substring(0, 6))
        New-Item -ItemType Directory -Path $empty -Force | Out-Null
        try {
            Set-Content -LiteralPath (Join-Path $empty 'readme.txt') -Value 'not an electron app'
            @(Test-TcpkCrashReporter -Path $empty).Count | Should -Be 0
        } finally { Remove-Item -LiteralPath $empty -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'detects the shipped Crashpad handler' {
        $r = @(Test-TcpkCrashReporter -Path $script:root)
        ($r | Where-Object RuleId -eq 'crashreporter.crashpad-present') | Should -Not -BeNullOrEmpty
    }

    It 'recovers the upload endpoint from crashReporter.start()' {
        $f = @(Test-TcpkCrashReporter -Path $script:root | Where-Object RuleId -eq 'crashreporter.uploads-enabled')
        $f | Should -Not -BeNullOrEmpty
        $f[0].Evidence | Should -Match 'crash\.example\.com'
        $f[0].Title    | Should -Match 'crash\.example\.com'
    }

    It 'flags the extra{} block that rides along with every report' {
        $f = @(Test-TcpkCrashReporter -Path $script:root | Where-Object RuleId -eq 'crashreporter.extra-params')
        $f | Should -Not -BeNullOrEmpty
    }

    It 'does not report uploads when uploadToServer is explicitly false' {
        $off = Join-Path ([System.IO.Path]::GetTempPath()) ("tcpk-crash-off-" + [guid]::NewGuid().ToString('N').Substring(0, 6))
        New-Item -ItemType Directory -Path $off -Force | Out-Null
        try {
            Set-Content -LiteralPath (Join-Path $off 'crashpad_handler.exe') -Value 'MZ stub' -Encoding ASCII
            Set-Content -LiteralPath (Join-Path $off 'main.js') -Encoding ASCII -Value @'
crashReporter.start({ submitURL: 'https://crash.example.com/submit', uploadToServer: false })
'@
            $r = @(Test-TcpkCrashReporter -Path $off)
            ($r | Where-Object RuleId -eq 'crashreporter.uploads-enabled') | Should -BeNullOrEmpty
        } finally { Remove-Item -LiteralPath $off -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'notes when Crashpad ships but no configuration call is recoverable' {
        $bare = Join-Path ([System.IO.Path]::GetTempPath()) ("tcpk-crash-bare-" + [guid]::NewGuid().ToString('N').Substring(0, 6))
        New-Item -ItemType Directory -Path $bare -Force | Out-Null
        try {
            Set-Content -LiteralPath (Join-Path $bare 'crashpad_handler.exe') -Value 'MZ stub' -Encoding ASCII
            $r = @(Test-TcpkCrashReporter -Path $bare)
            ($r | Where-Object RuleId -eq 'crashreporter.config-not-found') | Should -Not -BeNullOrEmpty
        } finally { Remove-Item -LiteralPath $bare -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

# Guard for the trap hit while adding dllsearch.delayload-phantom: the mapping tables use
# narrow alternation regexes, so a new RuleId that does not match silently ships with no
# ATT&CK technique, no TASVS control, and a default CVSS archetype.
Describe 'crashreporter rule IDs are registered in the mapping tables' {
    It 'maps <_> to an ATT&CK technique and a TASVS control' -ForEach @(
        'crashreporter.crashpad-present'
        'crashreporter.uploads-enabled'
        'crashreporter.extra-params'
        'crashreporter.config-not-found'
        'crashreporter.dumps-present'
        'crashreporter.db-user-writable'
    ) {
        $rid = $_
        $tech = & (Get-Module TCPK) { param($r) Get-TcpkAttackTechnique -RuleId $r } $rid
        @($tech).Count | Should -BeGreaterThan 0 -Because "$rid must map to an ATT&CK technique"

        $ctl = & (Get-Module TCPK) { param($r) Get-TcpkTasvsControl -RuleId $r } $rid
        @($ctl).Count | Should -BeGreaterThan 0 -Because "$rid must map to a TASVS control"
    }
}
