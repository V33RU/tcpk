#requires -Version 5.1
# G7: deep-link / file-association / argv session-override surface. Custom URI schemes,
# file-type open handlers and command-line credential/host overrides are how outside
# input drives a desktop app. Each is detected; a clean app trips none of them.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
    $script:work = Join-Path ([IO.Path]::GetTempPath()) ("tcpk-deeplink-" + [guid]::NewGuid().ToString('N'))

    function New-ElectronDir([string]$name, [string]$mainjs) {
        $d = Join-Path $script:work $name
        New-Item -ItemType Directory -Path $d -Force | Out-Null
        New-Item -ItemType File -Path (Join-Path $d 'ffmpeg.dll') -Force | Out-Null
        $mainjs | Set-Content -LiteralPath (Join-Path $d 'main.js') -Encoding UTF8
        return $d
    }

    $script:proto = New-ElectronDir 'proto' @'
const { app } = require('electron');
app.setAsDefaultProtocolClient('myapp');
'@
    $script:argv = New-ElectronDir 'argv' @'
const argv = process.argv.slice(1);
const host = pick(argv, '--host');
const token = pick(argv, '--token');
'@
    $script:assoc = New-ElectronDir 'assoc' @'
const entries = [
  ['HKCU\\Software\\Classes\\FooFile\\shell\\open\\command', '/ve', '/d', openCmd],
];
'@
    $script:clean = New-ElectronDir 'clean' @'
const { BrowserWindow } = require('electron');
const w = new BrowserWindow({ webPreferences: { contextIsolation: true, sandbox: true } });
'@
}

AfterAll {
    if ($script:work -and (Test-Path -LiteralPath $script:work)) {
        try { [System.IO.Directory]::Delete($script:work, $true) } catch {}
    }
}

Describe 'Test-TcpkElectron deep-link / argv surface (G7)' {
    It 'flags a custom URI scheme registration' {
        @(Test-TcpkElectron -Path $script:proto | Where-Object RuleId -eq 'electron.custom-protocol').Count | Should -BeGreaterThan 0
    }
    It 'flags command-line session/credential overrides as MEDIUM' {
        $f = @(Test-TcpkElectron -Path $script:argv | Where-Object RuleId -eq 'electron.argv-session-override')
        $f.Count | Should -BeGreaterThan 0
        $f[0].Severity | Should -Be 'MEDIUM'
    }
    It 'flags a file-type open-command handler' {
        @(Test-TcpkElectron -Path $script:assoc | Where-Object RuleId -eq 'electron.file-assoc-handler').Count | Should -BeGreaterThan 0
    }
    It 'flags none of the G7 surfaces on a clean app' {
        $r = @(Test-TcpkElectron -Path $script:clean | Where-Object { $_.RuleId -in 'electron.custom-protocol','electron.argv-session-override','electron.file-assoc-handler' })
        $r.Count | Should -Be 0
    }
}
