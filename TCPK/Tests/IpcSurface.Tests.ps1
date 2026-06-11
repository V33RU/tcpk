#requires -Version 5.1
# G3: main-process IPC handler surface + sender validation. ipcMain.handle/on registers
# the privileged operations the renderer can call; a handler that doesn't check
# event.senderFrame is reachable from any frame. Inventory them, and flag missing checks.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
    $script:work = Join-Path ([IO.Path]::GetTempPath()) ("tcpk-ipc-" + [guid]::NewGuid().ToString('N'))

    function New-ElectronDir([string]$name, [string]$mainjs) {
        $d = Join-Path $script:work $name
        New-Item -ItemType Directory -Path $d -Force | Out-Null
        New-Item -ItemType File -Path (Join-Path $d 'ffmpeg.dll') -Force | Out-Null
        $mainjs | Set-Content -LiteralPath (Join-Path $d 'main.js') -Encoding UTF8
        return $d
    }

    $script:handlers = New-ElectronDir 'handlers' @'
const { ipcMain } = require('electron');
ipcMain.handle('do:thing', () => act());
ipcMain.on('do:other', () => act2());
'@
    $script:validated = New-ElectronDir 'validated' @'
const { ipcMain } = require('electron');
ipcMain.handle('settings:get', (event, key) => {
  if (event.senderFrame.url !== 'app://main/index.html') return null;
  return read(key);
});
'@
    $script:none = New-ElectronDir 'none' @'
const { app } = require('electron');
app.whenReady().then(() => createWindow());
'@
}

AfterAll {
    if ($script:work -and (Test-Path -LiteralPath $script:work)) {
        try { [System.IO.Directory]::Delete($script:work, $true) } catch {}
    }
}

Describe 'Test-TcpkElectron IPC handler surface (G3)' {
    It 'inventories ipcMain handlers and flags missing sender validation' {
        $r = @(Test-TcpkElectron -Path $script:handlers)
        @($r | Where-Object RuleId -eq 'electron.ipc-surface').Count            | Should -BeGreaterThan 0
        @($r | Where-Object RuleId -eq 'electron.ipc-no-sender-validation').Count | Should -BeGreaterThan 0
    }
    It 'does NOT flag missing sender validation when senderFrame is checked' {
        $r = @(Test-TcpkElectron -Path $script:validated)
        @($r | Where-Object RuleId -eq 'electron.ipc-surface').Count            | Should -BeGreaterThan 0
        @($r | Where-Object RuleId -eq 'electron.ipc-no-sender-validation').Count | Should -Be 0
    }
    It 'emits no IPC findings when there are no handlers' {
        @(Test-TcpkElectron -Path $script:none | Where-Object RuleId -like 'electron.ipc*').Count | Should -Be 0
    }
}
