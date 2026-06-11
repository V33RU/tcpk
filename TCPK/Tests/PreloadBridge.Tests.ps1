#requires -Version 5.1
# G2: preload / contextBridge exposure analysis. With contextIsolation on, the real
# renderer<->main trust boundary is what the preload exposes. A secure preload (narrow
# named functions bound to FIXED channels) yields only an INFO inventory; over-broad
# shapes (raw ipcRenderer, caller-supplied channel passthrough, Node primitives) are flagged.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
    $script:work = Join-Path ([IO.Path]::GetTempPath()) ("tcpk-bridge-" + [guid]::NewGuid().ToString('N'))

    function New-ElectronDir([string]$name, [string]$preload) {
        $d = Join-Path $script:work $name
        New-Item -ItemType Directory -Path $d -Force | Out-Null
        New-Item -ItemType File -Path (Join-Path $d 'ffmpeg.dll') -Force | Out-Null   # trips isElectron
        $preload | Set-Content -LiteralPath (Join-Path $d 'preload.js') -Encoding UTF8
        return $d
    }

    $script:secure  = New-ElectronDir 'secure'  @'
const { contextBridge, ipcRenderer } = require('electron');
contextBridge.exposeInMainWorld('cfg', {
  load: () => ipcRenderer.invoke('config:load'),
  save: (v) => ipcRenderer.invoke('config:save', v),
});
'@
    $script:ipc     = New-ElectronDir 'ipc'     @'
const { contextBridge, ipcRenderer } = require('electron');
contextBridge.exposeInMainWorld('ipc', ipcRenderer);
'@
    $script:generic = New-ElectronDir 'generic' @'
const { contextBridge, ipcRenderer } = require('electron');
contextBridge.exposeInMainWorld('api', {
  invoke: (channel, ...args) => ipcRenderer.invoke(channel, ...args),
});
'@
    $script:node    = New-ElectronDir 'node'    @'
const { contextBridge } = require('electron');
contextBridge.exposeInMainWorld('fsapi', require('fs'));
'@
}

AfterAll {
    if ($script:work -and (Test-Path -LiteralPath $script:work)) {
        try { [System.IO.Directory]::Delete($script:work, $true) } catch {}
    }
}

Describe 'Test-TcpkElectron contextBridge analysis (G2)' {
    It 'inventories the exposed bridge surface (INFO) and flags nothing on a secure preload' {
        $r = @(Test-TcpkElectron -Path $script:secure)
        @($r | Where-Object RuleId -eq 'electron.bridge-surface').Count | Should -BeGreaterThan 0
        @($r | Where-Object { $_.RuleId -like 'electron.bridge-exposes-*' -or $_.RuleId -eq 'electron.bridge-generic-ipc' }).Count | Should -Be 0
    }
    It 'flags a raw ipcRenderer exposure as CRITICAL' {
        $f = @(Test-TcpkElectron -Path $script:ipc | Where-Object RuleId -eq 'electron.bridge-exposes-ipcRenderer')
        $f.Count | Should -BeGreaterThan 0
        $f[0].Severity | Should -Be 'CRITICAL'
    }
    It 'flags a caller-supplied channel passthrough as HIGH' {
        $f = @(Test-TcpkElectron -Path $script:generic | Where-Object RuleId -eq 'electron.bridge-generic-ipc')
        $f.Count | Should -BeGreaterThan 0
        $f[0].Severity | Should -Be 'HIGH'
    }
    It 'flags a Node primitive exposed via the bridge as CRITICAL' {
        $f = @(Test-TcpkElectron -Path $script:node | Where-Object RuleId -eq 'electron.bridge-exposes-node')
        $f.Count | Should -BeGreaterThan 0
        $f[0].Severity | Should -Be 'CRITICAL'
    }
}
