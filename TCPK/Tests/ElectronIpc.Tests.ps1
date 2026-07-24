#requires -Version 5.1
# Electron IPC handler-to-sink correlation + webpack/bundled-main scanning. The
# highest-impact Electron IPC bug is a handler that feeds its renderer-supplied
# argument into exec/shell/eval/fs. We also verify the scanner now reaches a
# bundled main file (main.bundle.js), which the old exact-name allow-list skipped.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force

    $script:work = Join-Path ([IO.Path]::GetTempPath()) ("tcpk-eipc-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:work -Force | Out-Null
    # marker so the target is recognised as Electron (no asar -> runtime-version path skips)
    Set-Content -LiteralPath (Join-Path $script:work 'electron.exe') -Value 'stub' -Encoding Ascii
    # webpack-bundled main process (old allow-list only matched main.js/preload.js/...)
    $main = @'
const { ipcMain, shell } = require('electron');
ipcMain.handle('run-cmd', (e, cmd) => { const cp = require('child_process'); return cp.execSync(cmd); });
ipcMain.on('open-path', function(event, p){ shell.openPath(p); });
ipcMain.handle('do-log', (e) => { require('child_process').execSync('echo hi'); });
ipcMain.handle('echo', (e, msg) => String(msg).toUpperCase());
'@
    Set-Content -LiteralPath (Join-Path $script:work 'main.bundle.js') -Value $main -Encoding Ascii
    $script:findings = @(Test-TcpkElectron -Path $script:work)
    $script:sinks = @($script:findings | Where-Object { $_.RuleId -eq 'electron.ipc-handler-sink' })
}

AfterAll {
    if ($script:work -and (Test-Path -LiteralPath $script:work)) {
        try { [System.IO.Directory]::Delete($script:work, $true) } catch {}
    }
}

Describe 'Electron IPC handler-to-sink correlation' {
    It 'scans a webpack-bundled main file (main.bundle.js), not just main.js' {
        ($script:findings | Where-Object { $_.File -match 'main\.bundle\.js' }) | Should -Not -BeNullOrEmpty
    }

    It 'flags a command-execution handler fed by a renderer arg as CRITICAL / Confirmed' {
        $f = $script:sinks | Where-Object { $_.Title -match "'run-cmd'" }
        $f | Should -Not -BeNullOrEmpty
        $f.Severity   | Should -Be 'CRITICAL'
        $f.Confidence | Should -Be 'Confirmed'
        $f.Evidence   | Should -Match 'execSync'
    }

    It 'flags a shell.openPath handler fed by a renderer arg as HIGH / Confirmed' {
        $f = $script:sinks | Where-Object { $_.Title -match "'open-path'" }
        $f | Should -Not -BeNullOrEmpty
        $f.Severity   | Should -Be 'HIGH'
        $f.Confidence | Should -Be 'Confirmed'
    }

    It 'flags a sink reachable from a handler with no renderer arg as Inferred (not Confirmed)' {
        $f = $script:sinks | Where-Object { $_.Title -match "'do-log'" }
        $f | Should -Not -BeNullOrEmpty
        $f.Confidence | Should -Be 'Inferred'
        $f.Severity   | Should -Be 'HIGH'   # command-exec sink, arg flow not proven
    }

    It 'does NOT flag a handler with no dangerous sink (precision)' {
        ($script:sinks | Where-Object { $_.Title -match "'echo'" }) | Should -BeNullOrEmpty
    }
}
