#requires -Version 5.1
# -LaunchTarget launch-and-observe helpers: resolve the target's main exe, launch it
# benignly (minimized) so the live-process checks have a process, and stop it after.
# The launch/stop tests are Windows-only and use a short-lived benign batch process.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
    $script:work = Join-Path ([IO.Path]::GetTempPath()) ("tcpk-launch-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:work -Force | Out-Null
}
AfterAll {
    if ($script:work -and (Test-Path -LiteralPath $script:work)) { try { [System.IO.Directory]::Delete($script:work, $true) } catch {} }
}

Describe 'Get-TcpkMainExePath' {
    It 'picks the largest non-helper .exe under the target' {
        [IO.File]::WriteAllBytes((Join-Path $script:work 'setup.exe'), (New-Object byte[] 10))
        [IO.File]::WriteAllBytes((Join-Path $script:work 'app.exe'),   (New-Object byte[] 4096))
        $r = InModuleScope TCPK -Parameters @{ d = $script:work } { param($d) Get-TcpkMainExePath -Dir $d }
        $r | Should -Match 'app\.exe$'
    }
}

Describe 'Start/Stop-TcpkTargetProcess' {
    It 'launches a benign process and then stops it' -Skip:($IsWindows -eq $false) {
        $bat = Join-Path $script:work 'sleeper.cmd'
        '@ping -n 6 127.0.0.1 >nul' | Set-Content -LiteralPath $bat -Encoding Ascii
        $proc = InModuleScope TCPK -Parameters @{ b = $bat } { param($b) Start-TcpkTargetProcess -ExePath $b -WaitSec 1 }
        $proc | Should -Not -BeNullOrEmpty
        $proc.HasExited | Should -BeFalse
        InModuleScope TCPK -Parameters @{ p = $proc } { param($p) Stop-TcpkTargetProcess -Proc $p }
        Start-Sleep -Milliseconds 800
        $proc.HasExited | Should -BeTrue
    }

    It 'returns null for a path that does not exist' {
        $r = InModuleScope TCPK { Start-TcpkTargetProcess -ExePath 'C:\nope\does-not-exist-xyz.exe' -WaitSec 1 }
        $r | Should -BeNullOrEmpty
    }
}
