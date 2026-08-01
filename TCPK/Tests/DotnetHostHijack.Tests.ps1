#requires -Version 5.1
# Pester 5: Test-TcpkDotnetHostHijack. Covers the .NET Core / 5+ host redirection vectors
# that replaced AppDomainManager injection. The file-based checks are cross-platform; the
# ACL-dependent and environment-scope checks are Windows-only and the detector degrades
# rather than failing off Windows.

BeforeDiscovery {
    $script:isWin = ($env:OS -eq 'Windows_NT')
}

BeforeAll {
    Import-Module "$PSScriptRoot\..\TCPK.psd1" -Force

    $script:root = Join-Path ([System.IO.Path]::GetTempPath()) ("tcpk-dnh-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
    New-Item -ItemType Directory -Path $script:root -Force | Out-Null

    # A .NET-shaped target: the presence of runtimeconfig/deps files is the gate the
    # detector uses to decide the target is managed at all.
    Set-Content -LiteralPath (Join-Path $script:root 'App.deps.json') -Encoding ASCII `
        -Value '{ "runtimeTarget": { "name": ".NETCoreApp,Version=v8.0" }, "targets": {} }'
    Set-Content -LiteralPath (Join-Path $script:root 'App.runtimeconfig.json') -Encoding ASCII -Value @'
{
  "runtimeOptions": {
    "tfm": "net8.0",
    "additionalProbingPaths": [ "probe-here" ],
    "framework": { "name": "Microsoft.NETCore.App", "version": "8.0.0" }
  }
}
'@
    New-Item -ItemType Directory -Path (Join-Path $script:root 'probe-here') -Force | Out-Null
}
AfterAll {
    if ($script:root) { Remove-Item -LiteralPath $script:root -Recurse -Force -ErrorAction SilentlyContinue }
}

Describe 'Test-TcpkDotnetHostHijack' {
    It 'stays silent on a target that is not managed' {
        $native = Join-Path ([System.IO.Path]::GetTempPath()) ("tcpk-dnh-native-" + [guid]::NewGuid().ToString('N').Substring(0, 6))
        New-Item -ItemType Directory -Path $native -Force | Out-Null
        try {
            Set-Content -LiteralPath (Join-Path $native 'readme.txt') -Value 'no managed app here'
            @(Test-TcpkDotnetHostHijack -Path $native).Count | Should -Be 0
        } finally { Remove-Item -LiteralPath $native -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'runs without throwing on a managed target' {
        { Test-TcpkDotnetHostHijack -Path $script:root } | Should -Not -Throw
    }

    It 'flags a shipped launcher that sets a .NET host variable' {
        $lp = Join-Path $script:root 'run.cmd'
        try {
            Set-Content -LiteralPath $lp -Encoding ASCII -Value @'
@echo off
set CORECLR_ENABLE_PROFILING=1
set CORECLR_PROFILER={cf0d821e-299b-5307-a3d8-b283c03916db}
App.exe
'@
            $f = @(Test-TcpkDotnetHostHijack -Path $script:root |
                Where-Object RuleId -eq 'dotnethost.launcher-sets-host-var')
            $f | Should -Not -BeNullOrEmpty
            $f[0].Evidence | Should -Match 'CORECLR'
        } finally { Remove-Item -LiteralPath $lp -Force -ErrorAction SilentlyContinue }
    }

    It 'flags a PowerShell launcher using the $env: form' {
        $lp = Join-Path $script:root 'run.ps1'
        try {
            Set-Content -LiteralPath $lp -Encoding ASCII -Value '$env:DOTNET_STARTUP_HOOKS = "C:\temp\hook.dll"'
            $f = @(Test-TcpkDotnetHostHijack -Path $script:root |
                Where-Object RuleId -eq 'dotnethost.launcher-sets-host-var')
            $f | Should -Not -BeNullOrEmpty
        } finally { Remove-Item -LiteralPath $lp -Force -ErrorAction SilentlyContinue }
    }

    It 'does not flag a launcher that sets unrelated variables' {
        $lp = Join-Path $script:root 'benign.cmd'
        try {
            Set-Content -LiteralPath $lp -Encoding ASCII -Value "@echo off`r`nset APP_LOG_LEVEL=debug`r`nApp.exe"
            $f = @(Test-TcpkDotnetHostHijack -Path $script:root |
                Where-Object { $_.RuleId -eq 'dotnethost.launcher-sets-host-var' -and $_.File -like '*benign.cmd' })
            $f | Should -BeNullOrEmpty
        } finally { Remove-Item -LiteralPath $lp -Force -ErrorAction SilentlyContinue }
    }
}

# Same guard as the crashreporter suite: these tables use narrow alternation regexes, so a
# new rule id that does not match ships silently with no ATT&CK technique, no TASVS control
# and a default CVSS archetype.
Describe 'dotnethost rule IDs are registered in the mapping tables' {
    It 'maps <_> to an ATT&CK technique and a TASVS control' -ForEach @(
        'dotnethost.runtimeconfig-writable'
        'dotnethost.probing-path-writable'
        'dotnethost.deps-writable'
        'dotnethost.launcher-sets-host-var'
        'dotnethost.bundle-extract-writable'
        'dotnethost.profiler-configured'
        'dotnethost.startup-hook-configured'
    ) {
        $rid = $_
        $tech = & (Get-Module TCPK) { param($r) Get-TcpkAttackTechnique -RuleId $r } $rid
        @($tech).Count | Should -BeGreaterThan 0 -Because "$rid must map to an ATT&CK technique"

        $ctl = & (Get-Module TCPK) { param($r) Get-TcpkTasvsControl -RuleId $r } $rid
        @($ctl).Count | Should -BeGreaterThan 0 -Because "$rid must map to a TASVS control"
    }

    It 'maps the profiler rule specifically to T1574.012' {
        $tech = & (Get-Module TCPK) { Get-TcpkAttackTechnique -RuleId 'dotnethost.profiler-configured' }
        ($tech -join ' ') | Should -Match 'T1574\.012'
    }
}
