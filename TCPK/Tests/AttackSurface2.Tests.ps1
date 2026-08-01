BeforeAll {
    Import-Module "$PSScriptRoot\..\TCPK.psd1" -Force
}

# -Skip is evaluated at DISCOVERY time, so the platform probe has to run here.
# The calibration below reads live KnownDLLs and System32, both Windows-only.
BeforeDiscovery {
    $script:isWin = ($env:OS -eq 'Windows_NT')
}

Describe 'PhantomDlls' {
    It 'runs without error on a directory with a PE' {
        $dir = Join-Path $env:TEMP "tcpk-phantom-$PID"
        New-Item $dir -ItemType Directory -Force | Out-Null
        try {
            Copy-Item "$env:SystemRoot\System32\kernel32.dll" "$dir\testapp.exe" -Force
            { Test-TcpkPhantomDlls -Path $dir } | Should -Not -Throw
        } finally { Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'returns nothing for an empty directory' {
        $dir = Join-Path $env:TEMP "tcpk-phantom-empty-$PID"
        New-Item $dir -ItemType Directory -Force | Out-Null
        try {
            $r = @(Test-TcpkPhantomDlls -Path $dir)
        } finally { Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue }
        $r.Count | Should -Be 0
    }

    It 'emits phantom-dll rule ID when findings exist' {
        $dir = Join-Path $env:TEMP "tcpk-phantom-rid-$PID"
        New-Item $dir -ItemType Directory -Force | Out-Null
        try {
            Copy-Item "$env:SystemRoot\System32\kernel32.dll" "$dir\testapp.exe" -Force
            $r = @(Test-TcpkPhantomDlls -Path $dir)
            # Two rule IDs are valid here: the normal import table and the
            # delay-import table (data directory 13), which is scanned too.
            foreach ($f in $r) {
                $f.RuleId | Should -BeIn @('dllsearch.phantom-dll', 'dllsearch.delayload-phantom')
            }
        } finally { Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

Describe 'PE delay-import parsing' -Skip:(-not $script:isWin) {
    It 'always exposes DelayImports so downstream detectors can enumerate it safely' {
        InModuleScope TCPK {
            $info = Read-TcpkPe -Path (Join-Path $env:SystemRoot 'System32\kernel32.dll')
            $info | Should -Not -BeNullOrEmpty
            $info.PSObject.Properties.Name | Should -Contain 'DelayImports'
        }
    }

    It 'actually parses delay-import descriptors (data directory 13)' {
        InModuleScope TCPK {
            # Delay-loading is pervasive in System32, but WHICH binary uses it varies
            # by Windows build, so require only that at least one of several does.
            # A parser that silently returns nothing would fail this.
            $found = $false
            foreach ($n in @('shell32.dll', 'comdlg32.dll', 'propsys.dll', 'ole32.dll',
                             'windows.storage.dll', 'shcore.dll', 'urlmon.dll')) {
                $p = Join-Path $env:SystemRoot "System32\$n"
                if (-not (Test-Path -LiteralPath $p)) { continue }
                $info = Read-TcpkPe -Path $p
                if ($info -and @($info.DelayImports).Count -gt 0) { $found = $true; break }
            }
            $found | Should -BeTrue -Because 'at least one common System32 binary delay-loads something'
        }
    }

    It 'returns delay-import names as lowercase dll file names' {
        InModuleScope TCPK {
            foreach ($n in @('shell32.dll', 'comdlg32.dll', 'propsys.dll', 'ole32.dll')) {
                $p = Join-Path $env:SystemRoot "System32\$n"
                if (-not (Test-Path -LiteralPath $p)) { continue }
                $d = @((Read-TcpkPe -Path $p).DelayImports)
                if (-not $d.Count) { continue }
                foreach ($x in $d) {
                    $x | Should -Match '^[a-z0-9_\-\.]+$'
                    $x | Should -Match '\.(dll|drv|ocx|exe)$'
                }
                break
            }
        }
    }
}

Describe 'PhantomDlls calibration' -Skip:(-not $script:isWin) {
    # Regression guard for the false-positive class the static 76-name allowlist
    # could not cover: a system binary imports plenty of DLLs that are NOT on the
    # allowlist, and before calibration every one of them was reported HIGH.
    # All of them resolve in System32, so the correct result is zero findings.
    It 'suppresses imports that resolve in System32 rather than reporting them HIGH' {
        $dir = Join-Path $env:TEMP "tcpk-phantom-cal-$PID"
        New-Item $dir -ItemType Directory -Force | Out-Null
        try {
            Copy-Item "$env:SystemRoot\System32\advapi32.dll" "$dir\testapp.exe" -Force
            $r = @(Test-TcpkPhantomDlls -Path $dir | Where-Object {
                $_.RuleId -in @('dllsearch.phantom-dll', 'dllsearch.delayload-phantom') })
            $r.Count | Should -Be 0
        } finally { Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'records the calibration inputs in the evidence of anything it does emit' {
        $dir = Join-Path $env:TEMP "tcpk-phantom-ev-$PID"
        New-Item $dir -ItemType Directory -Force | Out-Null
        try {
            Copy-Item "$env:SystemRoot\System32\kernel32.dll" "$dir\testapp.exe" -Force
            foreach ($f in @(Test-TcpkPhantomDlls -Path $dir)) {
                $f.Evidence | Should -Match 'root writable='
                $f.Severity | Should -BeIn @('HIGH', 'MEDIUM')
            }
        } finally { Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

Describe 'DllSideload' {
    It 'runs without error on a directory with a PE' {
        $dir = Join-Path $env:TEMP "tcpk-sideload-$PID"
        New-Item $dir -ItemType Directory -Force | Out-Null
        try {
            Copy-Item "$env:SystemRoot\System32\cmd.exe" "$dir\testapp.exe" -Force
            { Test-TcpkDllSideload -Path $dir } | Should -Not -Throw
        } finally { Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'emits sideload-candidate rule ID when findings exist' {
        $dir = Join-Path $env:TEMP "tcpk-sideload-rid-$PID"
        New-Item $dir -ItemType Directory -Force | Out-Null
        try {
            Copy-Item "$env:SystemRoot\System32\cmd.exe" "$dir\testapp.exe" -Force
            $r = @(Test-TcpkDllSideload -Path $dir)
            foreach ($f in $r) {
                $f.RuleId | Should -Be 'dllsearch.sideload-candidate'
            }
        } finally { Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'does not flag sideload targets already shipped in app dir' {
        $dir = Join-Path $env:TEMP "tcpk-sideload-ship-$PID"
        New-Item $dir -ItemType Directory -Force | Out-Null
        try {
            Copy-Item "$env:SystemRoot\System32\cmd.exe" "$dir\testapp.exe" -Force
            $baseline = @(Test-TcpkDllSideload -Path $dir)
            if ($baseline.Count -eq 0) {
                Set-ItResult -Skipped -Because 'cmd.exe imports no known sideload targets on this OS build'
                return
            }
            foreach ($f in $baseline) {
                $dll = $f.Title -replace '.*:\s*(\S+\.dll).*','$1'
                if ($dll -match '\.dll$') {
                    New-Item "$dir\$dll" -ItemType File -Force | Out-Null
                }
            }
            $after = @(Test-TcpkDllSideload -Path $dir)
            $after.Count | Should -BeLessThan $baseline.Count -Because 'shipped DLLs should be suppressed'
        } finally { Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'returns nothing for an empty directory' {
        $dir = Join-Path $env:TEMP "tcpk-sideload-empty-$PID"
        New-Item $dir -ItemType Directory -Force | Out-Null
        try {
            $r = @(Test-TcpkDllSideload -Path $dir)
        } finally { Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue }
        $r.Count | Should -Be 0
    }
}

Describe 'WerExposure' {
    It 'runs without error on a stub directory' {
        $dir = Join-Path $env:TEMP "tcpk-wer-$PID"
        New-Item $dir -ItemType Directory -Force | Out-Null
        try {
            { Test-TcpkWerExposure -Path $dir } | Should -Not -Throw
        } finally { Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

Describe 'WritablePath' {
    It 'runs without error' {
        $dir = Join-Path $env:TEMP "tcpk-path-$PID"
        New-Item $dir -ItemType Directory -Force | Out-Null
        try {
            { Test-TcpkWritablePath -Path $dir } | Should -Not -Throw
        } finally { Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

Describe 'ComHijack' {
    It 'runs without error on a stub directory' {
        $dir = Join-Path $env:TEMP "tcpk-comhijack-$PID"
        New-Item $dir -ItemType Directory -Force | Out-Null
        try {
            { Test-TcpkComHijack -Path $dir } | Should -Not -Throw
        } finally { Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'scans config files for CLSID references without error' {
        $dir = Join-Path $env:TEMP "tcpk-comhijack2-$PID"
        New-Item $dir -ItemType Directory -Force | Out-Null
        try {
            $clsid = '{13709620-C279-11CE-A49E-444553540000}'
            Set-Content "$dir\app.config" "<configuration><com clsid='$clsid'/></configuration>" -Encoding ASCII
            { Test-TcpkComHijack -Path $dir } | Should -Not -Throw
        } finally { Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

Describe 'DiagConfig' {
    It 'flags a shipped NLog config with verbose level' {
        $dir = Join-Path $env:TEMP "tcpk-diag-$PID"
        New-Item $dir -ItemType Directory -Force | Out-Null
        try {
            $nlog = @'
<?xml version="1.0" encoding="utf-8" ?>
<nlog>
  <rules>
    <logger name="*" minlevel="Trace" writeTo="file" />
  </rules>
  <targets>
    <target name="file" type="File" fileName="C:\temp\app.log" />
  </targets>
</nlog>
'@
            Set-Content "$dir\nlog.config" $nlog -Encoding ASCII
            $r = @(Test-TcpkDiagConfig -Path $dir)
            $r.Count | Should -BeGreaterOrEqual 2 -Because 'should flag config-shipped + verbose-level'
            $shipped = $r | Where-Object { $_.RuleId -eq 'diag.config-shipped' }
            $shipped | Should -Not -BeNullOrEmpty
            $verbose = $r | Where-Object { $_.RuleId -eq 'diag.verbose-level' }
            $verbose | Should -Not -BeNullOrEmpty
            $verbose.Severity | Should -Be 'MEDIUM'
        } finally { Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'flags insecure log path in temp directory' {
        $dir = Join-Path $env:TEMP "tcpk-diag2-$PID"
        New-Item $dir -ItemType Directory -Force | Out-Null
        try {
            $nlog = @'
<?xml version="1.0" encoding="utf-8" ?>
<nlog>
  <targets>
    <target name="file" type="File" fileName="C:\temp\debug\app.log" />
  </targets>
</nlog>
'@
            Set-Content "$dir\nlog.config" $nlog -Encoding ASCII
            $r = @(Test-TcpkDiagConfig -Path $dir)
            $insecure = $r | Where-Object { $_.RuleId -eq 'diag.insecure-log-path' }
            $insecure | Should -Not -BeNullOrEmpty
        } finally { Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'flags SMTP target in logging config' {
        $dir = Join-Path $env:TEMP "tcpk-diag-smtp-$PID"
        New-Item $dir -ItemType Directory -Force | Out-Null
        try {
            $nlog = @'
<?xml version="1.0" encoding="utf-8" ?>
<nlog>
  <targets>
    <target name="mail" type="Mail" smtpServer="mail.internal.corp" />
  </targets>
</nlog>
'@
            Set-Content "$dir\nlog.config" $nlog -Encoding ASCII
            $r = @(Test-TcpkDiagConfig -Path $dir)
            $smtp = $r | Where-Object { $_.RuleId -eq 'diag.smtp-target' }
            $smtp | Should -Not -BeNullOrEmpty
        } finally { Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'returns nothing for a directory without diagnostic configs' {
        $dir = Join-Path $env:TEMP "tcpk-diag-empty-$PID"
        New-Item $dir -ItemType Directory -Force | Out-Null
        try {
            Set-Content "$dir\readme.txt" 'hello' -Encoding ASCII
            $r = @(Test-TcpkDiagConfig -Path $dir)
        } finally { Remove-Item $dir -Recurse -Force -ErrorAction SilentlyContinue }
        $r.Count | Should -Be 0
    }
}

Describe 'ATT&CK mappings for new attack surface detections' {
    It 'maps phantom DLL to T1574.001' {
        $t = & (Get-Module TCPK) { Get-TcpkAttackTechnique -RuleId 'dllsearch.phantom-dll' }
        $t | Should -Contain 'T1574.001 DLL'
    }
    It 'maps sideload to T1574.002' {
        $t = & (Get-Module TCPK) { Get-TcpkAttackTechnique -RuleId 'dllsearch.sideload-candidate' }
        $t | Should -Contain 'T1574.002 DLL Side-Loading'
    }
    It 'maps COM hijack to T1546.015' {
        $t = & (Get-Module TCPK) { Get-TcpkAttackTechnique -RuleId 'comhijack.per-user-plantable' }
        $t | Should -Contain 'T1546.015 Component Object Model Hijacking'
    }
    It 'maps WER to T1005' {
        $t = & (Get-Module TCPK) { Get-TcpkAttackTechnique -RuleId 'wer.dump-folder-readable' }
        $t | Should -Contain 'T1005 Data from Local System'
    }
    It 'maps writable PATH to T1574.007' {
        $t = & (Get-Module TCPK) { Get-TcpkAttackTechnique -RuleId 'path.writable-entry' }
        $t | Should -Contain 'T1574.007 Path Interception by PATH Environment Variable'
    }
    It 'maps diag config to T1005' {
        $t = & (Get-Module TCPK) { Get-TcpkAttackTechnique -RuleId 'diag.verbose-level' }
        $t | Should -Contain 'T1005 Data from Local System'
    }
}

Describe 'TASVS mappings for new attack surface detections' {
    It 'maps phantom DLL to TASVS-PLATFORM' {
        $t = & (Get-Module TCPK) { Get-TcpkTasvsControl -RuleId 'dllsearch.phantom-dll' }
        ($t -join ';') | Should -Match 'TASVS-PLATFORM'
    }
    It 'maps COM hijack to TASVS-PLATFORM' {
        $t = & (Get-Module TCPK) { Get-TcpkTasvsControl -RuleId 'comhijack.per-user-plantable' }
        ($t -join ';') | Should -Match 'TASVS-PLATFORM'
    }
    It 'maps WER to TASVS-STORAGE' {
        $t = & (Get-Module TCPK) { Get-TcpkTasvsControl -RuleId 'wer.dump-folder-readable' }
        ($t -join ';') | Should -Match 'TASVS-STORAGE'
    }
    It 'maps diag to TASVS-CODE' {
        $t = & (Get-Module TCPK) { Get-TcpkTasvsControl -RuleId 'diag.config-shipped' }
        ($t -join ';') | Should -Match 'TASVS-CODE'
    }
}
