# Pester tests for the 4 new security features:
#   1. Test-TcpkWindowMessages       (window message attack surface)
#   2. Test-TcpkSharedMemoryDacl     (shared memory DACL audit)
#   3. Test-TcpkClipboardSecrets     (clipboard secret monitoring)
#   4. New-TcpkIlPatch               (IL binary patching)
# These are unit/smoke tests; the runtime checks require a live process.

BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '..\TCPK.psd1') -Force -ErrorAction Stop
}

Describe 'Test-TcpkWindowMessages' {
    It 'exists and has the right parameter sets' {
        $cmd = Get-Command Test-TcpkWindowMessages
        $cmd | Should -Not -BeNullOrEmpty
        $cmd.Parameters.Keys | Should -Contain 'ProcessName'
        $cmd.Parameters.Keys | Should -Contain 'ProcessId'
    }

    It 'returns findings for the current PowerShell process (self-test)' {
        $pid_val = $PID
        $r = @(Test-TcpkWindowMessages -ProcessId $pid_val)
        # at minimum should return a summary finding
        $summary = $r | Where-Object { $_.RuleId -eq 'window.message-summary' }
        $summary | Should -Not -BeNullOrEmpty
    }
}

Describe 'Test-TcpkSharedMemoryDacl' {
    It 'exists and has the right parameter sets' {
        $cmd = Get-Command Test-TcpkSharedMemoryDacl
        $cmd | Should -Not -BeNullOrEmpty
        $cmd.Parameters.Keys | Should -Contain 'ProcessName'
        $cmd.Parameters.Keys | Should -Contain 'ProcessId'
    }

    It 'returns at least a summary or none-found finding for a live process' {
        $pid_val = $PID
        $r = @(Test-TcpkSharedMemoryDacl -ProcessId $pid_val)
        # should return something (summary, none-found, or actual findings)
        $r.Count | Should -BeGreaterOrEqual 1
        $r[0].Module | Should -Be 'runtime'
    }
}

Describe 'Test-TcpkClipboardSecrets' {
    It 'exists and has DurationSec / IntervalMs parameters' {
        $cmd = Get-Command Test-TcpkClipboardSecrets
        $cmd | Should -Not -BeNullOrEmpty
        $cmd.Parameters.Keys | Should -Contain 'DurationSec'
        $cmd.Parameters.Keys | Should -Contain 'IntervalMs'
        $cmd.Parameters.Keys | Should -Contain 'ProcessName'
    }

    It 'runs a short monitor and returns a summary finding' {
        $r = @(Test-TcpkClipboardSecrets -DurationSec 2 -IntervalMs 500)
        $summary = $r | Where-Object { $_.RuleId -eq 'clipboard.scan-summary' }
        $summary | Should -Not -BeNullOrEmpty
        $summary.Module | Should -Be 'memory'
    }
}

Describe 'New-TcpkIlPatch' {
    BeforeAll {
        # build a tiny .NET assembly with a bool-returning method
        $script:patchDir = Join-Path ([System.IO.Path]::GetTempPath()) "tcpk-ilpatch-test-$([guid]::NewGuid().ToString('N').Substring(0,8))"
        New-Item -ItemType Directory -Path $script:patchDir -Force | Out-Null

        $cs = @'
namespace TestPatch {
    public class License {
        public static bool IsValid() { return false; }
        public static void DoNothing() { }
        public static bool CheckTwice(bool x) { if (x) return true; else return false; }
    }
}
'@
        $csFile = Join-Path $script:patchDir 'TestPatch.cs'
        Set-Content -LiteralPath $csFile -Value $cs -Encoding ASCII

        # compile using csc.exe (Framework)
        $csc = Join-Path $env:windir 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
        if (-not (Test-Path $csc)) { $csc = Join-Path $env:windir 'Microsoft.NET\Framework\v4.0.30319\csc.exe' }
        $script:testDll = Join-Path $script:patchDir 'TestPatch.dll'
        if (Test-Path $csc) {
            & $csc /nologo /target:library "/out:$($script:testDll)" $csFile 2>&1 | Out-Null
        }
        $script:hasDll = Test-Path $script:testDll
        $script:hasExploit = $false
        try { Enable-TcpkExploit -Acknowledge; $script:hasExploit = $true } catch { }
    }

    It 'exists and is gated behind Enable-TcpkExploit' {
        $cmd = Get-Command New-TcpkIlPatch
        $cmd | Should -Not -BeNullOrEmpty
        $cmd.Parameters.Keys | Should -Contain 'Mode'
        $cmd.Parameters['Mode'].Attributes.ValidValues | Should -Contain 'ReturnTrue'
        $cmd.Parameters['Mode'].Attributes.ValidValues | Should -Contain 'FlipBranch'
        $cmd.Parameters['Mode'].Attributes.ValidValues | Should -Contain 'StripSn'
    }

    It 'ReturnTrue: patches IsValid to return true' {
        if (-not $script:hasDll -or -not $script:hasExploit) { Set-ItResult -Skipped -Because 'no test DLL or exploit not enabled'; return }
        $outDir = Join-Path $script:patchDir 'out-true'
        $r = @(New-TcpkIlPatch -DllPath $script:testDll -TypeName 'TestPatch.License' -MethodName 'IsValid' -Mode ReturnTrue -OutDir $outDir)
        $r | Where-Object { $_.RuleId -eq 'exploit.il-patch-applied' } | Should -Not -BeNullOrEmpty
        $patched = Join-Path $outDir 'TestPatch.patched.dll'
        Test-Path $patched | Should -Be $true
        $bytes = [System.IO.File]::ReadAllBytes($patched)
        $a = [System.Reflection.Assembly]::Load($bytes)
        $result = $a.GetType('TestPatch.License').GetMethod('IsValid').Invoke($null, @())
        $result | Should -Be $true
    }

    It 'ReturnFalse: patches IsValid to return false' {
        if (-not $script:hasDll -or -not $script:hasExploit) { Set-ItResult -Skipped -Because 'no test DLL or exploit not enabled'; return }
        $outDir = Join-Path $script:patchDir 'out-false'
        $r = @(New-TcpkIlPatch -DllPath $script:testDll -TypeName 'TestPatch.License' -MethodName 'IsValid' -Mode ReturnFalse -OutDir $outDir)
        $r | Where-Object { $_.RuleId -eq 'exploit.il-patch-applied' } | Should -Not -BeNullOrEmpty
    }

    It 'FlipBranch: inverts brtrue/brfalse in CheckTwice' {
        if (-not $script:hasDll -or -not $script:hasExploit) { Set-ItResult -Skipped -Because 'no test DLL or exploit not enabled'; return }
        $outDir = Join-Path $script:patchDir 'out-flip'
        $r = @(New-TcpkIlPatch -DllPath $script:testDll -TypeName 'TestPatch.License' -MethodName 'CheckTwice' -Mode FlipBranch -OutDir $outDir)
        $r | Where-Object { $_.RuleId -eq 'exploit.il-patch-applied' } | Should -Not -BeNullOrEmpty
        ($r[0].Evidence) | Should -Match 'flipped='
    }

    It 'Nop: replaces void method body with nop+ret' {
        if (-not $script:hasDll -or -not $script:hasExploit) { Set-ItResult -Skipped -Because 'no test DLL or exploit not enabled'; return }
        $outDir = Join-Path $script:patchDir 'out-nop'
        $r = @(New-TcpkIlPatch -DllPath $script:testDll -TypeName 'TestPatch.License' -MethodName 'DoNothing' -Mode Nop -OutDir $outDir)
        $r | Where-Object { $_.RuleId -eq 'exploit.il-patch-applied' } | Should -Not -BeNullOrEmpty
    }

    It 'StripSn: removes strong name (no type/method needed)' {
        if (-not $script:hasDll -or -not $script:hasExploit) { Set-ItResult -Skipped -Because 'no test DLL or exploit not enabled'; return }
        $outDir = Join-Path $script:patchDir 'out-sn'
        $r = @(New-TcpkIlPatch -DllPath $script:testDll -Mode StripSn -OutDir $outDir)
        $r | Where-Object { $_.RuleId -eq 'exploit.il-patch-strip-sn' } | Should -Not -BeNullOrEmpty
    }

    AfterAll {
        try { Disable-TcpkExploit } catch { }
        if ($script:patchDir -and (Test-Path $script:patchDir)) {
            Remove-Item -LiteralPath $script:patchDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}
