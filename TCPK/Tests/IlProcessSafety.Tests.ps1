#requires -Version 5.1
# IL-proven thick-client process-safety: unbalanced impersonation (a client token left on the
# thread with no revert) and blanket handle inheritance (a child spawned inheriting every
# handle). Both read the shipped managed binary with Mono.Cecil; a source-string regex cannot
# tell a reverted impersonation from an unreverted one, nor bInheritHandle=TRUE from FALSE.
# Skips if Mono.Cecil is absent or the fixture cannot be compiled (Desktop/Framework only).

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
    $script:cecil = $false
    try { $script:cecil = & (Get-Module TCPK) { Test-TcpkCecilAvailable } } catch { }
    $script:desktop = ($PSVersionTable.PSEdition -eq 'Desktop')

    $script:work = Join-Path ([IO.Path]::GetTempPath()) ("tcpk-ips-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:work -Force | Out-Null

    if ($script:cecil -and $script:desktop) {
        $imp = @'
using System; using System.Runtime.InteropServices;
public class ImpBad {
  [DllImport("advapi32.dll")] static extern bool ImpersonateNamedPipeClient(IntPtr h);
  [DllImport("advapi32.dll")] static extern bool RevertToSelf();
  public void Leak(IntPtr h){ ImpersonateNamedPipeClient(h); }
  public void Balanced(IntPtr h){ try { ImpersonateNamedPipeClient(h); } finally { RevertToSelf(); } }
}
'@
        $script:impDll = Join-Path $script:work 'ImpBad.dll'
        Add-Type -TypeDefinition $imp -OutputAssembly $script:impDll -OutputType Library
        $script:iv = @(& (Get-Module TCPK) { param($d) Get-TcpkImpersonationVerdicts -DllPath $d } $script:impDll)

        $hnd = @'
using System; using System.Runtime.InteropServices;
public class HandleBad {
  [DllImport("kernel32.dll")] static extern bool SetHandleInformation(IntPtr h, uint mask, uint flags);
  [StructLayout(LayoutKind.Sequential)] struct SA { public int nLength; public IntPtr lpSD; public int bInheritHandle; }
  public void InheritOn(IntPtr h){ SetHandleInformation(h, 1u, 1u); }
  public void InheritOff(IntPtr h){ SetHandleInformation(h, 1u, 0u); }
  public void SaTrue(){ var s = new SA(); s.bInheritHandle = 1; GC.KeepAlive(s); }
  public void SaFalse(){ var s = new SA(); s.bInheritHandle = 0; GC.KeepAlive(s); }
}
'@
        $script:hndDll = Join-Path $script:work 'HandleBad.dll'
        Add-Type -TypeDefinition $hnd -OutputAssembly $script:hndDll -OutputType Library
        $script:hv = @(& (Get-Module TCPK) { param($d) Get-TcpkHandleInheritVerdicts -DllPath $d } $script:hndDll)

        $pipe = @'
using System; using System.Runtime.InteropServices;
public class PipeBad {
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode)]
  static extern IntPtr CreateNamedPipeW(string name, uint openMode, uint pipeMode, uint maxInstances, uint outBuf, uint inBuf, uint timeout, IntPtr sa);
  public void SquatMe(){ CreateNamedPipeW(@"\\.\pipe\myapp", 0x3u, 0u, 1u, 0u, 0u, 0u, IntPtr.Zero); }
  public void FirstInstance(){ CreateNamedPipeW(@"\\.\pipe\safe", 0x80003u, 0u, 1u, 0u, 0u, 0u, IntPtr.Zero); }
  public void Computed(uint extra){ CreateNamedPipeW(@"\\.\pipe\x", 0x3u | extra, 0u, 1u, 0u, 0u, 0u, IntPtr.Zero); }
}
'@
        $script:pipeDll = Join-Path $script:work 'PipeBad.dll'
        Add-Type -TypeDefinition $pipe -OutputAssembly $script:pipeDll -OutputType Library
        $script:pv = @(& (Get-Module TCPK) { param($d) Get-TcpkPipeFirstInstanceVerdicts -DllPath $d } $script:pipeDll)

        $dlldir = @'
using System; using System.Runtime.InteropServices;
public class DllDirBad {
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode)] static extern bool SetDllDirectory(string path);
  public void Relative(){ SetDllDirectory("plugins"); }
  public void Empty(){ SetDllDirectory(""); }
  public void Absolute(){ SetDllDirectory(@"C:\Program Files\App\lib"); }
}
'@
        $script:dllDirDll = Join-Path $script:work 'DllDirBad.dll'
        Add-Type -TypeDefinition $dlldir -OutputAssembly $script:dllDirDll -OutputType Library
        $script:dv = @(& (Get-Module TCPK) { param($d) Get-TcpkDllSearchWidenVerdicts -DllPath $d } $script:dllDirDll)

        # P/Invoke bare-name imports (read from ImplMap/ModuleRef metadata, NOT a text scan).
        # These live in their OWN subdir so the end-to-end Test-TcpkPInvokeSurface call below sees
        # only them, not the other fixtures above.
        $script:pinvDir = Join-Path $script:work 'pinv'
        New-Item -ItemType Directory -Path $script:pinvDir -Force | Out-Null
        $pinv = @'
using System; using System.Runtime.InteropServices;
public class PinvBare {
  [DllImport("myplugin.dll")] static extern int DoThing();
  public void Use(){ DoThing(); }
}
'@
        $script:pinvBareDll = Join-Path $script:pinvDir 'PinvBare.dll'
        Add-Type -TypeDefinition $pinv -OutputAssembly $script:pinvBareDll -OutputType Library

        $pinvH = @'
using System; using System.Runtime.InteropServices;
public class PinvHardened {
  [DllImport("myplugin.dll")] static extern int DoThing();
  [DllImport("kernel32.dll")] static extern bool SetDefaultDllDirectories(uint f);
  public void Use(){ DoThing(); SetDefaultDllDirectories(0x800u); }
}
'@
        $script:pinvHardDll = Join-Path $script:pinvDir 'PinvHardened.dll'
        Add-Type -TypeDefinition $pinvH -OutputAssembly $script:pinvHardDll -OutputType Library
        $script:pivBare = @(& (Get-Module TCPK) { param($d) Get-TcpkPInvokeImportVerdicts -DllPath $d } $script:pinvBareDll)
        $script:pivHard = @(& (Get-Module TCPK) { param($d) Get-TcpkPInvokeImportVerdicts -DllPath $d } $script:pinvHardDll)
    }
}

AfterAll {
    if ($script:work -and (Test-Path -LiteralPath $script:work)) {
        try { [System.IO.Directory]::Delete($script:work, $true) } catch {}
    }
}

Describe 'Get-TcpkImpersonationVerdicts (unbalanced impersonation)' {
    BeforeEach {
        if (-not $script:cecil) { Set-ItResult -Skipped -Because 'Mono.Cecil not available' }
        elseif (-not $script:desktop) { Set-ItResult -Skipped -Because 'fixture compiles under Desktop/Framework only' }
    }
    It 'flags a sink with no revert on the method body' {
        ($script:iv | Where-Object { $_.Method -eq 'Leak' }) | Should -Not -BeNullOrEmpty
    }
    It 'does NOT flag a try/finally RevertToSelf (precision)' {
        ($script:iv | Where-Object { $_.Method -eq 'Balanced' }) | Should -BeNullOrEmpty
    }
    It 'surfaces end-to-end as ipc.unbalanced-impersonation (Inferred)' {
        $f = @(Test-TcpkImpersonationBalance -Path $script:work)
        ($f | Where-Object { $_.RuleId -eq 'ipc.unbalanced-impersonation' -and $_.Confidence -eq 'Inferred' }) | Should -Not -BeNullOrEmpty
    }
}

Describe 'Get-TcpkHandleInheritVerdicts (blanket handle inheritance)' {
    BeforeEach {
        if (-not $script:cecil) { Set-ItResult -Skipped -Because 'Mono.Cecil not available' }
        elseif (-not $script:desktop) { Set-ItResult -Skipped -Because 'fixture compiles under Desktop/Framework only' }
    }
    It 'proves SetHandleInformation setting HANDLE_FLAG_INHERIT (Confirmed IL)' {
        $f = $script:hv | Where-Object { $_.Method -eq 'InheritOn' }
        $f.Kind | Should -Be 'sethandleinformation-inherit'
        $f.Confidence | Should -Be 'Confirmed (IL)'
    }
    It 'does NOT flag SetHandleInformation clearing the inherit bit' {
        ($script:hv | Where-Object { $_.Method -eq 'InheritOff' }) | Should -BeNullOrEmpty
    }
    It 'proves SECURITY_ATTRIBUTES.bInheritHandle = TRUE (Confirmed IL)' {
        $f = $script:hv | Where-Object { $_.Method -eq 'SaTrue' }
        $f.Kind | Should -Be 'security-attributes-inherit'
        $f.Confidence | Should -Be 'Confirmed (IL)'
    }
    It 'does NOT flag bInheritHandle = FALSE (precision)' {
        ($script:hv | Where-Object { $_.Method -eq 'SaFalse' }) | Should -BeNullOrEmpty
    }
    It 'surfaces end-to-end as handle.inherit-leak.* findings' {
        $f = @(Test-TcpkHandleInheritance -Path $script:work)
        ($f | Where-Object { $_.RuleId -like 'handle.inherit-leak.*' }) | Should -Not -BeNullOrEmpty
    }
}

Describe 'Get-TcpkPipeFirstInstanceVerdicts (named-pipe squatting)' {
    BeforeEach {
        if (-not $script:cecil) { Set-ItResult -Skipped -Because 'Mono.Cecil not available' }
        elseif (-not $script:desktop) { Set-ItResult -Skipped -Because 'fixture compiles under Desktop/Framework only' }
    }
    It 'flags a literal open mode lacking FILE_FLAG_FIRST_PIPE_INSTANCE' {
        ($script:pv | Where-Object { $_.Method -eq 'SquatMe' }) | Should -Not -BeNullOrEmpty
    }
    It 'does NOT flag an open mode that carries the flag (precision)' {
        ($script:pv | Where-Object { $_.Method -eq 'FirstInstance' }) | Should -BeNullOrEmpty
    }
    It 'does NOT flag a computed (non-literal) open mode (no false positive)' {
        ($script:pv | Where-Object { $_.Method -eq 'Computed' }) | Should -BeNullOrEmpty
    }
    It 'surfaces end-to-end as pipe.no-first-instance (Confirmed IL)' {
        $f = @(Test-TcpkNamedPipeHardening -Path $script:work)
        ($f | Where-Object { $_.RuleId -eq 'pipe.no-first-instance' -and $_.Confidence -eq 'Confirmed (IL)' }) | Should -Not -BeNullOrEmpty
    }
}

Describe 'Get-TcpkDllSearchWidenVerdicts (relative SetDllDirectory)' {
    BeforeEach {
        if (-not $script:cecil) { Set-ItResult -Skipped -Because 'Mono.Cecil not available' }
        elseif (-not $script:desktop) { Set-ItResult -Skipped -Because 'fixture compiles under Desktop/Framework only' }
    }
    It 'flags a relative path added to the search order' {
        ($script:dv | Where-Object { $_.Method -eq 'Relative' }) | Should -Not -BeNullOrEmpty
    }
    It 'does NOT flag the empty-string hardening form (precision)' {
        ($script:dv | Where-Object { $_.Method -eq 'Empty' }) | Should -BeNullOrEmpty
    }
    It 'does NOT flag a rooted absolute path (precision)' {
        ($script:dv | Where-Object { $_.Method -eq 'Absolute' }) | Should -BeNullOrEmpty
    }
    It 'surfaces end-to-end as dllsearch.setdlldirectory-relative' {
        $f = @(Test-TcpkPInvokeSurface -Path $script:work)
        ($f | Where-Object { $_.RuleId -eq 'dllsearch.setdlldirectory-relative' }) | Should -Not -BeNullOrEmpty
    }
}

Describe 'Get-TcpkPInvokeImportVerdicts + pinvoke.bare-name (IL metadata, replaces the dead text regex)' {
    BeforeEach {
        if (-not $script:cecil) { Set-ItResult -Skipped -Because 'Mono.Cecil not available' }
        elseif (-not $script:desktop) { Set-ItResult -Skipped -Because 'fixture compiles under Desktop/Framework only' }
    }
    It 'reads the bare ModuleRef import from metadata (what the old text regex could never see)' {
        ($script:pivBare | Where-Object { $_.Kind -eq 'import' -and $_.Module -eq 'myplugin.dll' }) | Should -Not -BeNullOrEmpty
    }
    It 'reports HardenedSearch=$false when SetDefaultDllDirectories is NOT imported' {
        (@($script:pivBare | Where-Object { $_.Kind -eq 'summary' })[0]).HardenedSearch | Should -BeFalse
    }
    It 'reports HardenedSearch=$true when SetDefaultDllDirectories IS imported' {
        (@($script:pivHard | Where-Object { $_.Kind -eq 'summary' })[0]).HardenedSearch | Should -BeTrue
    }
    It 'flags a bare non-System32 import as MEDIUM when the search order is not hardened' {
        $f = @(Test-TcpkPInvokeSurface -Path $script:pinvBareDll)
        $m = @($f | Where-Object { $_.RuleId -eq 'pinvoke.bare-name' -and $_.Title -like '*myplugin.dll*' })
        $m | Should -Not -BeNullOrEmpty
        $m[0].Severity | Should -Be 'MEDIUM'
    }
    It 'keeps the bare import at LOW when SetDefaultDllDirectories is imported' {
        $f = @(Test-TcpkPInvokeSurface -Path $script:pinvHardDll)
        @($f | Where-Object { $_.RuleId -eq 'pinvoke.bare-name' -and $_.Title -like '*myplugin.dll*' })[0].Severity | Should -Be 'LOW'
    }
    It 'does NOT flag a known System32 import (kernel32) as bare-name' {
        $f = @(Test-TcpkPInvokeSurface -Path $script:pinvHardDll)
        ($f | Where-Object { $_.RuleId -eq 'pinvoke.bare-name' -and $_.Title -like '*kernel32*' }) | Should -BeNullOrEmpty
    }
}
