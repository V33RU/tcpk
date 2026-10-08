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
