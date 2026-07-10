#requires -Version 5.1
# Pester 5: the autonomous agent's new read-only investigation tools (#2) -- call-graph
# navigation (get_callers / get_callees) and the deterministic taint verdict
# (get_taint_trace). The taint verdict MUST mirror the audit's IL prover
# (Get-TcpkCallsiteUsage): a public parameter reaching Process.Start is tainted-reachable,
# a constant Process.Start argument is constant-only (not injectable), and a method that
# calls no sink is no-sink. The toolset must stay read-only (no exploit surface).
# Skips the IL cases if the C# compiler is unavailable.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
    $script:fx = Join-Path $env:TEMP ('tcpk-agenttools-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:fx | Out-Null
    $script:dll = Join-Path $script:fx 'TaintFx.dll'
    $script:compiled = $false
    try {
        $prov = New-Object Microsoft.CSharp.CSharpCodeProvider
        $cp = New-Object System.CodeDom.Compiler.CompilerParameters
        $cp.GenerateExecutable = $false
        $cp.OutputAssembly = $script:dll
        $cp.ReferencedAssemblies.Add('System.dll') | Out-Null
        # Run(cmd): public parameter flows straight into Process.Start -> tainted + reachable.
        # Fixed():  Process.Start with a constant literal -> constant-only, not injectable.
        # Caller(): invokes Run (not a sink directly) -> a caller edge, and a no-sink method.
        $src = @'
using System.Diagnostics;
public class TaintFx {
    public void Run(string cmd) { Process.Start(cmd); }
    public void Fixed() { Process.Start("notepad.exe"); }
    public void Caller(string p) { Run(p); }
}
'@
        $r = $prov.CompileAssemblyFromSource($cp, $src)
        $script:compiled = (Test-Path $script:dll) -and ($r.Errors.Count -eq 0)
    } catch { }
}
AfterAll {
    if ($script:fx -and (Test-Path $script:fx)) { Remove-Item $script:fx -Recurse -Force -ErrorAction SilentlyContinue }
}

Describe 'Agent tool registry' {
    It 'registers the three new read-only investigation tools' {
        $names = & (Get-Module TCPK) { (Get-TcpkAgentTools).name }
        $names | Should -Contain 'get_taint_trace'
        $names | Should -Contain 'get_callers'
        $names | Should -Contain 'get_callees'
    }
    It 'exposes no exploit / write / execute tool to the agent' {
        $names = & (Get-Module TCPK) { (Get-TcpkAgentTools).name }
        ($names | Where-Object { $_ -match 'exploit|write|exec|launch|delete|enable' }) | Should -BeNullOrEmpty
    }
}

Describe 'get_taint_trace mirrors the deterministic IL prover' {
    It 'a public parameter reaching Process.Start is tainted-reachable' {
        if (-not $script:compiled) { Set-ItResult -Skipped -Because 'C# compiler unavailable'; return }
        $res = & (Get-Module TCPK) { param($d) Get-TcpkAgentTaintTrace -Dll $d -Method 'TaintFx::Run' } $script:dll
        $res.verdict      | Should -Be 'tainted-reachable'
        $res.taintedSites | Should -BeGreaterThan 0
    }
    It 'a constant Process.Start argument is constant-only (not injectable)' {
        if (-not $script:compiled) { Set-ItResult -Skipped -Because 'C# compiler unavailable'; return }
        $res = & (Get-Module TCPK) { param($d) Get-TcpkAgentTaintTrace -Dll $d -Method 'TaintFx::Fixed' } $script:dll
        $res.verdict | Should -Be 'constant-only'
    }
    It 'a method that calls no known sink returns no-sink' {
        if (-not $script:compiled) { Set-ItResult -Skipped -Because 'C# compiler unavailable'; return }
        $res = & (Get-Module TCPK) { param($d) Get-TcpkAgentTaintTrace -Dll $d -Method 'TaintFx::Caller' } $script:dll
        $res.verdict | Should -Be 'no-sink'
    }
    It 'returns an error object for a method that does not exist' {
        if (-not $script:compiled) { Set-ItResult -Skipped -Because 'C# compiler unavailable'; return }
        $res = & (Get-Module TCPK) { param($d) Get-TcpkAgentTaintTrace -Dll $d -Method 'TaintFx::Nope' } $script:dll
        $res.error | Should -Be 'method not found'
    }
}

Describe 'call-graph navigation' {
    It 'get_callers finds the caller of a method and reports its reachability' {
        if (-not $script:compiled) { Set-ItResult -Skipped -Because 'C# compiler unavailable'; return }
        $res = & (Get-Module TCPK) { param($d) Get-TcpkAgentCallers -Dll $d -Method 'TaintFx::Run' } $script:dll
        ($res.callers.method) | Should -Contain 'TaintFx::Caller'
        ($res.callers | Where-Object { $_.method -eq 'TaintFx::Caller' }).reachable | Should -BeTrue
    }
    It 'get_callees lists the sink a method calls, flagged as a sink' {
        if (-not $script:compiled) { Set-ItResult -Skipped -Because 'C# compiler unavailable'; return }
        $res = & (Get-Module TCPK) { param($d) Get-TcpkAgentCallees -Dll $d -Method 'TaintFx::Run' } $script:dll
        ($res.callees.target -join ';') | Should -Match 'Process::Start'
        $res.sinkCallees | Should -BeGreaterThan 0
    }
}
