#requires -Version 5.1
# StringBuilder-carried taint: external input appended to a StringBuilder and then
# materialised with ToString() into a sink is THE dominant SQL / command building
# idiom. Without carrier tracking the taint trail dies at ToString (not a source),
# dropping a real injection from Confirmed (IL) to Inferred. Verified with a
# command-execution sink (Process.Start); the propagation is sink-agnostic, so it
# applies identically to a SQL-command sink. Skips if Mono.Cecil is absent.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
    $script:cecil = $false
    try { $script:cecil = & (Get-Module TCPK) { Test-TcpkCecilAvailable } } catch { }

    $script:work = Join-Path ([IO.Path]::GetTempPath()) ("tcpk-sbt-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:work -Force | Out-Null
    if ($script:cecil) {
        # input -> sb.Append -> sb.ToString() -> Process.Start
        $pos = "using System; using System.IO; using System.Text; using System.Diagnostics; public class SbVuln { public void Run(string p){ var sb = new StringBuilder(); sb.Append(`"cmd /c `"); sb.Append(File.ReadAllText(p)); var s = sb.ToString(); Process.Start(s); } }"
        $script:dllPos = Join-Path $script:work 'SbVuln.dll'; Add-Type -TypeDefinition $pos -OutputAssembly $script:dllPos -OutputType Library

        # input -> sb.AppendFormat("... {0}", input) -> ToString -> Process.Start
        $fmt = "using System; using System.IO; using System.Text; using System.Diagnostics; public class SbFmt { public void Run(string p){ var sb = new StringBuilder(); sb.AppendFormat(`"run {0}`", File.ReadAllText(p)); Process.Start(sb.ToString()); } }"
        $script:dllFmt = Join-Path $script:work 'SbFmt.dll'; Add-Type -TypeDefinition $fmt -OutputAssembly $script:dllFmt -OutputType Library

        # PRECISION negative: only CONSTANTS appended -> ToString is not tainted.
        $neg = "using System; using System.Text; using System.Diagnostics; public class SbConst { public void Run(){ var sb = new StringBuilder(); sb.Append(`"calc`"); sb.Append(`".exe`"); var s = sb.ToString(); Process.Start(s); } }"
        $script:dllNeg = Join-Path $script:work 'SbConst.dll'; Add-Type -TypeDefinition $neg -OutputAssembly $script:dllNeg -OutputType Library
    }
}

AfterAll {
    if ($script:work -and (Test-Path -LiteralPath $script:work)) {
        # DLLs may be memory-mapped by Mono.Cecil; best-effort cleanup.
        try { [System.IO.Directory]::Delete($script:work, $true) } catch {}
    }
}

Describe 'StringBuilder-carried taint (Append -> ToString -> sink)' {
    BeforeAll {
        $script:Judge = {
            param($dll)
            $f = & (Get-Module TCPK) { param($p) New-TcpkFinding -Module 'static' -RuleId 'callsites.command-execution' `
                -Severity 'MEDIUM' -Confidence 'Inferred' -Title 'exec' -File $p -Evidence 'Process.Start' } $dll
            ,($f | & (Get-Module TCPK) { $input | Confirm-TcpkCallsiteUsage })
        }
    }
    BeforeEach { if (-not $script:cecil) { Set-ItResult -Skipped -Because 'Mono.Cecil (ILSpy) not available' } }

    It 'confirms input appended to a StringBuilder then materialised into a sink' {
        $r = & $script:Judge $script:dllPos
        $r.Confidence | Should -Be 'Confirmed (IL)'
        $r.Severity   | Should -Be 'MEDIUM'
    }

    It 'confirms input passed through AppendFormat then materialised into a sink' {
        $r = & $script:Judge $script:dllFmt
        $r.Confidence | Should -Be 'Confirmed (IL)'
    }

    It 'does NOT taint a sink when only constants were appended (precision)' {
        $r = & $script:Judge $script:dllNeg
        $r.Confidence | Should -Be 'Inferred'
        $r.Description | Should -Match 'no external-input source was proven'
    }
}
