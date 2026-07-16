#requires -Version 5.1
# Deterministic IL verification (Confirm-TcpkCallsiteUsage): reachability + constant-
# vs-dynamic argument analysis to separate real callsite bugs from false positives.
# Compiles tiny sample DLLs and checks the verdicts. Skips if Mono.Cecil is absent.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
    $script:cecil = $false
    try { $script:cecil = & (Get-Module TCPK) { Test-TcpkCecilAvailable } } catch { }

    $script:work = Join-Path ([IO.Path]::GetTempPath()) ("tcpk-ilv-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:work -Force | Out-Null

    # On .NET 5+ (PowerShell 7) BinaryFormatter serialization is an obsolete-as-error
    # diagnostic (SYSLIB0011). The type is still present and compile-loadable, so the
    # IlvDeser fixture suppresses only that one ID to keep the real BinaryFormatter::
    # Deserialize call site in the emitted IL (what the deser.binaryformatter prover
    # keys on). Windows PowerShell 5.1 (.NET Framework) has no such diagnostic, so no
    # option is passed there. If a future runtime removes the type entirely and the
    # compile still throws, the catch below degrades the suite to Skipped, not Failed.
    $deserOpts = @{}
    if ($PSVersionTable.PSEdition -eq 'Core') { $deserOpts['CompilerOptions'] = '/nowarn:SYSLIB0011' }
    $script:fxReady = $false
    $script:fxError = $null
    if ($script:cecil) {
      try {
        $a = "using System; using System.Diagnostics; public class IlvA { public void Dyn(string u){ Process.Start(u); } public void Con(){ Process.Start(`"notepad.exe`"); } }"
        $script:dllA = Join-Path $script:work 'IlvA.dll'; Add-Type -TypeDefinition $a -OutputAssembly $script:dllA -OutputType Library
        $b = "using System; using System.Diagnostics; public class IlvB { public void Only(){ Process.Start(`"calc.exe`"); } }"
        $script:dllB = Join-Path $script:work 'IlvB.dll'; Add-Type -TypeDefinition $b -OutputAssembly $script:dllB -OutputType Library
        $c = "public class IlvC { public string n = `"Process.Start is risky`"; }"
        $script:dllC = Join-Path $script:work 'IlvC.dll'; Add-Type -TypeDefinition $c -OutputAssembly $script:dllC -OutputType Library

        # deser tainted: reads a file (external source) then BinaryFormatter.Deserialize
        $dt = "using System; using System.IO; using System.Runtime.Serialization.Formatters.Binary; public class IlvDeser { public object Load(string p){ var b=File.ReadAllBytes(p); var bf=new BinaryFormatter(); using(var ms=new MemoryStream(b)){ return bf.Deserialize(ms);} } }"
        $script:dllDeser = Join-Path $script:work 'IlvDeser.dll'; Add-Type -TypeDefinition $dt -OutputAssembly $script:dllDeser -OutputType Library @deserOpts
        # deser referenced only (string), never invoked
        $dr = "public class IlvDeserRef { public string n = `"BinaryFormatter is dangerous`"; }"
        $script:dllDeserRef = Join-Path $script:work 'IlvDeserRef.dll'; Add-Type -TypeDefinition $dr -OutputAssembly $script:dllDeserRef -OutputType Library
        # P/Invoke command exec, tainted by a caller parameter: WinExec(cmd)
        $ep = "using System; using System.Runtime.InteropServices; public class IlvExecP { [DllImport(`"kernel32.dll`")] static extern uint WinExec(string c, uint f); public void Run(string cmd){ WinExec(cmd, 1); } }"
        $script:dllExecP = Join-Path $script:work 'IlvExecP.dll'; Add-Type -TypeDefinition $ep -OutputAssembly $script:dllExecP -OutputType Library
        # capability P/Invoke declared but never called (keyboard hook)
        $hk = "using System; using System.Runtime.InteropServices; public class IlvHook { [DllImport(`"user32.dll`")] static extern IntPtr SetWindowsHookEx(int t, IntPtr p, IntPtr m, uint th); public void Nop(){} }"
        $script:dllHook = Join-Path $script:work 'IlvHook.dll'; Add-Type -TypeDefinition $hk -OutputAssembly $script:dllHook -OutputType Library
        # reachable + dynamic argument but NOT tainted (a private field, no source, no param)
        $fl = "using System; using System.Diagnostics; public class IlvField { private string _c = `"x`"; public void Go(){ Process.Start(_c); } }"
        $script:dllField = Join-Path $script:work 'IlvField.dll'; Add-Type -TypeDefinition $fl -OutputAssembly $script:dllField -OutputType Library
        $script:fxReady = $true
      } catch {
        $script:fxError = $_.Exception.Message
      }
    }
}

AfterAll {
    if ($script:work -and (Test-Path -LiteralPath $script:work)) {
        try { [System.IO.Directory]::Delete($script:work, $true) } catch {}
    }
}

Describe 'Confirm-TcpkCallsiteUsage (IL reachability + argument analysis)' {
    BeforeAll {
        $script:JudgeSb = {
            param($dll)
            $f = & (Get-Module TCPK) { param($p) New-TcpkFinding -Module 'static' -RuleId 'callsites.command-execution' `
                -Severity 'MEDIUM' -Confidence 'Inferred' -Title 'exec' -File $p -Evidence 'Process.Start' } $dll
            ,($f | & (Get-Module TCPK) { $input | Confirm-TcpkCallsiteUsage })
        }
    }
    BeforeEach {
        if (-not $script:cecil)   { Set-ItResult -Skipped -Because 'Mono.Cecil (ILSpy) not available' }
        elseif (-not $script:fxReady) { Set-ItResult -Skipped -Because "C# fixtures did not compile on this runtime: $script:fxError" }
    }

    It 'marks a reachable call with a dynamic argument as Confirmed (IL)' {
        $r = & $script:JudgeSb $script:dllA
        $r.Confidence | Should -Be 'Confirmed (IL)'
        $r.Severity   | Should -Be 'MEDIUM'   # not demoted
    }

    It 'marks a constant-argument-only call as Likely-FP (IL) and demotes severity' {
        $r = & $script:JudgeSb $script:dllB
        $r.Confidence | Should -Be 'Likely-FP (IL)'
        $r.Severity   | Should -Be 'LOW'      # MEDIUM -> one notch down
    }

    It 'marks a string-only match (API never invoked) as Likely-FP (IL) / INFO' {
        $r = & $script:JudgeSb $script:dllC
        $r.Confidence | Should -Be 'Likely-FP (IL)'
        $r.Severity   | Should -Be 'INFO'
    }

    It 'passes non-callsite findings through unchanged' {
        $f = & (Get-Module TCPK) { New-TcpkFinding -Module 'network' -RuleId 'scheme.cleartext-http' -Severity 'MEDIUM' -Confidence 'Inferred' -Title 'x' -File 'y' }
        $r = @($f | & (Get-Module TCPK) { $input | Confirm-TcpkCallsiteUsage })
        $r[0].Confidence | Should -Be 'Inferred'
    }
}

Describe 'Confirm-TcpkCallsiteUsage (P/Invoke, deserialization, bounded taint)' {
    BeforeAll {
        # judge that takes an explicit RuleId + severity so we can exercise deser.* and
        # the capability/exec rules, not just command-execution.
        $script:JudgeR = {
            param($rule, $sev, $dll)
            $f = & (Get-Module TCPK) { param($r,$s,$p) New-TcpkFinding -Module 'static' -RuleId $r `
                -Severity $s -Confidence 'Inferred' -Title 't' -File $p -Evidence 'e' } $rule $sev $dll
            ,($f | & (Get-Module TCPK) { $input | Confirm-TcpkCallsiteUsage })
        }
    }
    BeforeEach {
        if (-not $script:cecil)   { Set-ItResult -Skipped -Because 'Mono.Cecil (ILSpy) not available' }
        elseif (-not $script:fxReady) { Set-ItResult -Skipped -Because "C# fixtures did not compile on this runtime: $script:fxError" }
    }

    It 'confirms unsafe deserialization fed by external input as Confirmed (IL)' {
        $r = & $script:JudgeR 'deser.binaryformatter' 'HIGH' $script:dllDeser
        $r.Confidence | Should -Be 'Confirmed (IL)'
        $r.Severity   | Should -Be 'HIGH'
        $r.Description | Should -Match 'external input reaches it'
    }

    It 'demotes a referenced-but-never-invoked formatter to Likely-FP (IL) / INFO' {
        $r = & $script:JudgeR 'deser.binaryformatter' 'HIGH' $script:dllDeserRef
        $r.Confidence | Should -Be 'Likely-FP (IL)'
        $r.Severity   | Should -Be 'INFO'
    }

    It 'confirms a P/Invoke command exec fed by a caller parameter as Confirmed (IL)' {
        $r = & $script:JudgeR 'callsites.command-execution' 'MEDIUM' $script:dllExecP
        $r.Confidence | Should -Be 'Confirmed (IL)'
        $r.Severity   | Should -Be 'MEDIUM'
    }

    It 'demotes a capability P/Invoke that is declared but never called to Likely-FP (IL) / INFO' {
        $r = & $script:JudgeR 'callsites.input-capture' 'MEDIUM' $script:dllHook
        $r.Confidence | Should -Be 'Likely-FP (IL)'
        $r.Severity   | Should -Be 'INFO'
    }

    It 'leaves a reachable dynamic-but-not-tainted call as Inferred (no over-claim)' {
        $r = & $script:JudgeR 'callsites.command-execution' 'MEDIUM' $script:dllField
        $r.Confidence | Should -Be 'Inferred'
        $r.Severity   | Should -Be 'MEDIUM'
        $r.Description | Should -Match 'no external-input source was proven'
    }
}
