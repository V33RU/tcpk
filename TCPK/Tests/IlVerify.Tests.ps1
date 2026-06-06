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
    if ($script:cecil) {
        $a = "using System; using System.Diagnostics; public class IlvA { public void Dyn(string u){ Process.Start(u); } public void Con(){ Process.Start(`"notepad.exe`"); } }"
        $script:dllA = Join-Path $script:work 'IlvA.dll'; Add-Type -TypeDefinition $a -OutputAssembly $script:dllA -OutputType Library
        $b = "using System; using System.Diagnostics; public class IlvB { public void Only(){ Process.Start(`"calc.exe`"); } }"
        $script:dllB = Join-Path $script:work 'IlvB.dll'; Add-Type -TypeDefinition $b -OutputAssembly $script:dllB -OutputType Library
        $c = "public class IlvC { public string n = `"Process.Start is risky`"; }"
        $script:dllC = Join-Path $script:work 'IlvC.dll'; Add-Type -TypeDefinition $c -OutputAssembly $script:dllC -OutputType Library
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
    BeforeEach { if (-not $script:cecil) { Set-ItResult -Skipped -Because 'Mono.Cecil (ILSpy) not available' } }

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
