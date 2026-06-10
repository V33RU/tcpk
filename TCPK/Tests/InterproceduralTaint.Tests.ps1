#requires -Version 5.1
# Interprocedural taint: external input that reaches a sink ACROSS a method boundary
# (var x = ReadConfig(); Process.Start(x), where ReadConfig reads the source in a
# different method) must be Confirmed (IL); a helper that returns a CONSTANT must NOT
# taint its caller (precision -- no false positives). Skips if Mono.Cecil is absent.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
    $script:cecil = $false
    try { $script:cecil = & (Get-Module TCPK) { Test-TcpkCecilAvailable } } catch { }

    $script:work = Join-Path ([IO.Path]::GetTempPath()) ("tcpk-ipt-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:work -Force | Out-Null
    if ($script:cecil) {
        # Cross-method via a LOCAL: Read() reads the source and returns it; Run() (no
        # source of its own) passes the result through a local into Process.Start.
        $ip = "using System; using System.IO; using System.Diagnostics; public class IpProc { string Read(string p){ return File.ReadAllText(p); } public void Run(string p){ var c = Read(p); Process.Start(c); } }"
        $script:dllInterproc = Join-Path $script:work 'IpProc.dll'; Add-Type -TypeDefinition $ip -OutputAssembly $script:dllInterproc -OutputType Library

        # Cross-method INLINE: Process.Start(Read(p)) with no intermediate local.
        $il = "using System; using System.IO; using System.Diagnostics; public class IpInline { string Read(string p){ return File.ReadAllText(p); } public void Run(string p){ Process.Start(Read(p)); } }"
        $script:dllInline = Join-Path $script:work 'IpInline.dll'; Add-Type -TypeDefinition $il -OutputAssembly $script:dllInline -OutputType Library

        # PRECISION negative: the helper returns a CONSTANT, not external input, so the
        # caller's Process.Start(local) is dynamic-but-NOT-tainted -> must stay Inferred.
        $ng = "using System; using System.Diagnostics; public class IpConst { string Name(){ return `"calc.exe`"; } public void Run(){ var c = Name(); Process.Start(c); } }"
        $script:dllConst = Join-Path $script:work 'IpConst.dll'; Add-Type -TypeDefinition $ng -OutputAssembly $script:dllConst -OutputType Library

        # Cross-method via a FIELD: Configure() stashes external input in a field; Run()
        # (no source of its own) feeds that field into Process.Start -- the classic carrier.
        $fp = "using System; using System.IO; using System.Diagnostics; public class FProc { string _cmd; public void Configure(string p){ _cmd = File.ReadAllText(p); } public void Run(){ Process.Start(_cmd); } }"
        $script:dllFld = Join-Path $script:work 'FProc.dll'; Add-Type -TypeDefinition $fp -OutputAssembly $script:dllFld -OutputType Library

        # PRECISION negative: a field only ever assigned a CONSTANT must not taint the sink.
        $fc = "using System; using System.Diagnostics; public class FConst { string _cmd = `"calc.exe`"; public void Run(){ Process.Start(_cmd); } }"
        $script:dllFldC = Join-Path $script:work 'FConst.dll'; Add-Type -TypeDefinition $fc -OutputAssembly $script:dllFldC -OutputType Library
    }
}

AfterAll {
    if ($script:work -and (Test-Path -LiteralPath $script:work)) {
        try { [System.IO.Directory]::Delete($script:work, $true) } catch {}
    }
}

Describe 'Interprocedural taint (cross-method source -> sink)' {
    BeforeAll {
        $script:Judge = {
            param($dll)
            $f = & (Get-Module TCPK) { param($p) New-TcpkFinding -Module 'static' -RuleId 'callsites.command-execution' `
                -Severity 'MEDIUM' -Confidence 'Inferred' -Title 'exec' -File $p -Evidence 'Process.Start' } $dll
            ,($f | & (Get-Module TCPK) { $input | Confirm-TcpkCallsiteUsage })
        }
    }
    BeforeEach { if (-not $script:cecil) { Set-ItResult -Skipped -Because 'Mono.Cecil (ILSpy) not available' } }

    It 'confirms input that reaches a sink via a local from another method' {
        $r = & $script:Judge $script:dllInterproc
        $r.Confidence | Should -Be 'Confirmed (IL)'
        $r.Severity   | Should -Be 'MEDIUM'
    }

    It 'confirms input that reaches a sink inline from another method call' {
        $r = & $script:Judge $script:dllInline
        $r.Confidence | Should -Be 'Confirmed (IL)'
    }

    It 'does NOT taint a caller when the helper returns a constant (precision)' {
        $r = & $script:Judge $script:dllConst
        $r.Confidence | Should -Be 'Inferred'   # reachable+dynamic but not tainted
        $r.Severity   | Should -Be 'MEDIUM'
        $r.Description | Should -Match 'no external-input source was proven'
    }
}

Describe 'Interprocedural taint (cross-method via a field)' {
    BeforeAll {
        $script:JudgeF = {
            param($dll)
            $f = & (Get-Module TCPK) { param($p) New-TcpkFinding -Module 'static' -RuleId 'callsites.command-execution' `
                -Severity 'MEDIUM' -Confidence 'Inferred' -Title 'exec' -File $p -Evidence 'Process.Start' } $dll
            ,($f | & (Get-Module TCPK) { $input | Confirm-TcpkCallsiteUsage })
        }
    }
    BeforeEach { if (-not $script:cecil) { Set-ItResult -Skipped -Because 'Mono.Cecil (ILSpy) not available' } }

    It 'confirms input stashed in a field then used at a sink in another method' {
        $r = & $script:JudgeF $script:dllFld
        $r.Confidence | Should -Be 'Confirmed (IL)'
    }
    It 'does NOT taint a sink fed by a constant-only field (precision)' {
        $r = & $script:JudgeF $script:dllFldC
        $r.Confidence | Should -Be 'Inferred'
    }
}

Describe 'Get-TcpkTaintedReturningMethods (return-value taint set)' {
    BeforeEach { if (-not $script:cecil) { Set-ItResult -Skipped -Because 'Mono.Cecil (ILSpy) not available' } }

    It 'classifies a source-reading value method as tainted-returning, a constant one as not' {
        $set = & (Get-Module TCPK) { param($d)
            $asm = Get-TcpkCecilAssembly $d
            Get-TcpkTaintedReturningMethods -Asm $asm -Key $d
        } $script:dllInterproc
        ($set | Where-Object { $_ -match '::Read\(' }).Count | Should -BeGreaterThan 0

        $set2 = & (Get-Module TCPK) { param($d)
            $asm = Get-TcpkCecilAssembly $d
            Get-TcpkTaintedReturningMethods -Asm $asm -Key $d
        } $script:dllConst
        ($set2 | Where-Object { $_ -match '::Name\(' }).Count | Should -Be 0
    }
}
