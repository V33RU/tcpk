#requires -Version 5.1
# Cross-assembly taint: a helper DLL reads external input and RETURNS it; the main DLL
# (a separate assembly) feeds that result into a sink. The source->sink path crosses the
# assembly boundary, so the per-assembly taint set misses it -- the cross-assembly union
# recognises it. Additive: a helper that returns a CONSTANT must NOT taint the sink.
# Skips if Mono.Cecil is absent.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
    $script:cecil = $false
    try { $script:cecil = & (Get-Module TCPK) { Test-TcpkCecilAvailable } } catch { }
    # The fixture references a sibling helper DLL via -ReferencedAssemblies, which on .NET Core
    # replaces the default BCL reference set (so System.Diagnostics.Process no longer resolves
    # -> CS0103). Under .NET Framework (Windows PowerShell 5.1 = Desktop) the default set stays,
    # so build the two-assembly fixture only there. The cross-assembly logic is runtime-agnostic.
    $script:desktop = ($PSVersionTable.PSEdition -eq 'Desktop')

    $script:work = Join-Path ([IO.Path]::GetTempPath()) ("tcpk-xasm-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:work -Force | Out-Null
    if ($script:cecil -and $script:desktop) {
        $helperCs = 'using System.IO; namespace H { public class Helper { public string Read(string p){ return File.ReadAllText(p); } public string Constant(){ return "calc.exe"; } } }'
        $script:helperDll = Join-Path $script:work 'Helper.dll'
        Add-Type -TypeDefinition $helperCs -OutputAssembly $script:helperDll -OutputType Library
        $mt = 'using System.Diagnostics; using H; namespace M { public class MT { public void Run(string p){ var h = new Helper(); var c = h.Read(p); Process.Start(c); } } }'
        $script:mtDll = Join-Path $script:work 'MainTainted.dll'
        Add-Type -TypeDefinition $mt -OutputAssembly $script:mtDll -OutputType Library -ReferencedAssemblies $script:helperDll
        $mc = 'using System.Diagnostics; using H; namespace M { public class MC { public void Run(){ var h = new Helper(); var c = h.Constant(); Process.Start(c); } } }'
        $script:mcDll = Join-Path $script:work 'MainConst.dll'
        Add-Type -TypeDefinition $mc -OutputAssembly $script:mcDll -OutputType Library -ReferencedAssemblies $script:helperDll
    }
}

AfterAll {
    try { & (Get-Module TCPK) { Clear-TcpkCecilCache } } catch {}
    if ($script:work -and (Test-Path -LiteralPath $script:work)) { try { [System.IO.Directory]::Delete($script:work, $true) } catch {} }
}

Describe 'Cross-assembly taint (source in DLL A -> sink in DLL B)' {
    BeforeAll {
        $script:Judge = {
            param($dll)
            $f = & (Get-Module TCPK) { param($p) New-TcpkFinding -Module 'static' -RuleId 'callsites.command-execution' `
                -Severity 'MEDIUM' -Confidence 'Inferred' -Title 'exec' -File $p -Evidence 'Process.Start' } $dll
            ($f | & (Get-Module TCPK) { $input | Confirm-TcpkCallsiteUsage })
        }
    }
    BeforeEach {
        if (-not $script:cecil) { Set-ItResult -Skipped -Because 'Mono.Cecil (ILSpy) not available' }
        elseif (-not $script:desktop) { Set-ItResult -Skipped -Because 'two-assembly fixture needs the .NET Framework default reference set (5.1/Desktop only)' }
    }

    It 'confirms input read by a helper assembly then sunk in the main assembly' {
        (& $script:Judge $script:mtDll).Confidence | Should -Be 'Confirmed (IL)'
    }

    It 'does NOT taint a sink fed by a helper that returns a constant (precision)' {
        (& $script:Judge $script:mcDll).Confidence | Should -Be 'Inferred'
    }
}
