function Test-TcpkAotBinary {
<#
.SYNOPSIS
    Detect .NET Native AOT binaries that evade IL-based analysis.

.DESCRIPTION
    .NET 7+ PublishAot compiles to pure native code with no IL metadata.
    TCPK's IL pipeline (taint analysis, crypto provers, decompilation) relies
    on Mono.Cecil which requires the CLI metadata header (BSJB signature).
    AOT binaries strip this entirely -- the IL pipeline silently produces
    no findings, creating a false-negative gap.

    This cmdlet detects AOT binaries by looking for .NET runtime string
    markers (System.Private.CoreLib, System.Runtime, System.Object) in a
    PE that has NO BSJB metadata header.  When found, it emits a warning
    so the operator knows IL analysis does not apply and alternative
    techniques (string extraction, native reversing) are needed.

    Also detects IL-stripped assemblies: binaries that have the BSJB header
    but where the majority of methods have empty IL bodies (PublishTrimmed
    with ILStrip).

.PARAMETER Path
    File or directory to scan.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    foreach ($pe in Get-TcpkPeFiles -Path $Path) {
        if (Test-TcpkIsFrameworkFile $pe.Name)  { continue }

        # --- Case 1: pure AOT (no BSJB, but .NET runtime strings present) ---
        if (Test-TcpkIsAotBinary -Path $pe.FullName) {
            New-TcpkFinding -Module 'static' -RuleId 'pe.native-aot' `
                -Severity 'MEDIUM' -Confidence 'Confirmed' `
                -Title "Native AOT binary -- IL analysis not applicable: $($pe.Name)" `
                -File $pe.FullName `
                -Evidence '.NET runtime strings present but no CLI metadata header (BSJB absent)' `
                -Cwe @('CWE-693') `
                -Description ('This binary was compiled with .NET Native AOT (PublishAot). It contains ' +
                    'no IL metadata, so taint analysis, decompilation, and IL-based provers will ' +
                    'produce no findings. This is NOT an absence of vulnerabilities -- it means the ' +
                    'automated IL pipeline cannot analyze this binary. Manual native reversing, ' +
                    'string analysis, and dynamic testing are required instead. AOT compilation is ' +
                    'also used as an evasion technique by malware (HarfangLab/Cyderes 2025).') `
                -Fix 'Use native analysis tools (IDA, Ghidra, x64dbg) and dynamic testing for this binary. Run Get-TcpkReconStrings for automated string extraction.'
            continue
        }

        # --- Case 2: IL-stripped (BSJB present, but method bodies gutted) ---
        $text = Read-TcpkAllText -Path $pe.FullName
        if (-not $text) { continue }
        if (-not $text.Contains('BSJB')) { continue }

        if (-not (Initialize-TcpkCecil)) { continue }

        $asm = $null
        try { $asm = [Mono.Cecil.AssemblyDefinition]::ReadAssembly($pe.FullName) } catch { continue }
        if (-not $asm) { continue }

        try {
            $totalMethods   = 0
            $emptyMethods   = 0
            foreach ($t in $asm.MainModule.GetTypes()) {
                foreach ($m in $t.Methods) {
                    if ($m.IsAbstract -or $m.IsPInvokeImpl) { continue }
                    $totalMethods++
                    if (-not $m.HasBody -or $m.Body.Instructions.Count -le 1) {
                        $emptyMethods++
                    }
                }
            }
            if ($totalMethods -ge 10 -and $emptyMethods -gt ($totalMethods * 0.8)) {
                New-TcpkFinding -Module 'static' -RuleId 'pe.il-stripped' `
                    -Severity 'LOW' -Confidence 'Confirmed' `
                    -Title "IL-stripped binary -- taint analysis degraded: $($pe.Name)" `
                    -File $pe.FullName `
                    -Evidence "$emptyMethods of $totalMethods methods have empty IL bodies" `
                    -Cwe @('CWE-693') `
                    -Description ('This assembly retains .NET metadata but most method bodies have been ' +
                        'stripped (PublishTrimmed with ILStrip or similar). IL-based taint analysis and ' +
                        'decompilation will produce incomplete results. The type/method structure is ' +
                        'still visible for attack-surface enumeration.') `
                    -Fix 'Supplement IL analysis with dynamic testing and string extraction.'
            }
        }
        finally {
            if ($asm) { try { $asm.Dispose() } catch { } }
        }
    }
}
