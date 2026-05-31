function Test-TcpkPeMitigations {
<#
.SYNOPSIS
    A02 - PE compile-time mitigations (ASLR, DEP, CFG, HighEntropyVA).

.DESCRIPTION
    Parses the PE optional-header DllCharacteristics field for every PE under
    the supplied path. Emits a HIGH finding for any PE missing ASLR or DEP,
    MEDIUM for missing CFG / HighEntropyVA.

.PARAMETER Path
    File or directory.

.EXAMPLE
    Test-TcpkPeMitigations -Path 'C:\Program Files\MyApp\'

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    # NOTE: do NOT use an [ordered]@{} keyed by the bit value here. An
    # OrderedDictionary indexed by an integer treats the integer as a POSITION,
    # not a key, so $flags[0x40] returns '' -- which made $on always empty and
    # caused EVERY PE to be reported as missing all four mitigations (massive
    # false-positive inflation). Use an explicit pair list instead.
    $flags = @(
        @{ Bit = 0x0020; Name = 'HIGH_ENTROPY_VA' }
        @{ Bit = 0x0040; Name = 'DYNAMIC_BASE'    }
        @{ Bit = 0x0080; Name = 'FORCE_INTEGRITY' }
        @{ Bit = 0x0100; Name = 'NX_COMPAT'       }
        @{ Bit = 0x4000; Name = 'GUARD_CF'        }
    )
    $required = @('DYNAMIC_BASE','NX_COMPAT','GUARD_CF','HIGH_ENTROPY_VA')

    foreach ($pe in Get-TcpkPeFiles -Path $Path) {
        $info = Read-TcpkPe -Path $pe.FullName
        if (-not $info) { continue }

        # Skip resource-only PEs (.mui, satellite resource assemblies). SizeOfCode = 0
        # means no executable code, so mitigation flags are meaningless -- nothing to
        # exploit. Reporting them is noise.
        if ($null -ne $info.SizeOfCode -and $info.SizeOfCode -eq 0) { continue }

        $on = @()
        foreach ($fl in $flags) {
            if ($info.DllCharacteristics -band $fl.Bit) { $on += $fl.Name }
        }
        $missing = $required | Where-Object { $_ -notin $on }
        if ($missing.Count -eq 0) { continue }

        $sev = if ('DYNAMIC_BASE' -in $missing -or 'NX_COMPAT' -in $missing) { 'HIGH' } else { 'MEDIUM' }
        $present = if ($on.Count) { $on -join ', ' } else { 'none' }
        $evidence = "DllCharacteristics=0x{0:X4}; present: {1}; missing: {2}" -f $info.DllCharacteristics, $present, ($missing -join ', ')

        New-TcpkFinding -Module 'static' -RuleId 'pe.missing-mitigations' `
            -Severity $sev -Confidence 'Confirmed' `
            -Title "$($pe.Name) missing: $($missing -join ', ')" `
            -File $pe.FullName -Evidence $evidence `
            -Cwe @('CWE-1037') `
            -Fix 'Rebuild with /DYNAMICBASE /NXCOMPAT /GUARD:CF /HIGHENTROPYVA.'
    }
}
