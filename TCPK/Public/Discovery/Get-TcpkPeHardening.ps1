function Get-TcpkPeHardening {
<#
.SYNOPSIS
    Per-DLL binary-hardening matrix (ASLR / DEP / CFG / HighEntropyVA / ...).

.DESCRIPTION
    Reads the PE optional-header DllCharacteristics for every executable PE under
    the path and returns a per-file row showing which exploit mitigations are
    enabled. This is the PESecurity-style matrix that drives the Excel
    'DLL Hardening' sheet -- a complete picture, not just the weak ones.

    Resource-only PEs (SizeOfCode = 0: .mui / satellite assemblies) are skipped
    -- they have no executable code, so mitigation flags are meaningless.

    Status:
      HARDENED  all four core mitigations present (ASLR + DEP + CFG + HighEntropyVA)
      WEAK      missing ASLR or DEP (the serious ones)
      PARTIAL   only CFG and/or HighEntropyVA missing

.PARAMETER Path
    File or directory.

.OUTPUTS
    [pscustomobject] per PE (NOT a [TcpkFinding]).
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $flags = @(
        @{ Bit = 0x0040; Name = 'ASLR' }            # DYNAMIC_BASE
        @{ Bit = 0x0100; Name = 'DEP' }             # NX_COMPAT
        @{ Bit = 0x4000; Name = 'CFG' }             # GUARD_CF
        @{ Bit = 0x0020; Name = 'HighEntropyVA' }   # HIGH_ENTROPY_VA
        @{ Bit = 0x0080; Name = 'ForceIntegrity' }  # FORCE_INTEGRITY
    )

    foreach ($pe in Get-TcpkPeFiles -Path $Path) {
        $info = Read-TcpkPe -Path $pe.FullName
        if (-not $info) { continue }
        if ($null -ne $info.SizeOfCode -and $info.SizeOfCode -eq 0) { continue }   # resource-only

        $on = @{}
        foreach ($fl in $flags) { $on[$fl.Name] = [bool]($info.DllCharacteristics -band $fl.Bit) }

        $arch = switch ($info.Machine) {
            0x8664  { 'x64' }
            0x14C   { 'x86' }
            0xAA64  { 'ARM64' }
            0x1C0   { 'ARM' }
            0x1C4   { 'ARM' }
            default { ('0x{0:X}' -f $info.Machine) }
        }

        $missing = @()
        foreach ($n in 'ASLR','DEP','CFG','HighEntropyVA') { if (-not $on[$n]) { $missing += $n } }
        $status = if ($missing.Count -eq 0) { 'HARDENED' }
                  elseif (-not $on['ASLR'] -or -not $on['DEP']) { 'WEAK' }
                  else { 'PARTIAL' }

        $safeSeh = if ($info.PSObject.Properties['SafeSeh']) { "$($info.SafeSeh)".ToUpper() } else { 'N/A' }
        $gs      = if ($info.PSObject.Properties['StackCookie']) { "$($info.StackCookie)".ToUpper() } else { 'N/A' }
        [pscustomobject]@{
            DLL            = $pe.Name
            Arch           = $arch
            ASLR           = if ($on['ASLR']) { 'YES' } else { 'NO' }
            DEP            = if ($on['DEP'])  { 'YES' } else { 'NO' }
            CFG            = if ($on['CFG'])  { 'YES' } else { 'NO' }
            HighEntropyVA  = if ($on['HighEntropyVA']) { 'YES' } else { 'NO' }
            SafeSEH        = $safeSeh
            GS             = $gs
            ForceIntegrity = if ($on['ForceIntegrity']) { 'YES' } else { 'NO' }
            Status         = $status
            Missing        = ($missing -join ', ')
            DllCharacteristics = ('0x{0:X4}' -f $info.DllCharacteristics)
            Path           = $pe.FullName
        }
    }
}
