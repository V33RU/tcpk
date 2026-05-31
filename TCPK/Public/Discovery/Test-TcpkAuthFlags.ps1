function Test-TcpkAuthFlags {
<#
.SYNOPSIS
    A23. Client-side authentication / licensing boolean flags.

.DESCRIPTION
    Thick clients often gate features on a LOCAL boolean (IsLicensed, IsTrial,
    bypassAuth, IsUnlocked, ...). Because the check runs client-side, an attacker
    who decompiles/patches the binary or flips the value in memory unlocks the
    feature. This scans first-party assemblies for high-signal license/auth-gate
    identifiers (deliberately excluding framework noise like the standard
    IIdentity.IsAuthenticated property).

.PARAMETER Path
    File or directory.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    # High-signal CUSTOM gate names (not framework properties)
    $flags = @(
        'IsLicensed','IsTrial','IsActivated','IsRegistered','IsPremium','IsPro',
        'IsPaid','IsPaidUser','IsUnlocked','HasLicense','HasValidLicense','LicenseValid',
        'IsValidLicense','bypassAuth','skipAuth','SkipLogin','bypassLogin','IsAuthorized',
        'IsFullVersion','IsActivatedLicense','CheckLicense','ValidateLicense','IsExpired',
        'IsDemo','DemoMode','IsCracked','noLicenseCheck','licenseBypass'
    )

    foreach ($pe in Get-TcpkPeFiles -Path $Path) {
        if (Test-TcpkIsFrameworkFile $pe.Name) { continue }
        if (Test-TcpkIsNativeNoise $pe.Name)   { continue }
        $text = Read-TcpkAllText -Path $pe.FullName
        if (-not $text) { continue }
        if (-not $text.Contains('BSJB')) { continue }   # managed only

        $hits = @($flags | Where-Object { $text.Contains($_) } | Select-Object -Unique)
        if ($hits.Count -eq 0) { continue }

        New-TcpkFinding -Module 'static' -RuleId 'authflags.client-side-gate' `
            -Severity 'MEDIUM' -Confidence 'Inferred' `
            -Title "$($pe.Name) has client-side license/auth gate(s): $($hits -join ', ')" `
            -File $pe.FullName -Evidence ($hits -join ', ') -Cwe @('CWE-602','CWE-603') `
            -Description 'These boolean gates appear to run on the client. Decompile to confirm the feature/license is enforced LOCALLY -- if so, it is bypassable by patching the binary, flipping the value in memory, or returning true from the check.' `
            -Fix 'Move authorization / licensing decisions server-side; never trust a client-side boolean for access control.'
    }
}
