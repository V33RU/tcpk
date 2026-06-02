function Test-TcpkRegistryFootprint {
<#
.SYNOPSIS
    C06. Registry footprint of the app (HKCU, HKLM, HKCR, and Uninstall/ARP).

.DESCRIPTION
    Surveys the registry for the app's own keys and emits an INFO finding per
    match. Triage aid -- shows WHERE the app keeps its config so the auditor can
    review for sensitive values.

    Searches each term across HKCU/HKLM Software, WOW6432Node, and Software\Classes
    (== HKCR, for ProgIDs / file associations), and separately walks the
    Uninstall/ARP keys (which are keyed by a product-code GUID, not the name) and
    matches on the DisplayName / Publisher values. The discovered product code and
    install location are surfaced because they are strong follow-on search terms.

.PARAMETER NameLike
    One or more vendor / product / package search terms (substring, case-
    insensitive). Pass the set from Get-TcpkIdentityTerms for app-aware coverage.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string[]]$NameLike)

    if (-not (Assert-TcpkWindows 'Test-TcpkRegistryFootprint')) { return }

    $terms = @($NameLike | Where-Object { $_ })
    if (-not $terms.Count) { return }

    foreach ($r in (Get-TcpkRegistrySearchRoots)) {
        if (-not (Test-Path $r)) { continue }
        try {
            # PERF: match the vendor root key(s) at the top level, then recurse only
            # under those, instead of walking the entire (huge) SOFTWARE/Classes tree.
            $vendorRoots = Get-ChildItem -Path $r -ErrorAction SilentlyContinue |
                Where-Object { Test-TcpkTermMatch -Text $_.PSChildName -Terms $terms }
            $hits = foreach ($vr in $vendorRoots) {
                $vr
                Get-ChildItem -Path $vr.PSPath -Recurse -Depth 3 -ErrorAction SilentlyContinue
            }
            foreach ($h in $hits) {
                $values = $null
                try {
                    $props = Get-ItemProperty -LiteralPath $h.PSPath -ErrorAction Stop
                    $valueNames = $props.PSObject.Properties.Name | Where-Object { -not $_.StartsWith('PS') }
                    if ($valueNames) { $values = "values: $($valueNames -join ', ')" }
                } catch { }

                New-TcpkFinding -Module 'os' -RuleId 'registry.footprint' `
                    -Severity 'INFO' -Confidence 'Confirmed' `
                    -Title "Registry key: $($h.PSPath -replace 'Microsoft\.PowerShell\.Core\\Registry::','')" `
                    -File ($h.PSPath -replace 'Microsoft\.PowerShell\.Core\\Registry::','') `
                    -Evidence $values
            }
        } catch { }
    }

    # Uninstall / Add-Remove-Programs entries (keyed by product-code GUID).
    try {
        foreach ($u in (Get-TcpkUninstallMatches -Terms $terms)) {
            $ev = "product code: $($u.ProductCode)"
            if ($u.DisplayVersion)  { $ev += "; version: $($u.DisplayVersion)" }
            if ($u.Publisher)       { $ev += "; publisher: $($u.Publisher)" }
            if ($u.InstallLocation) { $ev += "; install: $($u.InstallLocation)" }
            New-TcpkFinding -Module 'os' -RuleId 'registry.uninstall-entry' `
                -Severity 'INFO' -Confidence 'Confirmed' `
                -Title "Uninstall entry: $($u.DisplayName)" `
                -File $u.KeyPath -Evidence $ev `
                -Description 'Add/Remove-Programs (Uninstall) registration for the app. The product-code GUID and install location are useful additional registry/filesystem search terms.'
        }
    } catch { }
}
