function Test-TcpkRegistryFootprint {
<#
.SYNOPSIS
    C06. Registry footprint of the app (HKCU and HKLM).

.DESCRIPTION
    Surveys both registry roots for the vendor / product name and emits INFO
    findings for each first-level key found. Triage aid -- shows where the
    app keeps its config so the auditor can manually review for sensitive
    values.

.PARAMETER NameLike
    Substring to match against the key path (case-insensitive). Examples:
    Acme, MyVendor, ProductName.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$NameLike)

    if (-not (Assert-TcpkWindows 'Test-TcpkRegistryFootprint')) { return }

    $roots = @(
        'HKCU:\Software', 'HKLM:\Software', 'HKLM:\SOFTWARE\WOW6432Node'
    )
    foreach ($r in $roots) {
        if (-not (Test-Path $r)) { continue }
        try {
            # PERF: find the vendor root key(s) at the top level, then recurse only
            # under those, instead of walking the entire SOFTWARE tree.
            $vendorRoots = Get-ChildItem -Path $r -ErrorAction SilentlyContinue |
                Where-Object { $_.PSChildName -like "*$NameLike*" }
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
}
