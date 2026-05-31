function Compare-TcpkRegistrySnapshot {
<#
.SYNOPSIS
    C18b. Diff two registry snapshots (Regshot-style) -- what the app changed.

.DESCRIPTION
    Compares a BEFORE and AFTER snapshot (from Save-TcpkRegistrySnapshot) and
    reports added/changed/removed keys and values. New values matching secret
    patterns are raised to HIGH (the app just persisted a secret).

.PARAMETER Before
    Path to the 'before' snapshot JSON.

.PARAMETER After
    Path to the 'after' snapshot JSON.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Before,
        [Parameter(Mandatory)][string]$After
    )
    if (-not (Test-Path $Before) -or -not (Test-Path $After)) { Write-Warning "Snapshot file(s) not found."; return }

    $b = Get-Content -LiteralPath $Before -Raw | ConvertFrom-Json
    $a = Get-Content -LiteralPath $After  -Raw | ConvertFrom-Json
    $bMap = @{}; foreach ($p in $b.PSObject.Properties) { $bMap[$p.Name] = $p.Value }
    $aMap = @{}; foreach ($p in $a.PSObject.Properties) { $aMap[$p.Name] = $p.Value }

    $secretRx = '(?i)(password\s*=|pwd\s*=|AccountKey=|-----BEGIN|\bAKIA[A-Z0-9]{16}\b|\beyJ[A-Za-z0-9_-]{10,}\.|token|secret|apikey)'

    foreach ($key in $aMap.Keys) {
        $aVals = $aMap[$key]
        if (-not $bMap.ContainsKey($key)) {
            New-TcpkFinding -Module 'os' -RuleId 'registry.diff.added-key' -Severity 'LOW' -Confidence 'Confirmed' `
                -Title "New registry key created by the app: $key" -File $key `
                -Evidence (($aVals.PSObject.Properties.Name) -join ', ') -Cwe @('CWE-15') `
                -Description 'The app created this key while running. Inspect its values.'
            continue
        }
        $bVals = $bMap[$key]
        foreach ($vp in $aVals.PSObject.Properties) {
            $name = $vp.Name; $aVal = "$($vp.Value)"
            $bVal = if ($bVals.PSObject.Properties[$name]) { "$($bVals.$name)" } else { $null }
            if ($null -eq $bVal) {
                $sev = if (($name -match $secretRx) -or ($aVal -match $secretRx)) { 'HIGH' } else { 'INFO' }
                $red = if ($aVal.Length -gt 12) { $aVal.Substring(0,6) + '...(' + $aVal.Length + ')' } else { $aVal }
                New-TcpkFinding -Module 'os' -RuleId 'registry.diff.added-value' -Severity $sev -Confidence 'Confirmed' `
                    -Title "App wrote new registry value: $name" -File "$key\$name" -Evidence $red -Cwe @('CWE-312') `
                    -Description 'The app persisted this value at runtime. If it is a credential/token/license, it is now stored (and may be readable by other users / survive uninstall).'
            }
            elseif ($bVal -ne $aVal) {
                $sev = if (($name -match $secretRx) -or ($aVal -match $secretRx)) { 'MEDIUM' } else { 'INFO' }
                New-TcpkFinding -Module 'os' -RuleId 'registry.diff.changed-value' -Severity $sev -Confidence 'Confirmed' `
                    -Title "App changed registry value: $name" -File "$key\$name" -Evidence 'value changed at runtime' `
                    -Description 'Confirm what the changed value represents.'
            }
        }
    }
}
