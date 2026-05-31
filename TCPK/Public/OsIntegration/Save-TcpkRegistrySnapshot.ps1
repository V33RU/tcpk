function Save-TcpkRegistrySnapshot {
<#
.SYNOPSIS
    C18a. Regshot-style registry snapshot (before/after the app runs).

.DESCRIPTION
    Captures every key + value under the given root into a JSON snapshot file.
    Run it BEFORE launching the app, run the app, then run it AGAIN to a second
    file, and diff with Compare-TcpkRegistrySnapshot to see exactly what the app
    wrote (credentials, license blobs, config, persistence).

.PARAMETER OutFile
    Path to write the snapshot JSON.

.PARAMETER Root
    Registry root(s) to capture (default: HKCU:\SOFTWARE). Use a vendor key to
    keep it fast, e.g. 'HKCU:\SOFTWARE\Acme'.

.PARAMETER Depth
    Recursion depth (default 6).

.OUTPUTS
    [TcpkFinding] (one INFO confirming the snapshot)
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$OutFile,
        [string[]]$Root = @('HKCU:\SOFTWARE'),
        [int]$Depth = 6
    )
    if (-not (Assert-TcpkWindows 'Save-TcpkRegistrySnapshot')) { return }

    $snap = @{}
    foreach ($r in $Root) {
        if (-not (Test-Path $r)) { continue }
        $keys = @(Get-Item -LiteralPath $r -ErrorAction SilentlyContinue) + @(Get-ChildItem -LiteralPath $r -Recurse -Depth $Depth -ErrorAction SilentlyContinue)
        foreach ($k in $keys) {
            $kp = $k.PSPath -replace 'Microsoft\.PowerShell\.Core\\Registry::',''
            $vals = @{}
            try {
                $props = Get-ItemProperty -LiteralPath $k.PSPath -ErrorAction Stop
                foreach ($p in $props.PSObject.Properties) { if (-not $p.Name.StartsWith('PS')) { $vals[$p.Name] = "$($p.Value)" } }
            } catch { }
            $snap[$kp] = $vals
        }
    }
    Confirm-TcpkParentDir -FilePath $OutFile
    $snap | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $OutFile -Encoding UTF8

    New-TcpkFinding -Module 'os' -RuleId 'registry.snapshot' `
        -Severity 'INFO' -Confidence 'Confirmed' `
        -Title "Registry snapshot saved ($($snap.Count) keys)" `
        -File $OutFile -Evidence "roots: $($Root -join ', ')" `
        -Description 'Run this before AND after exercising the app, then Compare-TcpkRegistrySnapshot to see what the app persisted.'
}
