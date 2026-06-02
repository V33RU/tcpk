function Compare-TcpkFileSnapshot {
<#
.SYNOPSIS
    C19b. Diff two file-system snapshots (Regshot-style) - what the app changed on disk.

.DESCRIPTION
    Compares a BEFORE and AFTER snapshot (from Save-TcpkFileSnapshot) and reports
    files the app created, modified (SHA-256 changed), or removed at runtime.
    Severity is raised for executable/script drops (DLL planting / persistence) and
    for new files whose name suggests credentials/tokens.

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
    if (-not (Test-Path -LiteralPath $Before) -or -not (Test-Path -LiteralPath $After)) {
        Write-Warning 'Snapshot file(s) not found.'; return
    }

    $b = Get-Content -LiteralPath $Before -Raw | ConvertFrom-Json
    $a = Get-Content -LiteralPath $After  -Raw | ConvertFrom-Json
    $bMap = @{}; foreach ($p in $b.PSObject.Properties) { $bMap[$p.Name] = $p.Value }
    $aMap = @{}; foreach ($p in $a.PSObject.Properties) { $aMap[$p.Name] = $p.Value }

    $execRx   = '(?i)\.(exe|dll|sys|ocx|cpl|scr|ps1|psm1|bat|cmd|vbs|js|jar|msi|com)$'
    $secretRx = '(?i)(cred|password|secret|token|\.key$|\.pem$|\.pfx$|license|session|\.sqlite|\.db$)'

    foreach ($path in $aMap.Keys) {
        $av = $aMap[$path]
        if (-not $bMap.ContainsKey($path)) {
            $sev = 'LOW'
            if ($path -match $execRx)        { $sev = 'HIGH' }
            elseif ($path -match $secretRx)  { $sev = 'MEDIUM' }
            New-TcpkFinding -Module 'os' -RuleId 'fs.diff.added-file' -Severity $sev -Confidence 'Confirmed' `
                -Title "App created file at runtime: $(Split-Path -Leaf $path)" -File $path `
                -Evidence "size=$($av.Size) sha256=$($av.Sha256)" -Cwe @('CWE-377','CWE-312') `
                -Description 'The app wrote this file while running. An executable/script drop can be a persistence or DLL-planting vector; a credential/DB drop is data-at-rest exposure. Inspect the contents and the directory ACL.'
            continue
        }
        $bv = $bMap[$path]
        if ("$($av.Sha256)" -and "$($bv.Sha256)" -and "$($av.Sha256)" -ne "$($bv.Sha256)") {
            $sev = if ($path -match $execRx) { 'HIGH' } else { 'INFO' }
            New-TcpkFinding -Module 'os' -RuleId 'fs.diff.changed-file' -Severity $sev -Confidence 'Confirmed' `
                -Title "App modified file at runtime: $(Split-Path -Leaf $path)" -File $path `
                -Evidence "sha256 $($bv.Sha256) -> $($av.Sha256)" -Cwe @('CWE-494') `
                -Description 'The file contents changed while the app ran. A modified executable/DLL is especially notable (self-update / tamper). Confirm the change is expected and integrity-protected.'
        }
    }
    foreach ($path in $bMap.Keys) {
        if (-not $aMap.ContainsKey($path)) {
            New-TcpkFinding -Module 'os' -RuleId 'fs.diff.removed-file' -Severity 'INFO' -Confidence 'Confirmed' `
                -Title "App removed file at runtime: $(Split-Path -Leaf $path)" -File $path `
                -Evidence 'present before, absent after' `
                -Description 'The app deleted this file while running (e.g. temp cleanup). Note for completeness.'
        }
    }
}
