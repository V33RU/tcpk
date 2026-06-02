function Test-TcpkComObjects {
<#
.SYNOPSIS
    E06. COM objects registered in HKCR\CLSID pointing at the target.

.DESCRIPTION
    Surveys HKCR\CLSID\{guid}\InprocServer32\(default) and
    LocalServer32\(default) for values that name the target product or
    install path. Each match is a cross-process IPC endpoint other processes
    can invoke by CLSID.

.PARAMETER NameLike
    Substring to match in the (default) value (case-insensitive).

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([string[]]$NameLike)

    if (-not (Assert-TcpkWindows 'Test-TcpkComObjects')) { return }

    $terms = Get-TcpkNameTerms -NameLike $NameLike
    if (-not $terms.Count) { return }

    # PSDrive enumeration of HKCR\CLSID (50k+ keys) is prohibitively slow.
    # Use reg.exe query with substring filter on value data -- native, completes in
    # seconds. /f takes a single pattern, so run it once per term and merge the lines.
    $regOut = New-Object 'System.Collections.Generic.List[string]'
    foreach ($term in $terms) {
        $o = & reg.exe query 'HKCR\CLSID' /s /f "$term" /d 2>$null
        if ($o -and $LASTEXITCODE -eq 0) { foreach ($l in $o) { $regOut.Add($l) } }
    }
    if (-not $regOut.Count) { return }

    $currentKey = $null
    $seen = @{}   # dedupe: the same CLSID can surface under more than one term query
    foreach ($line in $regOut) {
        if ($line -match '^HKEY_CLASSES_ROOT\\(.+)$') {
            $currentKey = $matches[1]
            continue
        }
        # Value line format: "    (Default)    REG_SZ    <value>" (with multiple spaces)
        if ($line -match '^\s+\(Default\)\s+REG_[A-Z_]+\s+(.+)$' -and $currentKey) {
            $val = $matches[1]
            if (-not (Test-TcpkTermMatch -Text $val -Terms $terms)) { continue }
            # Distinguish InprocServer32 vs LocalServer32 based on the current key path
            $serverType = if ($currentKey -match '\\InprocServer32') { 'InprocServer32' }
                          elseif ($currentKey -match '\\LocalServer32') { 'LocalServer32' }
                          else { continue }
            $clsid = if ($currentKey -match '^CLSID\\([^\\]+)') { $matches[1] } else { $currentKey }

            $dedupKey = "$serverType|$clsid"
            if ($seen.ContainsKey($dedupKey)) { continue }
            $seen[$dedupKey] = $true

            New-TcpkFinding -Module 'runtime' -RuleId "com.$serverType" `
                -Severity 'MEDIUM' -Confidence 'Confirmed' `
                -Title "COM $serverType CLSID $clsid -> $val" `
                -File $clsid -Evidence $val `
                -Cwe @('CWE-668') `
                -Description 'Other processes can activate this COM object by CLSID. Treat all method arguments as cross-process attacker-controllable.' `
                -Fix 'Audit each method for input validation; consider DCOM LaunchPermission constraints.'
        }
    }
}
