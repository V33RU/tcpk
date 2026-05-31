function Test-TcpkDependencyCves {
<#
.SYNOPSIS
    A19. Parse *.deps.json and flag bundled NuGet deps with known CVEs.

.DESCRIPTION
    Walks every *.deps.json under the path, parses the libraries section,
    and matches each name@version against the offline CVE list in
    Data\secrets.json (cve_packages section).

.PARAMETER Path
    Folder (recursive), single .deps.json, or single .deps.json's parent.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $cves = (Get-TcpkData).cve_packages

    $files = if ((Get-Item -LiteralPath $Path).PSIsContainer) {
        Get-ChildItem -LiteralPath $Path -Recurse -File -Filter '*.deps.json' -ErrorAction SilentlyContinue
    } elseif ($Path -like '*.deps.json') {
        Get-Item -LiteralPath $Path
    } else { @() }

    $seen = @{}
    foreach ($f in $files) {
        try { $d = Get-Content -LiteralPath $f.FullName -Raw | ConvertFrom-Json } catch { continue }
        foreach ($k in $d.libraries.PSObject.Properties.Name) {
            if ($k -notmatch '^(.+)/(.+)$') { continue }
            $name = $matches[1]; $ver = $matches[2]
            $key  = "$name/$ver"
            if ($seen.ContainsKey($key)) { continue }
            $seen[$key] = $true

            foreach ($c in $cves) {
                if ($c.name -eq $name -and (Test-TcpkSemVerLt -A $ver -B $c.below)) {
                    New-TcpkFinding -Module 'static' -RuleId "deps.cve.$name" `
                        -Severity $c.severity -Confidence 'Confirmed' `
                        -Title "$name $ver - $($c.cve)" `
                        -File $f.FullName -Evidence "<$($c.below) required" `
                        -Cwe @('CWE-937') `
                        -Description $c.summary `
                        -Fix "Upgrade $name to >= $($c.below)."
                }
            }
        }
    }
}

# Helper -- not exported (defined in same file for locality).
function Test-TcpkSemVerLt {
    [CmdletBinding()] param([string]$A, [string]$B)
    $pa = ($A -split '[.\-+]') | ForEach-Object { if ($_ -match '^\d+') { [int]$matches[0] } else { 0 } }
    $pb = ($B -split '[.\-+]') | ForEach-Object { if ($_ -match '^\d+') { [int]$matches[0] } else { 0 } }
    for ($i = 0; $i -lt [Math]::Max($pa.Count, $pb.Count); $i++) {
        $x = if ($i -lt $pa.Count) { $pa[$i] } else { 0 }
        $y = if ($i -lt $pb.Count) { $pb[$i] } else { 0 }
        if ($x -lt $y) { return $true }
        if ($x -gt $y) { return $false }
    }
    return $false
}
