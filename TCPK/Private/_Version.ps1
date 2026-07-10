# Numeric semver comparison shared across the CVE / NVD / EOL paths.
# Compares each dotted component as an INTEGER, so 3.0.21 is correctly NEWER than 3.0.8
# (a lexical string compare would rank "3.0.21" < "3.0.8" because '2' < '8').
# Private helper (was formerly co-located in Test-TcpkDependencyCves, now removed).
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
