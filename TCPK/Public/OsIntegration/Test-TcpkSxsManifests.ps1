function Test-TcpkSxsManifests {
<#
.SYNOPSIS
    C09. Side-by-side activation context manifests + .local files.

.DESCRIPTION
    Inventories *.manifest and *.local files under the path. Presence of
    these enables SxS / app-local DLL redirection mechanisms that interact
    with the DLL search order. Each is INFO -- not itself a vulnerability,
    but feeds the DLL-hijack analysis.

.PARAMETER Path
    Folder.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { return }

    $files = Get-ChildItem -LiteralPath $Path -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Extension -in '.manifest','.local' }
    foreach ($f in $files) {
        $kind = if ($f.Extension -eq '.manifest') { 'sxs.manifest' } else { 'sxs.local-redirect' }
        New-TcpkFinding -Module 'os' -RuleId $kind `
            -Severity 'INFO' -Confidence 'Confirmed' `
            -Title "$($f.Name) ($($f.Extension)) present" `
            -File $f.FullName `
            -Description 'Interacts with the DLL search order. Cross-reference against the DLL-hijack analysis (Test-TcpkPInvokeSurface + Test-TcpkPeImports).'
    }
}
