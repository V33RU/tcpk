# Sweep helpers: discover every install location of an app by name, so a single
# Invoke-TcpkSweep can audit them all (Electron / electron-builder / MSI apps tend to
# scatter across Programs / Local / Roaming / Program Files).

# Find top-level directories whose name matches *AppName* across the usual install
# roots. -Root overrides the default roots (used by the tests). Returns string[].
function Get-TcpkInstallLocations {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$AppName,
        [string[]]$Root
    )
    $roots = if ($Root) { $Root } else { @(
        (Join-Path $env:LOCALAPPDATA 'Programs'),
        $env:LOCALAPPDATA,
        $env:APPDATA,
        $env:ProgramFiles,
        ${env:ProgramFiles(x86)},
        $env:ProgramData
    ) }
    $needle = "*$AppName*"
    $out  = New-Object 'System.Collections.Generic.List[string]'
    $seen = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($r in ($roots | Where-Object { $_ -and (Test-Path -LiteralPath $_) })) {
        try {
            Get-ChildItem -LiteralPath $r -Directory -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -like $needle } |
                ForEach-Object {
                    $p = $_.FullName
                    if ($seen.Add($p.ToLowerInvariant())) { $out.Add($p) }
                }
        } catch { }
    }
    # ,wrap so PowerShell does not unroll a single-element result to a scalar
    return ,$out.ToArray()
}
