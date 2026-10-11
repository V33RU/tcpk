function Test-TcpkDotLocalRedirection {
<#
.SYNOPSIS
    A52. DotLocal (.local) DLL redirection in the shipped tree.

.DESCRIPTION
    A file or directory named <module>.local next to a binary turns on Windows
    "DotLocal" redirection: for that binary, non-KnownDLLs are resolved from the
    application directory first, regardless of the normal search order. It exists for
    app-compat, but it is also a DLL-hijack primitive -- if the application directory is
    writable by a standard user, a planted DLL named like a system import loads into the
    binary. Shipping a .local redirection is unusual and worth surfacing; paired with a
    user-writable install directory (covered by install-dir.user-writable / acl.*) it is a
    load-order hijack.

.PARAMETER Path
    File or directory (recursive).

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { return }
    $root = if ((Get-Item -LiteralPath $Path).PSIsContainer) { $Path } else { Split-Path -Parent $Path }
    if (-not $root) { return }

    $items = @()
    try {
        $items = Get-ChildItem -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -like '*.local' }
    } catch { return }

    foreach ($it in $items) {
        # The redirection applies to the module whose name is the item name minus '.local'.
        $target = $it.Name.Substring(0, $it.Name.Length - 6)   # strip '.local'
        if ($target -notmatch '\.(exe|dll)$') { continue }      # only module redirections
        $kind = if ($it.PSIsContainer) { 'directory' } else { 'file' }
        New-TcpkFinding -Module 'static' -RuleId 'dllredirect.dotlocal' `
            -Severity 'MEDIUM' -Confidence 'Confirmed' `
            -Title "DotLocal DLL redirection present for $target" `
            -File $it.FullName `
            -Evidence "$kind '$($it.Name)' forces $target to resolve non-KnownDLLs from its own directory first" `
            -Cwe @('CWE-427') `
            -AttributionBasis 'established-footprint' -Subject $it.FullName `
            -Description 'A .local redirection shipped next to the binary makes Windows resolve that binary''s non-KnownDLL imports from the application directory before the normal search order. If the application directory is writable by a standard user (see install-dir.user-writable / acl.*), a DLL planted there under the name of a system import loads into the process. Even when the directory is admin-only, a shipped .local redirection is a legacy app-compat shim worth removing. Confirm whether the directory it redirects into is user-writable.' `
            -Fix 'Remove the .local redirection unless a documented app-compat need requires it; fix the underlying DLL resolution with a manifest or a full path instead, and keep the application directory admin-only.'
    }
}
