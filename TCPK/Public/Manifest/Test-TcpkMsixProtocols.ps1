function Test-TcpkMsixProtocols {
<#
.SYNOPSIS
    B03. URI scheme handlers declared in AppxManifest.xml.

.DESCRIPTION
    Every <uap:Extension Category="windows.protocol"> registers a URI scheme
    the OS will hand to this app. That makes any input parsing in the app's
    protocol-activation handler an attacker-reachable code path -- e.g. via
    a crafted "myapp://..." link in a browser or doc.

.PARAMETER Path
    MSIX file or extracted directory.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $expanded = Expand-TcpkMsix -Path $Path
    $m = Read-TcpkAppxManifest -ExpandedPath $expanded
    if (-not $m) { return }
    $nsm = Get-TcpkAppxNsMgr -Manifest $m
    if (-not $nsm) { return }

    foreach ($node in $m.DocumentElement.SelectNodes('//uap:Extension[@Category="windows.protocol"]', $nsm)) {
        $scheme = if ($node.Protocol) { $node.Protocol.Name } else { '(unknown)' }
        New-TcpkFinding -Module 'manifest' -RuleId 'msix.protocol-handler' `
            -Severity 'MEDIUM' -Confidence 'Confirmed' `
            -Title "URI scheme handler declared: ${scheme}://" `
            -File $Path -Evidence $scheme `
            -Cwe @('CWE-20','CWE-94') `
            -Description "The OS will deliver ${scheme}:// URIs to this app's activation handler. Treat the URI string as attacker-controlled input." `
            -Fix 'Validate the scheme, host, and arguments strictly; reject anything not on an allow-list.'
    }
}
