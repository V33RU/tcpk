function Test-TcpkMsixAppInstaller {
<#
.SYNOPSIS
    B05. AppInstaller (auto-update) declaration in AppxManifest.xml.

.DESCRIPTION
    The uap5:appInstaller extension lets the OS auto-update the package
    from a URL on a schedule. If present, the update source URL is part of
    the attack surface: anyone who can write to that URL can push code.

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

    $aiNodes = $m.DocumentElement.SelectNodes('//uap5:Extension[@Category="windows.appInstaller"]', $nsm)
    if (-not $aiNodes -or $aiNodes.Count -eq 0) { return }

    foreach ($n in $aiNodes) {
        New-TcpkFinding -Module 'manifest' -RuleId 'msix.app-installer' `
            -Severity 'MEDIUM' -Confidence 'Confirmed' `
            -Title 'AppInstaller auto-update extension declared' `
            -File $Path -Evidence $n.OuterXml `
            -Cwe @('CWE-494','CWE-345') `
            -Description 'The OS will auto-fetch updates from the configured URL. The integrity of update content depends entirely on TLS + signature on that URL.' `
            -Fix 'Confirm the update URL is HTTPS to a publisher-controlled host; rotate publisher cert if leaked.'
    }
}
