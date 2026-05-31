function Test-TcpkMsixCapabilities {
<#
.SYNOPSIS
    B01. Risky capabilities declared in AppxManifest.xml.

.DESCRIPTION
    Each capability is scored by impact. runFullTrust effectively opts the
    package out of the MSIX sandbox; broadFileSystemAccess gives access to
    every file the user can read.

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

    $risky = @{
        'runFullTrust'              = 'HIGH'
        'allowElevation'            = 'HIGH'
        'broadFileSystemAccess'     = 'HIGH'
        'elevatedFirewallRules'     = 'HIGH'
        'unvirtualizedResources'    = 'MEDIUM'
        'internetClientServer'      = 'MEDIUM'
        'privateNetworkClientServer'= 'MEDIUM'
        'appLicensing'              = 'MEDIUM'
        'enterpriseAuthentication'  = 'MEDIUM'
        'sharedUserCertificates'    = 'MEDIUM'
        'documentsLibrary'          = 'LOW'
        'picturesLibrary'           = 'LOW'
        'videosLibrary'             = 'LOW'
        'musicLibrary'              = 'LOW'
        'removableStorage'          = 'LOW'
    }

    $declared = @()
    if ($m.Package.Capabilities) {
        $declared = @($m.Package.Capabilities.ChildNodes | ForEach-Object { $_.Name })
    }
    foreach ($c in $declared) {
        if ($risky.ContainsKey($c)) {
            New-TcpkFinding -Module 'manifest' -RuleId "msix.capability.$c" `
                -Severity $risky[$c] -Confidence 'Confirmed' `
                -Title "Risky capability declared: $c" `
                -File $Path -Cwe @('CWE-250','CWE-269') `
                -Description 'AppxManifest.xml grants the package this OS-level permission at install time.' `
                -Fix 'Drop the capability or replace with a least-privilege equivalent.'
        }
    }
}
