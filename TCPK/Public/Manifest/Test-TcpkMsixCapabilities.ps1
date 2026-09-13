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
        # DeviceCapability entries. These sit in the same Capabilities element and are
        # returned by the same walk, but had no severity here so they were ignored even
        # once the name resolved. Privacy-sensitive hardware is graded above physical
        # channels because consent is user-visible and the data is personal.
        'webcam'                    = 'MEDIUM'
        'microphone'                = 'MEDIUM'
        'location'                  = 'MEDIUM'
        'bluetooth'                 = 'LOW'
        'serialcommunication'       = 'LOW'
        'usb'                       = 'LOW'
        'humaninterfacedevice'      = 'LOW'
        'pointOfService'            = 'LOW'
    }

    $declared = @()
    if ($m.Package.Capabilities) {
        # Read the Name ATTRIBUTE, not the element name.
        #
        # $_.Name on an XmlElement is the .NET XmlNode.Name property, which returns the
        # qualified TAG name: 'Capability', 'rescap:Capability', 'uap:Capability',
        # 'DeviceCapability'. PowerShell's XML adapter gives intrinsic members precedence
        # over a same-named attribute, so the capability identity ('runFullTrust',
        # 'broadFileSystemAccess', 'bluetooth') lives only in the Name attribute and was
        # never being read. Every lookup below keys on that identity, so a tag name matches
        # nothing. GetAttribute is used first and $_.Name kept as a fallback so this is
        # correct regardless of which semantics the host applies. Comment and whitespace
        # nodes have no GetAttribute; they throw and are dropped by the filter.
        $declared = @($m.Package.Capabilities.ChildNodes | ForEach-Object {
            $capName = ''
            try { $capName = "$($_.GetAttribute('Name'))" } catch { $capName = '' }
            if (-not $capName) { try { $capName = "$($_.Name)" } catch { $capName = '' } }
            $capName
        } | Where-Object { $_ })
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
