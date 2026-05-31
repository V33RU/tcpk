function Test-TcpkMsixComServers {
<#
.SYNOPSIS
    B06. COM server registrations in AppxManifest.xml.

.DESCRIPTION
    Packaged COM servers (com:ComServer / windows.comServer extensions)
    expose IPC endpoints accessible to other processes via CLSID. Each
    registered server is an attack surface: parser bugs in COM method
    arguments become cross-process attack primitives.

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

    $servers = @()
    foreach ($xpath in @(
        '//com:Extension',
        '//uap:Extension[@Category="windows.comServer"]',
        '//uap3:Extension[@Category="windows.comServer"]'
    )) {
        $nodes = $m.DocumentElement.SelectNodes($xpath, $nsm)
        if ($nodes) { $servers += $nodes }
    }

    foreach ($s in $servers) {
        $clsids = @()
        foreach ($c in $s.SelectNodes('.//*[local-name()="Class"]')) {
            if ($c.Id) { $clsids += $c.Id }
        }
        $evidence = if ($clsids) { "CLSIDs: $($clsids -join ', ')" } else { 'COM server extension declared' }
        New-TcpkFinding -Module 'manifest' -RuleId 'msix.com-server' `
            -Severity 'MEDIUM' -Confidence 'Confirmed' `
            -Title 'Packaged COM server declared in manifest' `
            -File $Path -Evidence $evidence `
            -Cwe @('CWE-668') `
            -Description 'The OS will route COM activation by CLSID to this app. Treat all method arguments as cross-process attacker-controllable.' `
            -Fix 'Audit each COM method for input validation; tighten LaunchPermission via DCOM config if applicable.'
    }
}
