function Test-TcpkWv2VirtualHost {
<#
.SYNOPSIS
    G04. SetVirtualHostNameToFolderMapping (local content as a web origin).

.DESCRIPTION
    SetVirtualHostNameToFolderMapping turns a local folder into a virtual
    https:// origin inside WebView2. The local files then have web-origin
    privileges. If the mapped folder is user-writable, attacker-planted
    HTML/JS runs with that origin's privileges in the WebView.

.PARAMETER Path
    File or directory.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    foreach ($pe in Get-TcpkPeFiles -Path $Path) {
        if (Test-TcpkIsFrameworkFile $pe.Name) { continue }
        $text = Read-TcpkAllText -Path $pe.FullName
        if (-not $text) { continue }

        if ($text.Contains('SetVirtualHostNameToFolderMapping')) {
            New-TcpkFinding -Module 'webview2' -RuleId 'webview2.virtual-host-mapping' `
                -Severity 'MEDIUM' -Confidence 'Confirmed' `
                -Title 'WebView2 SetVirtualHostNameToFolderMapping in use' `
                -File $pe.FullName -Evidence 'SetVirtualHostNameToFolderMapping' `
                -Cwe @('CWE-829','CWE-732') `
                -Description 'Local folder is exposed as a web origin to the embedded browser. If that folder is user-writable, attacker-planted content runs as the virtual origin.' `
                -Fix 'Confirm the mapped folder is not user-writable. Use CrossOriginResourceAccessKind.Deny on the host to prevent leaks.'
        }
    }
}
