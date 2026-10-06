function Test-TcpkWv2HostObjects {
<#
.SYNOPSIS
    G01. AddHostObjectToScript -- .NET object exposure to JS.

.DESCRIPTION
    Detects code that exposes a .NET host object to embedded JS via the
    WebView2 host-object bridge. ANY exposure is a serious attack surface
    because attacker-controlled JS can call into the exposed object's full
    public API.

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

        if ($text.Contains('AddHostObjectToScript')) {
            New-TcpkFinding -Module 'webview2' -RuleId 'webview2.add-host-object' `
                -Severity 'HIGH' -Confidence 'Confirmed' `
                -Title 'WebView2 AddHostObjectToScript usage' `
                -File $pe.FullName -Evidence 'AddHostObjectToScript' `
                -Cwe @('CWE-749','CWE-1188') `
                -Description 'Exposes a .NET object to embedded JS. If the WebView2 ever loads attacker-influenced content (compromised CDN, mixed-origin frame, untrusted file://), JS can call the host object''s full public API.' `
                -Fix 'Audit the exposed object surface and reduce to the minimum methods needed. Prefer the narrower WebMessageReceived bridge for one-way data passing.'
        }
        if ($text -match 'AreHostObjectsAllowed\s*=\s*true') {
            New-TcpkFinding -Module 'webview2' -RuleId 'webview2.are-host-objects-allowed' `
                -Description 'WebView2 has AreHostObjectsAllowed set to true, so web content in the control can call the native host objects the app exposed. If any navigable content is remote or attacker-influenced, that web-to-native bridge is a code-execution path into the host process.' `
                -Severity 'HIGH' -Confidence 'Confirmed' `
                -Title 'WebView2 AreHostObjectsAllowed=true' `
                -File $pe.FullName -Evidence $matches[0] `
                -Cwe @('CWE-749')
        }
    }
}
