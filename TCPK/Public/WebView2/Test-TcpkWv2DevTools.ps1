function Test-TcpkWv2DevTools {
<#
.SYNOPSIS
    G05. WebView2 DevTools enabled in shipped build.

.DESCRIPTION
    AreDevToolsEnabled = true ships DevTools support to production users.
    Lets anyone with local interactive access open F12 and inspect the
    embedded browser -- including any session tokens cached in WebView2
    storage, any host-object surface, the page DOM, etc.

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

        if ($text -match 'AreDevToolsEnabled\s*=\s*true') {
            New-TcpkFinding -Module 'webview2' -RuleId 'webview2.devtools-enabled' `
                -Severity 'MEDIUM' -Confidence 'Confirmed' `
                -Title 'WebView2 DevTools enabled in shipped build' `
                -File $pe.FullName -Evidence $matches[0] `
                -Cwe @('CWE-489','CWE-1188') `
                -Description 'Anyone with local UI access can open DevTools and inspect tokens, DOM, and the host-object surface.' `
                -Fix 'Disable DevTools in release builds: CoreWebView2.Settings.AreDevToolsEnabled = false.'
        }
    }
}
