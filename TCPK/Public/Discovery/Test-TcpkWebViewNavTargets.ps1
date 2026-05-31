function Test-TcpkWebViewNavTargets {
<#
.SYNOPSIS
    A21. URLs that an embedded WebView2 will navigate to.

.DESCRIPTION
    Filters all extracted http(s) URLs against navigation-API call sites in
    the same binary. The intent: a URL string is "interesting from a
    WebView2 perspective" if it appears in a DLL that also references
    Navigate / NavigateToString / Source = / CoreWebView2 / WebView2.

    Severity MEDIUM by default, escalating to HIGH if the URL is a HTTP
    (not HTTPS) target (WebView2 loading mixed/cleartext content).

.PARAMETER Path
    File or directory.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $navIndicators = @('Navigate(','NavigateToString','CoreWebView2','WebView2','Source = "http')
    $urlRx = [regex]'https?://[A-Za-z0-9./?_=&%:#@~+\-]+'

    foreach ($pe in Get-TcpkPeFiles -Path $Path) {
        if (Test-TcpkIsFrameworkFile $pe.Name) { continue }
        $text = Read-TcpkAllText -Path $pe.FullName
        if (-not $text) { continue }

        $hasNav = $false
        foreach ($i in $navIndicators) {
            if ($text.Contains($i)) { $hasNav = $true; break }
        }
        if (-not $hasNav) { continue }

        $urls = @{}
        foreach ($m in $urlRx.Matches($text)) {
            $u = $m.Value
            # Filter out the schema URLs that ship in every .NET assembly
            if ($u -match '(?i)(microsoft|w3\.org|xmlsoap|schemas\.|github\.io|aka\.ms)') { continue }
            $urls[$u] = $true
        }

        foreach ($u in $urls.Keys) {
            $sev = if ($u -like 'http://*') { 'HIGH' } else { 'MEDIUM' }
            New-TcpkFinding -Module 'static' -RuleId 'webview2.nav-target' `
                -Severity $sev -Confidence 'Inferred' `
                -Title "$($pe.Name) may navigate WebView2 to $u" `
                -File $pe.FullName -Evidence $u `
                -Cwe @('CWE-829') `
                -Description 'WebView2 loading content from an external origin imports that origin into the renderer process trust boundary. Verify the URL is HTTPS and pinned, and that WebMessageReceived is not used to elevate input.' `
                -Fix 'Pin the URL set; reject mixed-content; constrain WebView2 with SetVirtualHostNameToFolderMapping for local content.'
        }
    }
}
