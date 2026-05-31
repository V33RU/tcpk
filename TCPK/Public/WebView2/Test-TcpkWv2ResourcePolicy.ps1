function Test-TcpkWv2ResourcePolicy {
<#
.SYNOPSIS
    G07. WebResourceRequested / external-resource fetch policy.

.DESCRIPTION
    Looks for AddWebResourceRequestedFilter + WebResourceRequested handlers.
    These let the host intercept and modify every fetch the WebView2 makes.
    Powerful for security (force HTTPS, allow-list origins) but also a place
    where bad code lives (always-allow handlers, response forgery).

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
        if ($text.Contains('WebResourceRequested') -or $text.Contains('AddWebResourceRequestedFilter')) {
            New-TcpkFinding -Module 'webview2' -RuleId 'webview2.resource-request-filter' `
                -Severity 'INFO' -Confidence 'Confirmed' `
                -Title "$($pe.Name) installs a WebView2 resource-request filter" `
                -File $pe.FullName -Evidence 'WebResourceRequested handler present' `
                -Description 'Triage aid. Confirm in ILSpy that the handler enforces the intended policy (e.g. force HTTPS, allow-list origins). Always-allow handlers create a one-line policy bypass.'
        }
    }
}
