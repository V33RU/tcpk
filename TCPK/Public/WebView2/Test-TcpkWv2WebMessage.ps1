function Test-TcpkWv2WebMessage {
<#
.SYNOPSIS
    G02. WebMessageReceived handler presence (one-way JS-to-host bridge).

.DESCRIPTION
    Detects use of the WebView2 web-message bridge. Narrower than host-object
    exposure (only strings/JSON cross the boundary) but the host-side handler
    is still a parser of attacker-influenced input. Severity LOW; auditor
    must read the handler manually.

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

        if ($text.Contains('WebMessageReceived')) {
            New-TcpkFinding -Module 'webview2' -RuleId 'webview2.web-message-handler' `
                -Severity 'LOW' -Confidence 'Confirmed' `
                -Title 'WebView2 WebMessageReceived handler in use' `
                -File $pe.FullName -Evidence 'WebMessageReceived' `
                -Cwe @('CWE-20') `
                -Description 'The handler receives strings or JSON from embedded JS. Treat as attacker-controlled input. Look for command dispatch, file-path acceptance, or eval-style routing.' `
                -Fix 'Validate every incoming message strictly (schema validation, allow-listed commands). Never use the message contents to construct file paths, shell commands, or SQL.'
        }
    }
}
