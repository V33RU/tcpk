function Test-TcpkWv2ScriptInjection {
<#
.SYNOPSIS
    G06. AddScriptToExecuteOnDocumentCreated -- script auto-injection.

.DESCRIPTION
    Inventories use of AddScriptToExecuteOnDocumentCreated and
    ExecuteScriptAsync. These run JS in every navigation -- their content
    is part of the trust boundary. If the script string is built from
    untrusted data, the result is in-renderer XSS.

.PARAMETER Path
    File or directory.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $needles = @('AddScriptToExecuteOnDocumentCreated','ExecuteScriptAsync','AddScriptToExecuteOnDocumentCreatedAsync')

    foreach ($pe in Get-TcpkPeFiles -Path $Path) {
        if (Test-TcpkIsFrameworkFile $pe.Name) { continue }
        $text = Read-TcpkAllText -Path $pe.FullName
        if (-not $text) { continue }
        $hits = @()
        foreach ($n in $needles) {
            $c = ([regex]::Matches($text, [regex]::Escape($n))).Count
            if ($c -gt 0) { $hits += "$n(x$c)" }
        }
        if ($hits.Count -eq 0) { continue }

        New-TcpkFinding -Module 'webview2' -RuleId 'webview2.script-injection' `
            -Severity 'MEDIUM' -Confidence 'Inferred' `
            -Title "$($pe.Name) injects scripts into the WebView2" `
            -File $pe.FullName -Evidence ($hits -join ', ') `
            -Cwe @('CWE-79','CWE-94') `
            -Description 'These methods execute JS in the WebView2 renderer. Confirm in ILSpy that the script string is a constant; any string concatenation with non-static data is an XSS sink.' `
            -Fix 'Pass values via PostWebMessageAsJson and let the JS read them; never concatenate untrusted strings into script source.'
    }
}
