function Test-TcpkLogFiles {
<#
.SYNOPSIS
    H01. Log files under the target path: ACL + sensitive-content scan.

.DESCRIPTION
    Finds *.log / *.txt files in log-shaped subdirectories (logs, log, Logs,
    diagnostic, telemetry). For each: emits an INFO finding listing the
    file; HIGH if a known-sensitive-keyword pattern matches the first ~50 KB
    of content.

.PARAMETER Path
    Folder.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { return }

    $sensitiveKw = @(
        'password','token','bearer','authkey','accountkey','authorization',
        'cookie','session','jwt','client_secret','api_key','apikey','x-api-key'
    )

    $candidates = Get-ChildItem -LiteralPath $Path -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object {
            ($_.Extension -in '.log','.txt','.json') -and
            ($_.FullName -match '(?i)\\(log|logs|diagnostic|telemetry|trace)\\' -or $_.Name -match '(?i)\.log$|log\.|trace\.')
        }
    foreach ($f in $candidates) {
        New-TcpkFinding -Module 'logging' -RuleId 'log.file-present' `
            -Severity 'INFO' -Confidence 'Confirmed' `
            -Title "Log file: $($f.Name)" `
            -File $f.FullName -Evidence "size=$($f.Length) modified=$($f.LastWriteTime)"

        # Quick scan first 50 KB for sensitive keywords
        try {
            $head = Get-Content -LiteralPath $f.FullName -TotalCount 500 -ErrorAction Stop | Out-String
            $hits = @()
            foreach ($k in $sensitiveKw) {
                if ($head -match "(?i)$k") { $hits += $k }
            }
            if ($hits.Count -gt 0) {
                New-TcpkFinding -Module 'logging' -RuleId 'log.sensitive-keywords' `
                    -Severity 'HIGH' -Confidence 'Inferred' `
                    -Title "Sensitive keywords in $($f.Name): $($hits -join ', ')" `
                    -File $f.FullName -Evidence "first 500 lines contain: $($hits -join ', ')" `
                    -Cwe @('CWE-532') `
                    -Description 'Plain text logs containing credentials, tokens, or session material are a direct credential exposure to anyone reading the log.' `
                    -Fix 'Redact sensitive fields before logging. Centralize logging through a helper that strips known patterns.'
            }

            # Stack-trace / unhandled-exception leakage: exposes internal types,
            # file paths, and line numbers (info disclosure; aids exploitation).
            $stMatch = [regex]::Match($head, '(?im)(^\s*at\s+[\w\.<>`+]+\([^\r\n]*\)\s*$|--- End of (inner )?stack trace|\.cs:line\s+\d+|System\.[\w\.]+Exception\b|Traceback \(most recent call last\)|\bat [\w\.$]+\([\w\. ,]*\) in .+:\d+)')
            if ($stMatch.Success) {
                $ev = $stMatch.Value.Trim(); if ($ev.Length -gt 120) { $ev = $ev.Substring(0,120) + ' ...' }
                New-TcpkFinding -Module 'logging' -RuleId 'log.stack-trace' `
                    -Severity 'MEDIUM' -Confidence 'Inferred' `
                    -Title "Stack trace / exception detail in $($f.Name)" `
                    -File $f.FullName -Evidence $ev `
                    -Cwe @('CWE-209','CWE-497') `
                    -Description 'The log contains stack traces / exception detail (internal namespaces, source file paths, line numbers). In a production build this is information disclosure that maps the codebase and aids exploitation.' `
                    -Fix 'Disable verbose/stack-trace logging in release builds; log a correlation id instead and keep full detail server-side only.'
            }
        } catch { }
    }
}
