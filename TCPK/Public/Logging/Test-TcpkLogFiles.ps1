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
        } catch { }
    }
}
