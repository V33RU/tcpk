function Test-TcpkDiagConfig {
<#
.SYNOPSIS
    Detect shipped diagnostic/logging framework configs with exposure risk.

.DESCRIPTION
    Thick-client applications often ship with logging framework configuration
    files (NLog, log4net, Serilog, ELMAH, Enterprise Library) that were set up
    during development and never hardened for production.  Common issues:

      - Log output to a world-readable directory (C:\Temp, %APPDATA%, the
        install dir) where any local user can harvest logged secrets/PII.
      - Verbose/Debug log level in production, which logs sensitive data
        (credentials, tokens, PII) that a Trace level would suppress.
      - Internal logging targets (SMTP, database connection strings, Syslog
        endpoints) that leak infrastructure details.

    This is a STATIC check -- it reads the config files shipped with the
    application and looks for insecure patterns.

.PARAMETER Path
    File or directory to scan.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $item = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
    if (-not $item) { return }
    $root = if ($item.PSIsContainer) { $item.FullName } else { $item.DirectoryName }

    $diagFiles = @(
        'nlog.config','nlog.xml',
        'log4net.config','log4net.xml',
        'elmah.axd','elmah.config',
        'serilog.json',
        'logging.config','logging.json',
        'loggingConfiguration.config'
    )
    $diagSet = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    foreach ($d in $diagFiles) { [void]$diagSet.Add($d) }

    $diagPatterns = @(
        '(?i)<nlog[\s>]',
        '(?i)<log4net[\s>]',
        '(?i)<loggingConfiguration[\s>]',
        '(?i)"Serilog"',
        '(?i)elmah[\s>]',
        '(?i)<system\.diagnostics[\s>]'
    )

    $seen = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)

    foreach ($f in Get-ChildItem -LiteralPath $root -Recurse -File -ErrorAction SilentlyContinue) {
        $ext = $f.Extension.ToLowerInvariant()
        $isDiagFile = $diagSet.Contains($f.Name)
        $isConfigFile = $ext -in '.config','.xml','.json'
        if (-not $isDiagFile -and -not $isConfigFile) { continue }
        if ($f.Length -gt 2MB) { continue }

        try { $raw = Get-Content -LiteralPath $f.FullName -Raw -ErrorAction Stop } catch { continue }
        if (-not $raw) { continue }

        $isDiag = $isDiagFile
        if (-not $isDiag) {
            foreach ($p in $diagPatterns) {
                if ($raw -match $p) { $isDiag = $true; break }
            }
        }
        if (-not $isDiag) { continue }

        $relPath = $f.FullName
        if ($relPath.StartsWith($root, [System.StringComparison]::OrdinalIgnoreCase)) {
            $relPath = $relPath.Substring($root.Length).TrimStart('\')
        }

        New-TcpkFinding -Module 'static' -RuleId 'diag.config-shipped' `
            -Severity 'LOW' -Confidence 'Confirmed' `
            -Title "Diagnostic logging config shipped: $relPath" `
            -File $f.FullName `
            -Evidence "file=$($f.Name)" `
            -Cwe @('CWE-532') `
            -Description ('A logging framework configuration file is shipped with the application. ' +
                'Review it for verbose log levels, sensitive data in log output, and accessible ' +
                'log file paths.') `
            -Fix 'Remove diagnostic configs from production builds or harden log levels and output paths.'

        if ($raw -match '(?i)(minlevel|level|minimumLevel)\s*[=:]\s*["\x27]?(Trace|Debug|Verbose|ALL)') {
            $levelMatch = $matches[0] -replace '[\r\n]',''
            New-TcpkFinding -Module 'static' -RuleId 'diag.verbose-level' `
                -Severity 'MEDIUM' -Confidence 'Inferred' `
                -Title "Verbose logging level in production: $relPath" `
                -File $f.FullName `
                -Evidence $levelMatch.Substring(0, [Math]::Min(120, $levelMatch.Length)) `
                -Cwe @('CWE-532','CWE-209') `
                -Description ('The logging config sets a verbose log level (Trace/Debug/ALL) ' +
                    'in production. Verbose logging often captures credentials, tokens, session ' +
                    'IDs, PII, and stack traces that should not be written to disk.') `
                -Fix 'Set the minimum log level to Warning or Error for production builds.'
        }

        $insecurePaths = @()
        $pathRx = '(?i)\b(fileName|file|path|folder|logDirectory|logFile)\s*[=:]\s*["\x27]?([^"\x27<>\r\n]+)'
        $pathMatches = [regex]::Matches($raw, $pathRx)
        foreach ($pm in $pathMatches) {
            $logPath = $pm.Groups[2].Value.Trim()
            if ($logPath -match '(?i)(\\temp\\|\\tmp\\|%temp%|%tmp%|/tmp/|\\logs?\\|\\debug\\)') {
                $insecurePaths += $logPath
            }
        }
        if ($insecurePaths.Count -gt 0) {
            New-TcpkFinding -Module 'static' -RuleId 'diag.insecure-log-path' `
                -Severity 'MEDIUM' -Confidence 'Inferred' `
                -Title "Logs written to accessible directory: $relPath" `
                -File $f.FullName `
                -Evidence (($insecurePaths | Select-Object -First 3) -join '; ') `
                -Cwe @('CWE-532','CWE-538') `
                -Description ('The logging config writes log files to a commonly-accessible ' +
                    'directory (temp, logs, debug). Any local user may be able to read logged ' +
                    'data including credentials and PII.') `
                -Fix 'Write logs to a directory with restricted ACLs (e.g. ProgramData\<app>\logs with admin-only access).'
        }

        if ($raw -match '(?i)(smtp|mail|SmtpClient|mailSettings|<smtp\b)') {
            New-TcpkFinding -Module 'static' -RuleId 'diag.smtp-target' `
                -Severity 'LOW' -Confidence 'Inferred' `
                -Title "Logging config references SMTP/mail target: $relPath" `
                -File $f.FullName `
                -Evidence 'SMTP or mail configuration in logging config' `
                -Cwe @('CWE-200') `
                -Description ('The logging config contains SMTP/mail settings, potentially ' +
                    'leaking infrastructure details (mail server, credentials) and sending ' +
                    'log data (which may include secrets) over email.') `
                -Fix 'Remove SMTP targets from production logging configs or ensure credentials are not embedded.'
        }
    }
}
