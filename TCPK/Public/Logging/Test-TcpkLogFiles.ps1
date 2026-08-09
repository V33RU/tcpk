function Test-TcpkLogFiles {
<#
.SYNOPSIS
    H01. Log files under the target path: ACL + sensitive-content scan.

.DESCRIPTION
    Finds *.log / *.txt / *.json files in log-shaped subdirectories (logs, log,
    diagnostic, telemetry, trace). For each: an INFO inventory finding; MEDIUM
    when a sensitive-keyword pattern matches an actual value in the first ~500
    lines; MEDIUM for stack-trace / exception leakage.

    It also answers the LOG TAMPERING question, which is separate from what a
    log leaks: can a non-admin principal rewrite or delete the record after the
    fact. A log an attacker can edit is not evidence, and a log they can delete
    removes the trail of everything else they did. The ACL of each log file and
    of its containing directory is checked for Write / Modify / FullControl or
    Delete granted to Everyone, Authenticated Users, Users or INTERACTIVE.

    Directory permissions are reported separately and matter more than the file
    ones: on Windows, Delete on the PARENT lets a principal remove a file whose
    own ACL denies them everything, so a hardened log file inside a loose
    directory is still deletable.

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
            # Require the keyword to be followed by an actual value (>=6 chars, not a placeholder),
            # so prose like "user changed password" / "token refresh started" no longer fires HIGH.
            $placeholderRx = '(?i)(redact|example|sample|dummy|placeholder|changeme|your[_-]?|xxxx+|<[^>]*>|\$\{[^}]*\}|%[A-Za-z0-9_]+%|\bnull\b|\bnone\b)'
            $hits = @()
            foreach ($k in $sensitiveKw) {
                $km = [regex]::Match($head, "(?i)\b$k\b\s*[=:]\s*[`"']?([^\s`"',;<>&]{6,})")
                if ($km.Success -and ($km.Groups[1].Value -notmatch $placeholderRx)) { $hits += $k }
            }
            if ($hits.Count -gt 0) {
                New-TcpkFinding -Module 'logging' -RuleId 'log.sensitive-keywords' `
                    -Severity 'MEDIUM' -Confidence 'Inferred' `
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

        # ---- log TAMPERING: who can rewrite or delete this record? ----------------
        # Reported per file. AppendData without WriteData is deliberately NOT flagged:
        # append-only is the correct posture for a log and a legitimate design.
        try {
            $acl = Get-Acl -LiteralPath $f.FullName -ErrorAction Stop
            $bad = $acl.Access | Where-Object {
                $_.AccessControlType -eq 'Allow' -and
                $_.IdentityReference.Value -match '(?i)\b(Everyone|Authenticated Users|Users|INTERACTIVE)\b' -and
                $_.FileSystemRights -match 'FullControl|Modify|WriteData|Delete'
            }
            if ($bad) {
                $grant = (@($bad | ForEach-Object { "$($_.IdentityReference) -> $($_.FileSystemRights)" }) | Select-Object -Unique) -join '; '
                $canDelete = [bool](@($bad | Where-Object { $_.FileSystemRights -match 'FullControl|Delete' }).Count)
                New-TcpkFinding -Module 'logging' -RuleId 'log.tamperable-file' `
                    -Severity 'MEDIUM' -Confidence 'Confirmed' `
                    -Title "Log file is rewritable by a non-admin principal: $($f.Name)" `
                    -File $f.FullName -Evidence $grant `
                    -Cwe @('CWE-732','CWE-117') `
                    -AttributionBasis 'established-footprint' `
                    -Description ('A non-administrative principal holds write access to this log, so its ' +
                        'contents can be altered after the fact' + $(if ($canDelete) { ', and the grant includes Delete or FullControl, so the file can be removed entirely' } else { '' }) +
                        '. Any security event recorded here is repudiable: it cannot be relied on as ' +
                        'evidence of what happened, because the account that would be investigated can ' +
                        'edit it. This is a statement about the ACL that was read, not about whether ' +
                        'tampering has occurred.') `
                    -Fix ('Grant non-admin principals append-only access (AppendData without WriteData) ' +
                        'or none at all, and forward security-relevant events to a store the local user ' +
                        'cannot reach, such as the Windows Event Log or a remote collector.')
            }
        } catch { }
    }

    # ---- log TAMPERING: the containing directories ------------------------------
    # Checked once per directory rather than once per file, because Delete on the
    # parent defeats a hardened file ACL and reporting it per file would repeat the
    # same defect for every log in the folder.
    $logDirs = @($candidates | ForEach-Object { $_.DirectoryName } | Where-Object { $_ } | Select-Object -Unique)
    foreach ($d in $logDirs) {
        try {
            $dacl = Get-Acl -LiteralPath $d -ErrorAction Stop
            $dbad = $dacl.Access | Where-Object {
                $_.AccessControlType -eq 'Allow' -and
                $_.IdentityReference.Value -match '(?i)\b(Everyone|Authenticated Users|Users|INTERACTIVE)\b' -and
                $_.FileSystemRights -match 'FullControl|Modify|Delete|DeleteSubdirectoriesAndFiles|Write'
            }
            if ($dbad) {
                $dgrant = (@($dbad | ForEach-Object { "$($_.IdentityReference) -> $($_.FileSystemRights)" }) | Select-Object -Unique) -join '; '
                New-TcpkFinding -Module 'logging' -RuleId 'log.tamperable-directory' `
                    -Severity 'MEDIUM' -Confidence 'Confirmed' `
                    -Title "Log directory permits non-admin delete/rename: $(Split-Path $d -Leaf)" `
                    -File $d -Evidence $dgrant `
                    -Cwe @('CWE-732','CWE-117') `
                    -AttributionBasis 'established-footprint' `
                    -Description ('A non-administrative principal can create, rename or delete entries in ' +
                        'the log directory. On Windows this defeats a hardened ACL on the log FILE: ' +
                        'Delete or DeleteSubdirectoriesAndFiles on the parent removes the file regardless ' +
                        'of its own permissions, and write access allows a replacement file of the same ' +
                        'name. The audit trail in this directory is therefore not tamper-evident.') `
                    -Fix ('Restrict the log directory to SYSTEM and Administrators, granting the ' +
                        'application account only the append rights it needs. Keep security-relevant ' +
                        'events in the Windows Event Log or a remote collector as well.')
            }
        } catch { }
    }
}
