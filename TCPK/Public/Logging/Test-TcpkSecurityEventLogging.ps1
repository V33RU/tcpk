function Test-TcpkSecurityEventLogging {
<#
.SYNOPSIS
    C36. Missing security event logging -- absence of audit-trail APIs in
    binaries and source files that perform authentication or authorization.

.DESCRIPTION
    Security-sensitive operations (login, logout, privilege change, admin action,
    access denial) must be logged to support incident response and forensic
    analysis. Applications that perform these operations without writing to
    the Windows Event Log or a structured audit log leave no trace of attacks.

    Binary check:
      Native PEs: if the binary imports authentication/privilege APIs
      (LogonUser, LsaLogonUser, OpenProcessToken + AdjustTokenPrivileges,
      NetUserGetInfo) but does NOT import any Windows Event Log write API
      (ReportEvent, EventRegister, EventWrite, RegisterEventSource),
      flag as missing security logging.

      Managed .NET: if the binary references credential/auth class strings
      (PasswordValidator, ClaimsPrincipal, WindowsPrincipal) but does not
      reference EventLog, EventSource, ILogger, or AuditLog, flag similarly.

    Source code check:
      Scans .cs/.vb/.java files for method definitions whose name matches
      an authentication/authorization pattern (Login, Authenticate, Logout,
      CheckPassword, VerifyCredentials, Authorize, GrantAccess, DenyAccess)
      and checks whether a logging call appears inside that method body
      (within the next 30 lines before the next method definition).
      Missing log call = Inferred MEDIUM.

    Configuration check:
      appsettings.json: if a Logging section is present but the minimum level
      for SecurityAudit or System.Security is Warning or higher (i.e., audit
      events at Information level would be suppressed), flag Inferred LOW.

.PARAMETER Path
    Root directory of the application to scan.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Assert-TcpkWindows 'Test-TcpkSecurityEventLogging')) { return }
    if (-not (Test-Path $Path)) { return }

    # ---- Binary: native PE import check ----
    # Auth APIs that indicate the binary handles credential or privilege operations.
    $authApiRx   = '(?i)\b(LogonUserW?A?|LsaLogonUser|NtLmSsp|OpenProcessToken|AdjustTokenPrivileges|' +
                   'CreateProcessAsUser|CreateProcessWithLogonW|ImpersonateLoggedOnUser|' +
                   'NetUserGetInfo|NetLogonGetDomainInfo)\b'
    # Security event-logging write APIs.
    $secLogApiRx = '(?i)\b(ReportEvent|RegisterEventSource|EventRegister|EventWrite|' +
                   'EventWriteTransfer|EvtCreateBookmark)\b'

    foreach ($pe in Get-TcpkPeFiles -Path $Path) {
        if (-not (Test-TcpkIsFirstParty -Name $pe.Name -SizeBytes $pe.Length -Path $pe.FullName)) { continue }
        $text = Read-TcpkAllText -Path $pe.FullName
        if (-not $text) { continue }
        $isManaged = $text.Contains('BSJB')

        if (-not $isManaged) {
            # Native PE: check for auth imports without event-log write imports
            $hasAuthApi   = $text -match $authApiRx
            $hasSecLogApi = $text -match $secLogApiRx
            if ($hasAuthApi -and -not $hasSecLogApi) {
                $authMatch = [regex]::Match($text, $authApiRx).Value
                New-TcpkFinding -Module 'logging' -RuleId 'security-logging.native-no-event-log' `
                    -Severity 'LOW' -Confidence 'Inferred' `
                    -Title "$($pe.Name) uses auth/privilege API without EventLog write API" `
                    -File $pe.FullName `
                    -Evidence "Auth API: $authMatch; EventLog write API: absent" `
                    -Cwe @('CWE-778','CWE-223') `
                    -Description ("The native binary imports an authentication or privilege API " +
                        "($authMatch) but no Windows Event Log write function " +
                        "(ReportEvent, EventRegister, EventWrite) was found. " +
                        "Security-sensitive operations without event logging leave no forensic " +
                        "trail for SOC/IR teams. Verify that logging occurs via a different " +
                        "mechanism (syslog, file, ETW from the host) before flagging as exploitable. " +
                        "This is an absence-of-evidence finding -- the burden is on the app to " +
                        "demonstrate audit logging exists for authentication events.") `
                    -Fix ('Add EventLog.WriteEntry or RegisterEventSource + ReportEvent calls at ' +
                        'each authentication success and failure path, privilege elevation, and ' +
                        'access denial. Write to the Application log under the product''s event ' +
                        'source name with event IDs that distinguish success from failure.')
            }
        } else {
            # Managed .NET: check class/method name strings in the metadata heap
            $authManagedRx   = '(?i)(PasswordValidator|ClaimsPrincipal|WindowsPrincipal|' +
                               'ValidateCredentials|AuthenticateUser|CheckPassword|VerifyToken)'
            $secLogManagedRx = '(?i)(EventLog\.WriteEntry|EventSource|ILogger|AuditLog|' +
                               'LogSecurityEvent|SecurityAudit)'
            $hasAuthM   = $text -match $authManagedRx
            $hasSecLogM = $text -match $secLogManagedRx
            if ($hasAuthM -and -not $hasSecLogM) {
                $authMatch = [regex]::Match($text, $authManagedRx).Value
                New-TcpkFinding -Module 'logging' -RuleId 'security-logging.managed-no-audit' `
                    -Severity 'LOW' -Confidence 'Inferred' `
                    -Title "$($pe.Name) references auth types without audit logging types" `
                    -File $pe.FullName `
                    -Evidence "Auth type: $authMatch; EventLog/ILogger audit API: absent" `
                    -Cwe @('CWE-778','CWE-223') `
                    -Description ("The .NET binary's metadata heap contains a reference to an " +
                        "authentication or credential-validation type ($authMatch) but no reference " +
                        "to a security logging type (EventLog.WriteEntry, EventSource, ILogger, AuditLog). " +
                        "Confirm by decompiling the authentication code paths and checking whether " +
                        "each success and failure is logged with enough context for incident response " +
                        "(timestamp, user, source IP, result).") `
                    -Fix ('Inject an ILogger<T> or EventLog into the authentication service. Log ' +
                        'every authentication attempt (success and failure) with: username, timestamp, ' +
                        'source IP (if available), and result. Use structured logging with consistent ' +
                        'EventIds for SIEM correlation.')
            }
        }
    }

    # ---- Source-level: auth method without log call ----
    $srcFiles = @(Get-ChildItem -Path $Path -Recurse `
                    -Include '*.cs','*.vb','*.java' -File `
                    -ErrorAction SilentlyContinue | Select-Object -First 300)

    # Method name patterns that indicate auth/authz operations
    $authMethodRx = '(?i)(void|bool|Task|IActionResult|ActionResult|LoginResult|AuthResult|async)\s+' +
                    '(Login|Logout|SignIn|SignOut|Authenticate|VerifyCredentials|CheckPassword|' +
                    'ValidateToken|ValidateUser|Authorize|GrantAccess|DenyAccess|OnAuthentication)\s*\('

    # Logging calls within a method body
    $logCallRx = '(?i)(_?logger\.(Log|LogInformation|LogWarning|LogError|LogCritical)|' +
                 'EventLog\.WriteEntry|log\.(info|warn|error|debug)|' +
                 'AuditLog\.|SecurityLog\.|Trace\.(TraceInformation|TraceWarning|TraceError)|' +
                 'Console\.Error\.Write)'

    # Method body end heuristic: next method definition or class-level brace
    $nextMethodRx = '(?i)(public|private|protected|internal|static)\s+(override\s+)?' +
                    '(void|bool|Task|async|int|string|IActionResult)\s+\w+\s*\('

    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($src in $srcFiles) {
        try { $lines = Get-Content $src.FullName -ErrorAction Stop } catch { continue }
        $lineCount = $lines.Count

        for ($i = 0; $i -lt $lineCount; $i++) {
            if ($lines[$i] -notmatch $authMethodRx) { continue }
            $methodName = if ($lines[$i] -match '(Login|Logout|SignIn|SignOut|Authenticate|VerifyCredentials|' +
                                                  'CheckPassword|ValidateToken|ValidateUser|Authorize|' +
                                                  'GrantAccess|DenyAccess|OnAuthentication)') { $matches[1] } else { '' }

            # Scan the next 30 lines (or until next method) for a logging call
            $bodyEnd    = [Math]::Min($i + 30, $lineCount - 1)
            $hasLogCall = $false
            for ($j = $i + 1; $j -le $bodyEnd; $j++) {
                if ($lines[$j] -match $nextMethodRx -and $j -gt $i + 3) { $bodyEnd = $j; break }
                if ($lines[$j] -match $logCallRx) { $hasLogCall = $true; break }
            }

            if (-not $hasLogCall) {
                $loc = "$($src.FullName):$($i+1)"
                if ($seen.Add("$methodName|$loc")) {
                    New-TcpkFinding -Module 'logging' -RuleId 'security-logging.auth-method-no-log' `
                        -Severity 'MEDIUM' -Confidence 'Inferred' `
                        -Title "Auth method '$methodName' has no logging call in its body: $($src.Name):$($i+1)" `
                        -File $src.FullName `
                        -Evidence "Line $($i+1): $($lines[$i].Trim())" `
                        -Cwe @('CWE-778') `
                        -Description ("The method '$methodName' appears to be an authentication or " +
                            "authorization handler (based on name pattern), but no logging call was found " +
                            "in the next $($bodyEnd - $i) lines of the method body. Authentication events " +
                            "must be logged with the result (success/failure), user identity, and a " +
                            "timestamp to support incident response and brute-force detection. " +
                            "Confirm whether logging occurs in a called sub-method or middleware layer " +
                            "before promoting to Confirmed.") `
                        -Fix ('Add a structured log statement at each return point of the method: ' +
                            '_logger.LogWarning("Authentication failed for user {User} from {IP}", ' +
                            'username, remoteIp); // on failure ' +
                            '_logger.LogInformation("Authentication succeeded for {User}", username); // on success ' +
                            'Include the EventId so SIEM rules can aggregate by type.')
                }
            }
        }
    }

    # ---- Config: appsettings.json logging level for security namespaces ----
    $appSettings = @(Get-ChildItem -Path $Path -Recurse -Filter 'appsettings*.json' -File `
                       -ErrorAction SilentlyContinue | Select-Object -First 10)
    foreach ($as in $appSettings) {
        $raw = Get-Content $as.FullName -Raw -ErrorAction SilentlyContinue
        if (-not $raw) { continue }
        if ($raw -notmatch '(?i)"Logging"') { continue }
        try { $jobj = $raw | ConvertFrom-Json -ErrorAction Stop } catch { continue }

        $logSection = $null
        try { $logSection = $jobj.Logging.LogLevel } catch {}
        if (-not $logSection) { continue }

        # Check if Default or System.Security is set to Warning, Error, Critical or None
        # which would suppress Information-level security events
        $defaultLevel = try { "$($logSection.Default)" } catch { '' }
        $secLevel     = try { "$($logSection.'System.Security')" } catch { '' }
        $suppressing  = @('Warning','Error','Critical','None') -contains $defaultLevel -and
                        -not ($secLevel -match '(?i)(Debug|Information|Trace)')

        if ($suppressing) {
            New-TcpkFinding -Module 'logging' -RuleId 'security-logging.level-suppresses-audit' `
                -Severity 'LOW' -Confidence 'Inferred' `
                -Title "Logging default level '$defaultLevel' suppresses Information-level security events: $($as.Name)" `
                -File $as.FullName `
                -Evidence "Logging:LogLevel:Default=$defaultLevel; System.Security override=$secLevel" `
                -Cwe @('CWE-778') `
                -Description ("The appsettings.json sets the default log level to '$defaultLevel', " +
                    "which suppresses all Information-level log entries. Authentication events " +
                    "(login success, token issue) are typically logged at Information level. " +
                    "Without a specific override for the security namespace, these events are " +
                    "silently dropped. Failure events at Warning level may still be logged, but " +
                    "success events (needed for session reconstruction in IR) are lost.") `
                -Fix ('Add a specific minimum level for the security namespace: ' +
                    '"Logging": { "LogLevel": { "Default": "Warning", ' +
                    '"YourApp.Auth": "Information", "Microsoft.AspNetCore.Authentication": "Information" } } ' +
                    'This preserves auth event logging without flooding the log with framework noise.')
        }
    }
}
