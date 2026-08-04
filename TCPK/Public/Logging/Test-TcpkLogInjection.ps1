function Test-TcpkLogInjection {
<#
.SYNOPSIS
    C30. Log injection and CRLF log-forging attack surface in logging configuration.

.DESCRIPTION
    Scans deployed application files for logging framework configuration that
    enables log injection attacks. Log injection occurs when user-controlled input
    containing CR/LF characters (\r\n) reaches a log sink without sanitization,
    allowing an attacker to forge log entries or inject content into log viewers.

    Static checks (no source code required):

    NLog.config:
      - Detects layout targets that use raw ${message} or ${exception} without
        wrapping the output in an encoding attribute (--no ANSI / HTML encode).
      - Flags "File" and "Database" targets with un-encoded layout patterns.

    log4net.config:
      - Detects PatternLayout with %m (message) or %exception in conversionPattern
        without ExceptionRenderer or HTML-encoded appender layout.

    Serilog (appsettings.json / serilog.json):
      - Detects {Message} in outputTemplate without the :l (literal) or :j (JSON)
        format specifier, meaning structured events are rendered as user-influenced
        strings.

    Source code (.cs / .vb / .java files, if present in the scan directory):
      - Detects string concatenation or String.Format calls used directly as
        arguments to common logging methods (log.Error, Logger.Log, etc.).
        These are Confirmed when the concatenated value includes a name that
        matches a user-input pattern (request, query, input, param, user, client).

    Findings:
      - Source-level concat-to-log with user-input name: Confirmed MEDIUM (CWE-117)
      - Logging config without sanitization: Inferred LOW (analyst must trace
        data flow to confirm user input reaches the sink)

.PARAMETER Path
    Root directory of the application or project to scan.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Assert-TcpkWindows 'Test-TcpkLogInjection')) { return }
    if (-not (Test-Path $Path)) { return }

    # --------------------------------------------------------- NLog.config
    $nlogConfigs = @(Get-ChildItem -Path $Path -Recurse -Filter 'NLog.config' -File `
                       -ErrorAction SilentlyContinue | Select-Object -First 10)

    foreach ($cfg in $nlogConfigs) {
        try { [xml]$xml = Get-Content $cfg.FullName -Raw -ErrorAction Stop } catch { continue }

        $targets = @($xml.nlog.targets.target | Where-Object { $_ -ne $null })
        if (-not $targets.Count) { continue }

        foreach ($t in $targets) {
            $ttype  = "$($t.type)"
            $layout = "$($t.layout)"
            if (-not $layout) {
                # Layout may be a child element
                $layoutNode = $t.layout
                $layout = if ($layoutNode) { "$($layoutNode.InnerText)" } else { '' }
            }
            if (-not $layout) { continue }

            # ${message} or ${exception} without html-encode="${}" attribute
            # indicates raw user content may reach the log file.
            $hasRaw = ($layout -match '\$\{message\}' -or $layout -match '\$\{exception\}')
            $hasEnc = ($layout -match 'html-encode\s*=\s*(true|yes)' -or
                       $layout -match 'url-encode\s*=\s*(true|yes)')

            if ($hasRaw -and -not $hasEnc) {
                New-TcpkFinding -Module 'logging' -RuleId 'log-injection.nlog-raw-message' `
                    -Severity 'LOW' -Confidence 'Inferred' `
                    -Title "NLog target '$($t.name)' uses raw \${message} without encoding" `
                    -File $cfg.FullName `
                    -Evidence "type=$ttype layout=$($layout.Substring(0, [Math]::Min(120, $layout.Length)))" `
                    -Cwe @('CWE-117','CWE-93') `
                    -Description ('The NLog target uses ${message} or ${exception} in its layout ' +
                        'without the html-encode="true" or url-encode="true" attribute. If any ' +
                        'user-controlled string (network input, file content, username, query ' +
                        'parameter) reaches this log statement without CRLF stripping, an attacker ' +
                        'can inject newlines to forge subsequent log lines, corrupt structured ' +
                        'log formats, or trigger XSS in log management UIs. ' +
                        'Trace data flow from network/UI entry points to the log call to confirm.') `
                    -Fix ('Add html-encode="true" to the layout: ${message:html-encode=true}. ' +
                        'Alternatively, strip CR and LF before passing user-derived strings to ' +
                        'any log method: $input -replace "[\r\n]", " ". ' +
                        'Ref: https://nlog-project.org/config/?tab=layout-renderers&search=message')
            }
        }
    }

    # ------------------------------------------------------ log4net.config
    $log4netConfigs = @(Get-ChildItem -Path $Path -Recurse -Filter 'log4net.config' -File `
                          -ErrorAction SilentlyContinue | Select-Object -First 10)

    # Also catch log4net config embedded in App.config / Web.config
    $appConfigs = @(Get-ChildItem -Path $Path -Recurse `
                      -Include 'App.config','Web.config','app.config','web.config' -File `
                      -ErrorAction SilentlyContinue | Select-Object -First 20)

    $log4netFiles = @($log4netConfigs) + @($appConfigs)

    foreach ($cfg in $log4netFiles) {
        $raw = Get-Content $cfg.FullName -Raw -ErrorAction SilentlyContinue
        if (-not $raw) { continue }
        # Cheap check: does this file contain log4net content?
        if ($raw -notmatch 'log4net') { continue }

        try { [xml]$xml = $raw } catch { continue }

        # Locate all conversionPattern values
        $patterns = @()
        $xml.SelectNodes('//*[@conversionPattern]') | ForEach-Object {
            $patterns += @{ File = $cfg.FullName; Pattern = $_.conversionPattern; AppenderName = $_.ParentNode.name }
        }

        foreach ($p in $patterns) {
            # %m = message, %message = message, %exception = exception -- all raw user content
            if ($p.Pattern -match '%(-?\d+)?m(?!\w)' -or $p.Pattern -match '%message' -or $p.Pattern -match '%exception') {
                # Check for HTML encoding appender
                $hasHtml = $p.Pattern -match 'HtmlLayout' -or $raw -match 'log4net\.Layout\.HtmlLayout'
                if (-not $hasHtml) {
                    New-TcpkFinding -Module 'logging' -RuleId 'log-injection.log4net-raw-message' `
                        -Severity 'LOW' -Confidence 'Inferred' `
                        -Title "log4net appender '$($p.AppenderName)' logs raw message (%m) without HTML encoding" `
                        -File $p.File `
                        -Evidence "conversionPattern: $($p.Pattern)" `
                        -Cwe @('CWE-117','CWE-93') `
                        -Description ('The log4net PatternLayout uses %m (message) or %exception ' +
                            'in its conversionPattern without an HtmlLayout wrapper. If user-supplied ' +
                            'strings reach this log call, an attacker can inject CRLF sequences to ' +
                            'forge log entries or inject content into log viewers that render HTML. ' +
                            'Trace data flow from UI/network entry points to log calls to confirm.') `
                        -Fix ('Wrap the appender with log4net.Layout.HtmlLayout for web-based log ' +
                            'viewers. For plain-text log files, sanitize user input before logging: ' +
                            'strip \r and \n from all externally sourced strings. ' +
                            'Ref: https://logging.apache.org/log4net/release/sdk/html/T_log4net_Layout_HtmlLayout.htm')
                }
            }
        }
    }

    # ------------------------------------------ Serilog (appsettings.json)
    $serilogJsons = @(Get-ChildItem -Path $Path -Recurse `
                        -Include 'appsettings*.json','serilog.json','logging.json' -File `
                        -ErrorAction SilentlyContinue | Select-Object -First 20)

    foreach ($sj in $serilogJsons) {
        $raw = Get-Content $sj.FullName -Raw -ErrorAction SilentlyContinue
        if (-not $raw) { continue }
        if ($raw -notmatch 'Serilog') { continue }

        try { $jobj = $raw | ConvertFrom-Json -ErrorAction Stop } catch { continue }

        # Look for WriteTo entries with outputTemplate containing {Message} but not {Message:l} or {Message:j}
        $writeTo = @()
        try { $writeTo = @($jobj.Serilog.WriteTo) } catch {}
        if (-not $writeTo.Count) { continue }

        foreach ($sink in $writeTo) {
            $tmpl = ''
            try { $tmpl = "$($sink.Args.outputTemplate)" } catch {}
            if (-not $tmpl) { continue }

            # {Message} without format specifier = rendered as string, not JSON
            if ($tmpl -match '\{Message\}' -and $tmpl -notmatch '\{Message:[lj]\}') {
                $sinkName = try { "$($sink.Name)" } catch { 'unknown' }
                New-TcpkFinding -Module 'logging' -RuleId 'log-injection.serilog-unencoded-message' `
                    -Severity 'LOW' -Confidence 'Inferred' `
                    -Title "Serilog sink '$sinkName' uses {Message} without format specifier" `
                    -File $sj.FullName `
                    -Evidence "outputTemplate: $tmpl" `
                    -Cwe @('CWE-117') `
                    -Description ('The Serilog outputTemplate uses {Message} without a :l (literal) or ' +
                        ':j (JSON) format specifier. The default {Message} renderer calls ToString() ' +
                        'on message arguments, which means user-controlled strings are embedded as-is ' +
                        'in the log output. CRLF characters in those strings can forge log lines. ' +
                        'Use structured (template) logging: log.Information("User {Name} logged in", userName) ' +
                        'instead of log.Information("User " + userName + " logged in") so the value is ' +
                        'stored separately from the template and cannot alter log structure.') `
                    -Fix ('Change {Message} to {Message:l} (literal -- renders the template, not string-args) ' +
                        'or switch to a JSON formatter (Serilog.Formatting.Compact.CompactJsonFormatter) which ' +
                        'encodes all values as JSON strings, making CRLF injection structurally impossible. ' +
                        'Ref: https://github.com/serilog/serilog/wiki/Formatting-Output')
            }
        }
    }

    # ------------------------------------------ Source-level scan (.cs/.vb/.java)
    # If source files are present in the scan directory (dev environment or
    # build output with PDB/source), look for string concatenation passed
    # directly to a log method.
    $srcFiles = @(Get-ChildItem -Path $Path -Recurse `
                    -Include '*.cs','*.vb','*.java' -File `
                    -ErrorAction SilentlyContinue | Select-Object -First 200)

    if (-not $srcFiles.Count) { return }

    # Logging method patterns: log.Error(, _logger.LogError(, Logger.Write(, etc.
    $logCallRx = '(?i)(log\.(error|warn|info|debug|fatal|trace|write|writeline)\s*\(|' +
                 '_?logger\.(log|logerror|logwarning|loginformation|logdebug|logcritical|logcritical)\s*\(|' +
                 'logger\.(error|warn|info|debug|fatal|trace)\s*\(|' +
                 'Trace\.(WriteLine|Write|TraceError|TraceWarning|TraceInformation)\s*\(|' +
                 'Console\.(Error\.Write|Error\.WriteLine)\s*\()'

    # User-input variable name heuristic
    $userInputRx = '(?i)(request|query|input|param|args\b|user(name|data|input)?|client|payload|body|header|cookie|message|text|value|data)\s*[\+\)]'

    # String concat in argument: "..." + variable  or  string.Format(
    $concatRx  = '(?i)(".*?"\s*\+|string\.Format\s*\(|String\.format\s*\(|\$")'

    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($src in $srcFiles) {
        try { $lines = Get-Content $src.FullName -ErrorAction Stop } catch { continue }
        for ($i = 0; $i -lt $lines.Count; $i++) {
            $line = $lines[$i]
            if ($line -notmatch $logCallRx) { continue }
            if ($line -notmatch $concatRx)  { continue }
            if ($line -notmatch $userInputRx) { continue }

            $loc = "$($src.FullName):$($i + 1)"
            if (-not $seen.Add($loc)) { continue }

            New-TcpkFinding -Module 'logging' -RuleId 'log-injection.source-concat' `
                -Severity 'MEDIUM' -Confidence 'Confirmed' `
                -Title "Log call with string concatenation of user-named variable: $($src.Name):$($i+1)" `
                -File $src.FullName `
                -Evidence "Line $($i+1): $($line.Trim())" `
                -Cwe @('CWE-117','CWE-93') `
                -Description ('A logging method call uses string concatenation (+ operator or ' +
                    'String.Format) where one operand matches a user-input naming pattern ' +
                    '(request, query, input, param, user, client, payload, etc.). If this ' +
                    'variable contains CR (\r) or LF (\n) characters from attacker-controlled ' +
                    'input, the log sink will interpret them as record separators, allowing the ' +
                    'attacker to forge subsequent log lines. This is a confirmed pattern match; ' +
                    'verify the variable originates from an external source to confirm exploitability.') `
                -Fix ('Replace string concatenation with a structured log template: ' +
                    'log.Error("Operation failed for {User}", userName) -- the value is stored ' +
                    'separately from the format string and cannot alter log structure. ' +
                    'If raw output is required, strip CR/LF before logging: ' +
                    'value.Replace("\r","").Replace("\n"," ").')
        }
    }
}
