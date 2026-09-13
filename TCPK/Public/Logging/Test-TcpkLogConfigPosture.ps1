function Test-TcpkLogConfigPosture {
<#
.SYNOPSIS
    L07. Operational soundness of the shipped logging configuration: retention bounds,
    time source, and whether the output is machine-parseable.

.DESCRIPTION
    Test-TcpkLogInjection reads the same NLog / log4net / Serilog configuration files to
    answer one question: can an attacker forge a log line. This answers three different
    ones that decide whether the log is usable as evidence at all.

    RETENTION BOUND. A file target with no size cap and no time-based roll grows without
    limit. Two consequences: the volume the application writes to eventually fills, which
    on a system volume is a denial of service the application inflicts on its own host;
    and an attacker who can drive log volume can push older entries past whatever manual
    cleanup exists, destroying the record of what they did earlier.

    TIME SOURCE. Timestamps written in local time without an offset cannot be correlated
    across hosts in different zones, and become ambiguous twice a year when the clock
    moves back an hour: two distinct events carry the same stamp and their order is
    unrecoverable. UTC removes both problems.

    STRUCTURE. A free-text layout has to be re-parsed with regular expressions before it
    can be queried, and any field containing a delimiter breaks that parse. A structured
    (JSON) layout keeps field boundaries intact, which is what makes the log searchable
    during an incident rather than merely readable.

    Rules:
      log.no-rotation           LOW   A file target declares no size or time bound.
      log.timestamp-not-utc     LOW   The layout renders local time rather than UTC.
      log.unstructured-format   INFO  Free-text layout rather than a structured formatter.

    QUIET BY DEFAULT. Nothing is emitted when no logging configuration ships: absence of a
    config is not evidence of a defect, it usually means the app does not use one of these
    frameworks. Only targets that write to a FILE are evaluated, because a console or
    debugger target needs no retention bound. Rotation and time source configured in code
    rather than in config are not visible here, which the findings state.

.PARAMETER Path
    Install directory or a single configuration file.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { return }

    # Namespace-agnostic node selection. NLog.config declares a default xmlns, so a plain
    # //target XPath silently matches nothing; local-name() sidesteps the namespace.
    function _SelectNodes {
        param([xml]$Xml, [string]$LocalName)
        $out = @()
        try { $out = @($Xml.SelectNodes("//*[local-name()='$LocalName']")) } catch { $out = @() }
        return $out
    }
    function _Attr {
        param([object]$Node, [string]$Name)
        $v = ''
        try { $v = "$($Node.GetAttribute($Name))" } catch { $v = '' }
        return $v
    }

    # ------------------------------------------------------------------ NLog
    $nlogFiles = @()
    try {
        $nlogFiles = @(Get-ChildItem -Path $Path -Recurse -Filter 'NLog.config' -File -ErrorAction SilentlyContinue |
                       Select-Object -First 20)
    } catch { }

    foreach ($cfg in $nlogFiles) {
        $raw = ''
        try { $raw = Get-Content -LiteralPath $cfg.FullName -Raw -ErrorAction Stop } catch { continue }
        if (-not $raw) { continue }
        $xml = $null
        try { $xml = [xml]$raw } catch { continue }

        foreach ($t in (_SelectNodes -Xml $xml -LocalName 'target')) {
            $ttype = _Attr -Node $t -Name 'type'
            if (-not $ttype) { $ttype = _Attr -Node $t -Name 'xsi:type' }
            # Only file-writing targets carry a retention obligation.
            if ($ttype -notlike '*File*') { continue }
            $tname = _Attr -Node $t -Name 'name'
            if (-not $tname) { $tname = '(unnamed)' }
            $outer = "$($t.OuterXml)"

            # ---- retention bound ----
            $hasBound = ($outer -match '(?i)\barchiveEvery\s*=' -or
                         $outer -match '(?i)\barchiveAboveSize\s*=' -or
                         $outer -match '(?i)\bmaxArchiveFiles\s*=' -or
                         $outer -match '(?i)\bmaxArchiveDays\s*=' -or
                         $outer -match '(?i)\barchiveFileName\s*=')
            if (-not $hasBound) {
                New-TcpkFinding -Module 'logging' -RuleId 'log.no-rotation' `
                    -Severity 'LOW' -Confidence 'Confirmed' `
                    -Title "NLog file target '$tname' declares no size or time bound" `
                    -File $cfg.FullName `
                    -Evidence "type=$ttype; no archiveEvery / archiveAboveSize / maxArchiveFiles / maxArchiveDays" `
                    -Cwe @('CWE-770', 'CWE-400') `
                    -Description ('This target writes to a file and declares no archive trigger and no ' +
                        'retention limit, so the file grows until the volume is full. On a system volume ' +
                        'that is a denial of service the application inflicts on its own host. It also ' +
                        'means an attacker who can drive log volume (repeated failed logins, a noisy error ' +
                        'path) can grow the file until whatever manual cleanup exists discards the older ' +
                        'entries that recorded what they did first. Rotation configured in code rather than ' +
                        'in this file would not be visible here.') `
                    -Fix 'Set archiveAboveSize (or archiveEvery) together with maxArchiveFiles or maxArchiveDays on the target, so the file rolls at a known size or interval and old archives are discarded on a defined schedule.'
            }

            # ---- time source ----
            # NLog renders local time unless universalTime=true is set on the renderer.
            $layout = _Attr -Node $t -Name 'layout'
            if (-not $layout) { $layout = $outer }
            $usesDate = ($layout -match '(?i)\$\{longdate' -or $layout -match '(?i)\$\{date' -or $layout -match '(?i)\$\{time')
            $isUtc    = ($layout -match '(?i)universalTime\s*=\s*true')
            if ($usesDate -and -not $isUtc) {
                $shown = $layout
                if ($shown.Length -gt 120) { $shown = $shown.Substring(0, 120) }
                New-TcpkFinding -Module 'logging' -RuleId 'log.timestamp-not-utc' `
                    -Severity 'LOW' -Confidence 'Confirmed' `
                    -Title "NLog target '$tname' timestamps in local time" `
                    -File $cfg.FullName `
                    -Evidence "layout=$shown ; no universalTime=true" `
                    -Description ('The layout renders a timestamp with no universalTime=true, so entries ' +
                        'carry local time with no UTC offset. Two problems follow. Logs from hosts in ' +
                        'different time zones cannot be placed on one timeline without knowing each host''s ' +
                        'zone at the time of writing. And when the clock moves back for daylight saving, one ' +
                        'hour repeats: two distinct events receive the same stamp and their true order ' +
                        'cannot be recovered from the log alone.') `
                    -Fix 'Render the timestamp in UTC, for example ${longdate:universalTime=true}, or include an explicit offset so entries remain orderable across hosts and across a daylight-saving transition.'
            }

            # ---- structure ----
            if ($outer -notmatch '(?i)JsonLayout') {
                New-TcpkFinding -Module 'logging' -RuleId 'log.unstructured-format' `
                    -Severity 'INFO' -Confidence 'Confirmed' `
                    -Title "NLog file target '$tname' writes free-text, not structured output" `
                    -File $cfg.FullName -Evidence "type=$ttype; no JsonLayout on this target" `
                    -Description ('The target writes a rendered text line rather than a structured record. ' +
                        'Querying it later means re-parsing with regular expressions, and any logged value ' +
                        'containing the delimiter breaks that parse, which is also the mechanism behind log ' +
                        'forging. Reported as scope information about how usable this log is as evidence, ' +
                        'not as a defect on its own.') `
                    -Fix 'Use a JsonLayout on the target so each field stays a discrete value and the log can be queried without re-parsing.'
            }
        }
    }

    # --------------------------------------------------------------- log4net
    $l4nFiles = @()
    try {
        $l4nFiles = @(Get-ChildItem -Path $Path -Recurse -File -ErrorAction SilentlyContinue |
                      Where-Object { $_.Name -eq 'log4net.config' -or $_.Name -like '*.exe.config' -or
                                     $_.Name -eq 'App.config' -or $_.Name -eq 'Web.config' } |
                      Select-Object -First 30)
    } catch { }

    foreach ($cfg in $l4nFiles) {
        $raw = ''
        try { $raw = Get-Content -LiteralPath $cfg.FullName -Raw -ErrorAction Stop } catch { continue }
        if (-not $raw -or $raw -notmatch 'log4net') { continue }
        $xml = $null
        try { $xml = [xml]$raw } catch { continue }

        foreach ($ap in (_SelectNodes -Xml $xml -LocalName 'appender')) {
            $atype = _Attr -Node $ap -Name 'type'
            if ($atype -notlike '*File*') { continue }
            $aname = _Attr -Node $ap -Name 'name'
            if (-not $aname) { $aname = '(unnamed)' }
            $outer = "$($ap.OuterXml)"

            # ---- retention bound ----
            # A plain FileAppender has no rolling behaviour at all; a RollingFileAppender
            # still needs a size or date trigger to actually roll.
            $hasBound = ($outer -match '(?i)maximumFileSize' -or
                         $outer -match '(?i)maxSizeRollBackups' -or
                         $outer -match '(?i)rollingStyle' -or
                         $outer -match '(?i)datePattern')
            if (-not $hasBound) {
                New-TcpkFinding -Module 'logging' -RuleId 'log.no-rotation' `
                    -Severity 'LOW' -Confidence 'Confirmed' `
                    -Title "log4net file appender '$aname' declares no size or time bound" `
                    -File $cfg.FullName `
                    -Evidence "type=$atype; no maximumFileSize / maxSizeRollBackups / rollingStyle / datePattern" `
                    -Cwe @('CWE-770', 'CWE-400') `
                    -Description ('This appender writes to a file with no roll trigger and no backup ' +
                        'limit, so the file grows until the volume fills. That is a denial of service the ' +
                        'application inflicts on its own host, and it lets anyone who can drive log volume ' +
                        'push earlier entries out of whatever retention exists. A plain FileAppender never ' +
                        'rolls at all; a RollingFileAppender without a size or date trigger behaves the ' +
                        'same way.') `
                    -Fix 'Use a RollingFileAppender with rollingStyle plus maximumFileSize and maxSizeRollBackups (or a datePattern for time-based rolling) so the file is bounded and old data is discarded predictably.'
            }

            # ---- time source ----
            $isUtc = ($outer -match '(?i)%utcdate')
            $usesLocal = ($outer -match '(?i)%date' -or $outer -match '(?i)%d\{')
            if ($usesLocal -and -not $isUtc) {
                New-TcpkFinding -Module 'logging' -RuleId 'log.timestamp-not-utc' `
                    -Severity 'LOW' -Confidence 'Confirmed' `
                    -Title "log4net appender '$aname' timestamps in local time" `
                    -File $cfg.FullName -Evidence 'conversionPattern uses %date / %d rather than %utcdate' `
                    -Description ('The conversion pattern renders local time. Entries cannot be placed on ' +
                        'a single timeline with logs from hosts in other zones, and the hour that repeats ' +
                        'at the end of daylight saving produces duplicate timestamps whose real order ' +
                        'cannot be recovered.') `
                    -Fix 'Use %utcdate in the conversionPattern, or include the zone offset, so entries stay orderable across hosts and across a daylight-saving transition.'
            }

            # ---- structure ----
            if ($outer -match '(?i)PatternLayout' -and $outer -notmatch '(?i)(JsonLayout|XmlLayout)') {
                New-TcpkFinding -Module 'logging' -RuleId 'log.unstructured-format' `
                    -Severity 'INFO' -Confidence 'Confirmed' `
                    -Title "log4net appender '$aname' writes free-text, not structured output" `
                    -File $cfg.FullName -Evidence 'PatternLayout with no JsonLayout or XmlLayout' `
                    -Description ('The appender renders a text line via PatternLayout rather than a ' +
                        'structured record, so later querying means re-parsing with regular expressions and ' +
                        'any value containing the delimiter breaks that parse. Scope information about the ' +
                        'log''s usability as evidence.') `
                    -Fix 'Use a structured layout (log4net.Layout.JsonLayout or an XmlLayout) so fields stay discrete.'
            }
        }
    }

    # --------------------------------------------------------------- Serilog
    $serilogFiles = @()
    try {
        $serilogFiles = @(Get-ChildItem -Path $Path -Recurse -Include 'appsettings*.json', 'serilog.json', 'logging.json' `
                            -File -ErrorAction SilentlyContinue | Select-Object -First 20)
    } catch { }

    foreach ($sj in $serilogFiles) {
        $raw = ''
        try { $raw = Get-Content -LiteralPath $sj.FullName -Raw -ErrorAction Stop } catch { continue }
        if (-not $raw -or $raw -notmatch 'Serilog') { continue }
        $jobj = $null
        try { $jobj = $raw | ConvertFrom-Json -ErrorAction Stop } catch { continue }

        $writeTo = @()
        try { $writeTo = @($jobj.Serilog.WriteTo) } catch { $writeTo = @() }
        if (-not $writeTo.Count) { continue }

        foreach ($sink in $writeTo) {
            $sname = ''
            try { $sname = "$($sink.Name)" } catch { }
            if ($sname -ne 'File') { continue }

            $argsNode = $null
            try { $argsNode = $sink.Args } catch { }
            $argText = ''
            try { $argText = ($argsNode | ConvertTo-Json -Depth 6 -Compress) } catch { $argText = '' }

            # ---- retention bound ----
            $hasBound = ($argText -match '(?i)rollingInterval' -or
                         $argText -match '(?i)fileSizeLimitBytes' -or
                         $argText -match '(?i)retainedFileCountLimit' -or
                         $argText -match '(?i)rollOnFileSizeLimit')
            if (-not $hasBound) {
                New-TcpkFinding -Module 'logging' -RuleId 'log.no-rotation' `
                    -Severity 'LOW' -Confidence 'Confirmed' `
                    -Title 'Serilog File sink declares no size or time bound' `
                    -File $sj.FullName `
                    -Evidence 'no rollingInterval / fileSizeLimitBytes / retainedFileCountLimit / rollOnFileSizeLimit' `
                    -Cwe @('CWE-770', 'CWE-400') `
                    -Description ('The Serilog File sink declares no rolling interval and no size limit, ' +
                        'so the log grows until the volume fills. Serilog applies a default size cap on ' +
                        'some sink versions, but relying on an unstated default is not a retention policy ' +
                        'and changes between package versions. An attacker who can drive log volume can ' +
                        'also use unbounded growth to push earlier entries out of retention.') `
                    -Fix 'Set rollingInterval (Day) together with retainedFileCountLimit, and fileSizeLimitBytes with rollOnFileSizeLimit, so retention is explicit rather than inherited from a package default.'
            }

            # ---- structure and timestamp ----
            # Serilog renders UTC vs local through code-side enrichment far more often than
            # through config, so local-vs-UTC is deliberately NOT claimed here. Only the
            # declared output shape is judged.
            $hasFormatter = ($argText -match '(?i)formatter')
            $tmpl = ''
            try { $tmpl = "$($argsNode.outputTemplate)" } catch { }
            if (-not $hasFormatter) {
                New-TcpkFinding -Module 'logging' -RuleId 'log.unstructured-format' `
                    -Severity 'INFO' -Confidence 'Confirmed' `
                    -Title 'Serilog File sink writes a rendered template, not structured output' `
                    -File $sj.FullName `
                    -Evidence ("no formatter arg" + $(if ($tmpl) { "; outputTemplate=$tmpl" } else { '' })) `
                    -Description ('The sink declares no formatter, so it renders each event through an ' +
                        'output template into a text line and the structured properties Serilog captured ' +
                        'are flattened away. Querying the result later means re-parsing text. Scope ' +
                        'information about how usable this log is as evidence, not a defect on its own.') `
                    -Fix 'Set a structured formatter on the sink (Serilog.Formatting.Compact.CompactJsonFormatter) so captured properties survive as discrete fields.'
            }
        }
    }
}
