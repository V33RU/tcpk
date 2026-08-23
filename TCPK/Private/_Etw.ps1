#requires -Version 5.1
# Shared ETW capture and analysis for the ProcMon-equivalent runtime checks.
#
# WHY THIS EXISTS. Test-TcpkDllSearchTrace, Test-TcpkFileActivity and Test-TcpkRegistryWrites
# each opened their own logman session, slept, stopped, parsed and deleted the ETL. Two of
# them subscribe to the SAME provider (Microsoft-Windows-Kernel-File), and Invoke-TcpkAudit
# ran all three in sequence at 30 seconds each. So the operator had to exercise the
# application three times to answer three questions about what should have been one window,
# and because the two file captures came from DIFFERENT windows, a DLL probe and the write it
# led to could never be correlated. Capturing once and analysing three ways fixes both.
#
# Capture and analysis are separated here for a second reason. An analyser that is a pure
# function over already-parsed events can be tested: a Pester suite feeds it synthetic records
# with no admin rights, no Windows ETW session and no 30-second wait. The old shape could not
# be tested at all, which is why these two cmdlets shipped with no suite.

function Get-TcpkProcessTreeId {
<#
.SYNOPSIS
    A PID plus every descendant PID currently alive.

.DESCRIPTION
    ETW attributes each event to the PID that raised it. Filtering on the target PID alone
    discards everything a spawned helper, updater or renderer child does, which for a modern
    thick client can be most of the interesting activity. ProcMon shows the tree; so should we.

    KNOWN LIMIT, stated rather than hidden: this is a snapshot. A child that both starts and
    exits inside the capture window appears in neither the start nor the stop snapshot and its
    events are dropped. Callers take the union of a before and after call to narrow that
    window, but closing it entirely needs the Kernel-Process provider and is not done here.
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][int]$ProcessId, [int]$MaxDepth = 6)

    $out = [System.Collections.Generic.HashSet[int]]::new()
    [void]$out.Add($ProcessId)

    $all = $null
    try { $all = @(Get-CimInstance -ClassName Win32_Process -ErrorAction Stop | Select-Object ProcessId, ParentProcessId) }
    catch { return $out }
    if (-not $all.Count) { return $out }

    $frontier = @($ProcessId)
    for ($d = 0; $d -lt $MaxDepth -and $frontier.Count; $d++) {
        $next = New-Object 'System.Collections.Generic.List[int]'
        foreach ($p in $all) {
            $ppid = [int]$p.ParentProcessId
            if ($frontier -notcontains $ppid) { continue }
            $cpid = [int]$p.ProcessId
            # A PID is reused after the process dies, so a self-parent or an already-seen id
            # would loop forever. Add() returning false is the guard.
            if ($cpid -eq $ppid) { continue }
            if ($out.Add($cpid)) { $next.Add($cpid) }
        }
        $frontier = $next.ToArray()
    }
    return $out
}

function Start-TcpkEtwCapture {
<#
.SYNOPSIS
    Start ONE logman session carrying every provider a caller needs.

.DESCRIPTION
    Returns a session object, or $null with $Reason set when the session could not start.
    Never throws: a failed capture is a Skipped finding at the call site, not an exception.

.PARAMETER Provider
    One or more provider names or GUIDs. Multiple providers in one session is the entire point.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string[]]$Provider,
        [string]$Label = 'Trace'
    )

    $sess = "TCPK-$Label-$([Guid]::NewGuid().ToString().Substring(0, 8))"
    $etl  = Join-Path (Get-TcpkWorkDir -Kind 'trace') "$sess.etl"

    $first = $Provider[0]
    $out = & logman create trace $sess -p $first 0xffffffff 0xff -o $etl -ets 2>&1
    if ($LASTEXITCODE -ne 0) {
        return [pscustomobject]@{
            Name = $sess; Etl = $etl; Started = $false
            Reason = "logman create exit $LASTEXITCODE : $($out -join ' ')"
        }
    }

    # Providers 2..n are added to the running session. A failure here is not fatal: a capture
    # with one of two providers is degraded, not useless, and the caller is told which are live
    # so a finding can say what it could not see rather than reporting a clean result.
    $live = New-Object 'System.Collections.Generic.List[string]'
    $live.Add($first)
    $failed = New-Object 'System.Collections.Generic.List[string]'
    for ($i = 1; $i -lt $Provider.Count; $i++) {
        $u = & logman update trace $sess -p $Provider[$i] 0xffffffff 0xff -ets 2>&1
        if ($LASTEXITCODE -eq 0) { $live.Add($Provider[$i]) } else { $failed.Add($Provider[$i]) }
    }

    return [pscustomobject]@{
        Name = $sess; Etl = $etl; Started = $true; Reason = ''
        Providers = $live.ToArray(); FailedProviders = $failed.ToArray()
    }
}

function Stop-TcpkEtwCapture {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Session)
    if (-not $Session -or -not $Session.Started) { return }
    & logman stop $Session.Name -ets 2>&1 | Out-Null
}

function Read-TcpkEtwEvents {
<#
.SYNOPSIS
    Parse an ETL once into normalised records that every analyser can read.

.DESCRIPTION
    One pass, one shape. Each record carries EventId, ProcessId, Provider, TimeCreated, the
    promoted fields the analysers actually use (Path, ValueName, Status), and Fields for
    anything else the provider emitted.

    Path is FileName for the file provider and KeyName for the registry provider, because
    every consumer wants "the thing that was touched" and no consumer wants to know which
    provider named it what.

.PARAMETER ProcessIds
    Keep only events raised by these PIDs. Pass the process tree, not a single id.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Etl,
        $ProcessIds,
        [switch]$AllProcesses
    )

    $out = New-Object 'System.Collections.Generic.List[object]'
    if (-not (Test-Path -LiteralPath $Etl)) { return $out }

    # Deliberately not caught. A parse failure has to reach the caller, which decides to keep
    # the .etl and say so in a Skipped finding.
    $events = Get-WinEvent -Path $Etl -Oldest -ErrorAction Stop

    foreach ($e in $events) {
        $xml = $null
        try { $xml = [xml]$e.ToXml() } catch { continue }
        $epid = -1
        try { $epid = [int]($xml.Event.System.Execution.ProcessID) } catch { continue }
        if (-not $AllProcesses) {
            if (-not $ProcessIds) { continue }
            if (-not $ProcessIds.Contains($epid)) { continue }
        }

        $fields = @{}
        try {
            foreach ($d in $xml.Event.EventData.Data) {
                $n = "$($d.Name)"
                if ($n) { $fields[$n] = "$($d.'#text')" }
            }
        } catch { }

        # Some builds emit the MOF message string instead of structured EventData. The registry
        # cmdlet already carried this fallback; it belongs here so every consumer gets it.
        if (-not $fields.Count -and $e.Message) {
            foreach ($k in 'FileName', 'KeyName', 'ValueName', 'Status') {
                if ($e.Message -match ($k + '\s*:\s*(.+?)(?:\r?\n|$)')) { $fields[$k] = $matches[1].Trim() }
            }
        }

        # Kind records WHICH provider named the path, and it is load-bearing once one session
        # carries two providers. Without it a registry key called ApiToken reaches the file
        # analyser, matches its credential-name pattern, and is reported as a file write.
        $path = $null; $kind = 'other'
        if ($fields.ContainsKey('FileName')) { $path = $fields['FileName']; $kind = 'file' }
        elseif ($fields.ContainsKey('KeyName')) { $path = $fields['KeyName']; $kind = 'registry' }

        $val = $null
        if ($fields.ContainsKey('ValueName')) { $val = $fields['ValueName'] }
        $st = $null
        if ($fields.ContainsKey('Status')) { $st = $fields['Status'] }

        $out.Add([pscustomobject]@{
            EventId     = [int]$e.Id
            Kind        = $kind
            ProcessId   = $epid
            Provider    = "$($e.ProviderName)"
            TimeCreated = $e.TimeCreated
            Path        = $path
            ValueName   = $val
            Status      = $st
            Fields      = $fields
        })
    }
    return $out
}

function Test-TcpkEtwPathFilter {
<#
.SYNOPSIS
    Operator-supplied -Include / -Exclude, applied on top of a check's own rules.

.DESCRIPTION
    ProcMon's value is not that it sees events, it is that you can narrow to the ones you care
    about. Every one of these checks shipped with its filter hardcoded, so an operator chasing
    one directory had no way to say so and no way to silence a chatty logger.

    Semantics, chosen to match what an operator expects rather than what is easiest:
      - No -Include: everything the check's own rules matched stays.
      - -Include given: the path must match at least ONE include pattern.
      - -Exclude always wins over -Include, because silencing noise is the more common intent
        and an exclusion that could be overridden by an inclusion is not a silencer.
    Patterns are regexes, case-insensitive. An invalid pattern returns $true rather than
    silently dropping every event, so a typo cannot manufacture a clean result.
#>
    [CmdletBinding()]
    param(
        [string]$Path,
        [string[]]$Include,
        [string[]]$Exclude
    )
    if (-not $Path) { return $false }

    if ($Exclude) {
        foreach ($rx in $Exclude) {
            if (-not $rx) { continue }
            try { if ($Path -match $rx) { return $false } } catch { return $true }
        }
    }
    if ($Include) {
        $hit = $false
        foreach ($rx in $Include) {
            if (-not $rx) { continue }
            try { if ($Path -match $rx) { $hit = $true; break } } catch { return $true }
        }
        if (-not $hit) { return $false }
    }
    return $true
}

function Remove-TcpkEtl {
<#
.SYNOPSIS
    Delete a capture unless the caller asked to keep it, and say where it is when kept.

.DESCRIPTION
    Every one of these captures costs a human 30 seconds of exercising an application, and the
    old code deleted the ETL unconditionally including on a PARSE FAILURE, which is exactly the
    case where an operator most wants the file. -KeepEtl exists so the capture can be re-read
    with tracerpt or Windows Performance Analyzer instead of being re-recorded.
#>
    [CmdletBinding()]
    param([string]$Etl, [switch]$Keep)
    if (-not $Etl -or -not (Test-Path -LiteralPath $Etl)) { return '' }
    if ($Keep) { return $Etl }
    Remove-Item -LiteralPath $Etl -Force -ErrorAction SilentlyContinue
    return ''
}
