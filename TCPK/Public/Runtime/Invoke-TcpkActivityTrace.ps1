function Invoke-TcpkActivityTrace {
<#
.SYNOPSIS
    E24. One ETW capture window, analysed three ways: DLL probes, file writes, registry writes.

.DESCRIPTION
    The ProcMon-equivalent entry point. Starts a SINGLE logman session carrying both the
    kernel file and kernel registry providers, waits while the operator exercises the target,
    then runs all three analysers over the one capture.

    WHY THIS EXISTS. Test-TcpkDllSearchTrace, Test-TcpkFileActivity and Test-TcpkRegistryWrites
    each opened their own session. The first two subscribe to the SAME provider, and the audit
    ran all three in sequence at 30 seconds each. That cost the operator three separate
    exercise cycles for one question, and because the two file captures came from different
    windows, a DLL probe and the write that followed it could never be correlated. They can now.

    WHAT IT DOES NOT DO. This is not ProcMon. There are no per-event call stacks (that needs a
    kernel driver), and reads and queries are not captured, only creates, writes and probes.
    Where ProcMon shows you everything and asks you to filter, this applies a security rule set
    and reports findings. -Include and -Exclude narrow it further.

    Requires admin. Exercise the application during the capture window.

.PARAMETER ProcessName
    Process name, with or without .exe.

.PARAMETER ProcessId
    PID to trace.

.PARAMETER Seconds
    Capture duration. Default 30.

.PARAMETER InstallPath
    Install directory. Writes outside this tree are flagged as unexpected output. Inferred from
    the process main module when omitted.

.PARAMETER Include
    Regex patterns. A path must match at least one to be considered. Applied on top of each
    check's own rules, never instead of them.

.PARAMETER Exclude
    Regex patterns. A matching path is dropped. Exclude beats Include: silencing a chatty
    logger is the common intent, and an exclusion that Include could override would not silence.

.PARAMETER IncludeChildren
    Also attribute events raised by child processes of the target. Off by default because it
    widens the result set; on is usually what you want for an app that spawns helpers.

.PARAMETER KeepEtl
    Keep the .etl instead of deleting it, and name its path in the summary finding. A capture
    costs 30 seconds of human interaction; re-reading it in Windows Performance Analyzer beats
    re-recording it.

.PARAMETER Check
    Which analysers to run. Default all three.

.EXAMPLE
    Invoke-TcpkActivityTrace -ProcessName MyApp -Seconds 45 -IncludeChildren -KeepEtl

.EXAMPLE
    # Narrow to one directory and silence the app's own log writes
    Invoke-TcpkActivityTrace -ProcessName MyApp -Include '\\ProgramData\\Acme\\' -Exclude '\.log$'

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding(DefaultParameterSetName = 'ByName')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'ByName')][string]$ProcessName,
        [Parameter(Mandatory, ParameterSetName = 'ById')][int]$ProcessId,
        [int]$Seconds = 30,
        [string]$InstallPath,
        [string[]]$Include,
        [string[]]$Exclude,
        [switch]$IncludeChildren,
        [switch]$KeepEtl,
        [ValidateSet('DllSearch', 'FileWrites', 'RegistryWrites')]
        [string[]]$Check = @('DllSearch', 'FileWrites', 'RegistryWrites')
    )

    if (-not (Assert-TcpkWindows 'Invoke-TcpkActivityTrace')) { return }
    if (-not (Test-TcpkIsAdmin)) {
        New-TcpkSkippedFinding -RuleId 'activity-trace.skipped-no-admin' `
            -Title 'Activity trace skipped (admin required)'
        return
    }

    $proc = if ($PSCmdlet.ParameterSetName -eq 'ByName') {
        Get-Process -Name ($ProcessName -replace '\.exe$', '') -ErrorAction SilentlyContinue | Select-Object -First 1
    } else {
        Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
    }
    if (-not $proc) {
        $who = if ($PSCmdlet.ParameterSetName -eq 'ByName') { $ProcessName } else { "pid $ProcessId" }
        New-TcpkSkippedFinding -RuleId 'activity-trace.no-process' -Title "Process not found: $who"
        return
    }

    $installDir = ''
    if ($InstallPath -and (Test-Path -LiteralPath $InstallPath)) {
        $installDir = (Resolve-Path -LiteralPath $InstallPath).Path.TrimEnd('\').ToLowerInvariant()
    }
    if (-not $installDir) {
        try {
            $mainMod = $proc.MainModule.FileName
            if ($mainMod) { $installDir = (Split-Path -Parent $mainMod).TrimEnd('\').ToLowerInvariant() }
        } catch { }
    }

    # Kernel file provider by name, kernel registry provider by GUID (documented, stable
    # across Win10/11). Both in ONE session so every event shares a clock and a window.
    $providers = @()
    if ($Check -contains 'DllSearch' -or $Check -contains 'FileWrites') { $providers += 'Microsoft-Windows-Kernel-File' }
    if ($Check -contains 'RegistryWrites') { $providers += '{70EB4F03-C1DE-4F73-A051-33D13D5413BD}' }
    if (-not $providers.Count) { return }

    $pidsBefore = Get-TcpkProcessTreeId -ProcessId $proc.Id
    $sess = Start-TcpkEtwCapture -Provider $providers -Label 'Activity'
    if (-not $sess.Started) {
        New-TcpkSkippedFinding -RuleId 'activity-trace.etw-start-failed' `
            -Title 'Could not start the activity ETW session' -Reason $sess.Reason
        return
    }

    try {
        Write-Information -MessageData ("  Capturing {0}s of file+registry ETW for {1} (pid {2}) -- exercise the app now..." -f $Seconds, $proc.ProcessName, $proc.Id) -InformationAction Continue
        if ($Seconds -gt 0) { Start-Sleep -Seconds $Seconds }
    } finally {
        Stop-TcpkEtwCapture -Session $sess
    }

    # Union of the trees seen before and after. A child that both started and exited inside the
    # window is still missed; that limit is stated on Get-TcpkProcessTreeId rather than hidden.
    $pids = $pidsBefore
    if ($IncludeChildren) {
        foreach ($p in (Get-TcpkProcessTreeId -ProcessId $proc.Id)) { [void]$pids.Add($p) }
    } else {
        $pids = [System.Collections.Generic.HashSet[int]]::new()
        [void]$pids.Add($proc.Id)
    }

    $events = $null
    try { $events = Read-TcpkEtwEvents -Etl $sess.Etl -ProcessIds $pids }
    catch {
        # Keep the ETL on a parse failure regardless of -KeepEtl. This is precisely the case
        # where the operator wants the file, and the old code deleted it here.
        New-TcpkSkippedFinding -RuleId 'activity-trace.etw-parse-failed' `
            -Title 'Cannot parse the captured ETL' `
            -Reason "$($_.Exception.Message) -- capture retained at $($sess.Etl)"
        return
    }

    if ($Check -contains 'DllSearch') {
        ConvertTo-TcpkDllSearchFinding -Events $events -ProcName $proc.ProcessName -Include $Include -Exclude $Exclude
    }
    if ($Check -contains 'FileWrites') {
        ConvertTo-TcpkFileActivityFinding -Events $events -ProcName $proc.ProcessName -InstallDir $installDir -Include $Include -Exclude $Exclude
    }
    if ($Check -contains 'RegistryWrites') {
        ConvertTo-TcpkRegistryFinding -Events $events -ProcName $proc.ProcessName -Include $Include -Exclude $Exclude
    }

    $kept = Remove-TcpkEtl -Etl $sess.Etl -Keep:$KeepEtl

    # State what the window actually saw. Zero findings from a capture that recorded 40,000
    # events means something different from zero findings from a capture that recorded none,
    # and without this line the report cannot tell them apart.
    $ev = "events=$(@($events).Count) pids=$(($pids | Sort-Object) -join ',') seconds=$Seconds providers=$($sess.Providers -join ',')"
    if ($sess.FailedProviders -and $sess.FailedProviders.Count) { $ev += " FAILED-PROVIDERS=$($sess.FailedProviders -join ',')" }
    if ($kept) { $ev += " etl=$kept" }
    New-TcpkFinding -Module 'runtime' -RuleId 'activity-trace.window' `
        -Severity 'INFO' -Confidence 'Confirmed' `
        -Title "Activity trace captured $(@($events).Count) event(s) for $($proc.ProcessName) over ${Seconds}s" `
        -File $proc.ProcessName -Evidence $ev `
        -Description ('Scope line for the capture window. A check that reported nothing over a ' +
            'window that recorded no events was not answered; a check that reported nothing over ' +
            'a window full of events was. Read this before treating any absent finding above as ' +
            'a clean result. If a provider failed to attach it is named here, and the checks ' +
            'depending on it saw nothing at all.') `
        -Fix 'Not a defect. Re-run with a longer -Seconds, with -IncludeChildren, or exercise more of the application if the event count looks low.'
}
