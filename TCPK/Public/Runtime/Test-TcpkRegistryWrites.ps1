function Test-TcpkRegistryWrites {
<#
.SYNOPSIS
    E11. Registry writes by a running process during an exercise window (ETW).

.DESCRIPTION
    Starts a Kernel-Registry ETW session for -Seconds seconds while the operator
    exercises the target application, then parses the captured trace for write
    operations attributed to the target process.

    Flags writes to persistence-relevant paths: autorun keys, service configuration,
    COM / shell-extension registration, IFEO, AppInit, and any value whose name
    contains credential-related terms.

    Each finding represents a confirmed runtime write, not a static guess. The ETL
    is deleted after parsing.

    Requires admin. Exercise the app (log in, trigger workflows, change settings)
    during the capture window.

    The capture is now shared: this cmdlet keeps its own single-provider session for standalone
    use, but Invoke-TcpkActivityTrace runs one window across both providers and dispatches to
    every analyser, which is what the audit uses. The rule logic lives in _EtwRules.ps1 so a fix
    applies to both paths instead of only the one that was edited.


.PARAMETER ProcessName
    Process name without .exe extension.

.PARAMETER ProcessId
    PID of the process to trace.

.PARAMETER Seconds
    Capture duration in seconds. Default 30. Set to 0 to return immediately after
    starting the session (useful for scripted orchestration -- stop the session
    manually with logman stop).

.PARAMETER Include
    Regex patterns. A path must match at least one to be considered. Applied on top of this
    check's own rules, never instead of them.

.PARAMETER Exclude
    Regex patterns. A matching path is dropped. Exclude beats Include.

.PARAMETER IncludeChildren
    Also attribute events raised by child processes of the target.

.PARAMETER KeepEtl
    Keep the .etl instead of deleting it. A capture costs the operator a full exercise window;
    re-reading it in Windows Performance Analyzer beats re-recording it. Kept unconditionally
    when parsing fails, which is exactly when it is wanted.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding(DefaultParameterSetName = 'ByName')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'ByName')][string]$ProcessName,
        [Parameter(Mandatory, ParameterSetName = 'ById')][int]$ProcessId,
        [int]$Seconds = 30,
        [string[]]$Include,
        [string[]]$Exclude,
        [switch]$IncludeChildren,
        [switch]$KeepEtl
    )

    if (-not (Assert-TcpkWindows 'Test-TcpkRegistryWrites')) { return }
    if (-not (Test-TcpkIsAdmin)) {
        New-TcpkSkippedFinding -RuleId 'reg-writes.skipped-no-admin' `
            -Title 'Registry-write ETW trace skipped (admin required)'
        return
    }

    $proc = if ($PSCmdlet.ParameterSetName -eq 'ByName') {
        Get-Process -Name ($ProcessName -replace '\.exe$', '') -ErrorAction SilentlyContinue | Select-Object -First 1
    } else {
        Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
    }
    if (-not $proc) {
        $who = if ($PSCmdlet.ParameterSetName -eq 'ByName') { $ProcessName } else { "pid $ProcessId" }
        New-TcpkSkippedFinding -RuleId 'reg-writes.no-process' -Title "Process not found: $who"
        return
    }

    $sess = Start-TcpkEtwCapture -Provider @('{70EB4F03-C1DE-4F73-A051-33D13D5413BD}') -Label 'RegWrites'
    if (-not $sess.Started) {
        New-TcpkSkippedFinding -RuleId 'reg-writes.etw-start-failed' `
            -Title 'Could not start the ETW session' -Reason $sess.Reason
        return
    }

    try {
        Write-Information -MessageData ("  Capturing {0}s of ETW for {1} (pid {2}) -- exercise the app now..." -f $Seconds, $proc.ProcessName, $proc.Id) -InformationAction Continue
        if ($Seconds -gt 0) { Start-Sleep -Seconds $Seconds }
    } finally {
        Stop-TcpkEtwCapture -Session $sess
    }

    $pids = [System.Collections.Generic.HashSet[int]]::new()
    [void]$pids.Add($proc.Id)
    if ($IncludeChildren) {
        foreach ($p in (Get-TcpkProcessTreeId -ProcessId $proc.Id)) { [void]$pids.Add($p) }
    }

    $events = $null
    try { $events = Read-TcpkEtwEvents -Etl $sess.Etl -ProcessIds $pids }
    catch {
        # The ETL is KEPT here regardless of -KeepEtl. A parse failure is the one case where
        # the operator most wants the capture, and the previous version deleted it.
        New-TcpkSkippedFinding -RuleId 'reg-writes.etw-parse-failed' `
            -Title 'Cannot parse the captured ETL' `
            -Reason "$($_.Exception.Message) -- capture retained at $($sess.Etl)"
        return
    }

    ConvertTo-TcpkRegistryFinding -Events $events -ProcName $proc.ProcessName -Include $Include -Exclude $Exclude

    [void](Remove-TcpkEtl -Etl $sess.Etl -Keep:$KeepEtl)
}
