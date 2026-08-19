function Test-TcpkDllSearchTrace {
<#
.SYNOPSIS
    E08. ETW capture of NAME NOT FOUND DLL probes during a window.

.DESCRIPTION
    Starts a kernel-file ETW session, captures Microsoft-Windows-Kernel-File
    events for -Seconds seconds, filters to the target PID, and emits a
    HIGH finding for each *.dll probe that returned 0xC0000034
    (STATUS_OBJECT_NAME_NOT_FOUND). Each such probe is a runtime-confirmed
    hijack candidate.

    Requires admin. Operator should exercise the app during the window.

    The capture is now shared: this cmdlet keeps its own single-provider session for standalone
    use, but Invoke-TcpkActivityTrace runs one window across both providers and dispatches to
    every analyser, which is what the audit uses. The rule logic lives in _EtwRules.ps1 so a fix
    applies to both paths instead of only the one that was edited.

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

    if (-not (Assert-TcpkWindows 'Test-TcpkDllSearchTrace')) { return }
    if (-not (Test-TcpkIsAdmin)) {
        New-TcpkSkippedFinding -RuleId 'dll-search.skipped-no-admin' `
            -Title 'DLL search-order ETW trace skipped (admin required)'
        return
    }

    $proc = if ($PSCmdlet.ParameterSetName -eq 'ByName') {
        Get-Process -Name ($ProcessName -replace '\.exe$', '') -ErrorAction SilentlyContinue | Select-Object -First 1
    } else {
        Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
    }
    if (-not $proc) {
        $who = if ($PSCmdlet.ParameterSetName -eq 'ByName') { $ProcessName } else { "pid $ProcessId" }
        New-TcpkSkippedFinding -RuleId 'dll-search.no-process' -Title "Process not found: $who"
        return
    }

    $sess = Start-TcpkEtwCapture -Provider @('Microsoft-Windows-Kernel-File') -Label 'DllSearch'
    if (-not $sess.Started) {
        New-TcpkSkippedFinding -RuleId 'dll-search.etw-start-failed' `
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
        New-TcpkSkippedFinding -RuleId 'dll-search.etw-parse-failed' `
            -Title 'Cannot parse the captured ETL' `
            -Reason "$($_.Exception.Message) -- capture retained at $($sess.Etl)"
        return
    }

    ConvertTo-TcpkDllSearchFinding -Events $events -ProcName $proc.ProcessName -Include $Include -Exclude $Exclude

    [void](Remove-TcpkEtl -Etl $sess.Etl -Keep:$KeepEtl)
}
