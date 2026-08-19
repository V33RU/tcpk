function Test-TcpkFileActivity {
<#
.SYNOPSIS
    E12. File creates and writes to sensitive paths during an exercise window (ETW).

.DESCRIPTION
    Starts a Kernel-File ETW session for -Seconds seconds while the operator
    exercises the target application, then parses the captured trace for file
    creation and write events attributed to the target process.

    Flags writes to paths that are security-relevant:
      - TEMP / AppData / ProgramData  (world-writable outputs, race-condition targets)
      - Files whose name contains credential-related terms (.key, .pem, .pfx, token, etc.)
      - Files outside the application's own install directory
        (unexpected output paths that may represent data leakage)

    Companion to Test-TcpkDllSearchTrace. That cmdlet captures NAME NOT FOUND probes
    (DLL hijack candidates). This one captures successful creates and writes.

    Requires admin. Exercise the app during the capture window.

    The capture is now shared: this cmdlet keeps its own single-provider session for standalone
    use, but Invoke-TcpkActivityTrace runs one window across both providers and dispatches to
    every analyser, which is what the audit uses. The rule logic lives in _EtwRules.ps1 so a fix
    applies to both paths instead of only the one that was edited.


.PARAMETER ProcessName
    Process name without .exe extension.

.PARAMETER ProcessId
    PID of the process to trace.

.PARAMETER Seconds
    Capture duration in seconds. Default 30.

.PARAMETER InstallPath
    Optional install directory. Writes OUTSIDE this tree are flagged as unexpected.
    If omitted, only credential-named and world-writable-path writes are flagged.

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
        [string]$InstallPath,
        [string[]]$Include,
        [string[]]$Exclude,
        [switch]$IncludeChildren,
        [switch]$KeepEtl
    )

    if (-not (Assert-TcpkWindows 'Test-TcpkFileActivity')) { return }
    if (-not (Test-TcpkIsAdmin)) {
        New-TcpkSkippedFinding -RuleId 'file-activity.skipped-no-admin' `
            -Title 'File-activity ETW trace skipped (admin required)'
        return
    }

    $proc = if ($PSCmdlet.ParameterSetName -eq 'ByName') {
        Get-Process -Name ($ProcessName -replace '\.exe$', '') -ErrorAction SilentlyContinue | Select-Object -First 1
    } else {
        Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
    }
    if (-not $proc) {
        $who = if ($PSCmdlet.ParameterSetName -eq 'ByName') { $ProcessName } else { "pid $ProcessId" }
        New-TcpkSkippedFinding -RuleId 'file-activity.no-process' -Title "Process not found: $who"
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

    $sess = Start-TcpkEtwCapture -Provider @('Microsoft-Windows-Kernel-File') -Label 'FileAct'
    if (-not $sess.Started) {
        New-TcpkSkippedFinding -RuleId 'file-activity.etw-start-failed' `
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
        New-TcpkSkippedFinding -RuleId 'file-activity.etw-parse-failed' `
            -Title 'Cannot parse the captured ETL' `
            -Reason "$($_.Exception.Message) -- capture retained at $($sess.Etl)"
        return
    }

    ConvertTo-TcpkFileActivityFinding -Events $events -ProcName $proc.ProcessName -InstallDir $installDir -Include $Include -Exclude $Exclude

    [void](Remove-TcpkEtl -Etl $sess.Etl -Keep:$KeepEtl)
}
