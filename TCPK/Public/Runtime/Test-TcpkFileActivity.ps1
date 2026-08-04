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

.PARAMETER ProcessName
    Process name without .exe extension.

.PARAMETER ProcessId
    PID of the process to trace.

.PARAMETER Seconds
    Capture duration in seconds. Default 30.

.PARAMETER InstallPath
    Optional install directory. Writes OUTSIDE this tree are flagged as unexpected.
    If omitted, only credential-named and world-writable-path writes are flagged.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding(DefaultParameterSetName = 'ByName')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'ByName')][string]$ProcessName,
        [Parameter(Mandatory, ParameterSetName = 'ById')][int]$ProcessId,
        [int]$Seconds = 30,
        [string]$InstallPath
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
        New-TcpkSkippedFinding -RuleId 'file-activity.no-process' `
            -Title "Process not found: $who"
        return
    }

    # Resolve the install path so we can detect writes outside it.
    $installDir = $null
    if ($InstallPath -and (Test-Path $InstallPath)) {
        $installDir = (Resolve-Path $InstallPath).Path.TrimEnd('\').ToLowerInvariant()
    }
    if (-not $installDir) {
        try {
            $mainMod = $proc.MainModule.FileName
            if ($mainMod) { $installDir = (Split-Path -Parent $mainMod).TrimEnd('\').ToLowerInvariant() }
        } catch { }
    }

    $sess = "TCPK-FileAct-$([Guid]::NewGuid().ToString().Substring(0, 8))"
    $etl  = Join-Path $env:TEMP "$sess.etl"
    $started = $false

    try {
        $out = & logman create trace $sess -p 'Microsoft-Windows-Kernel-File' 0xffffffff 0xff -o $etl -ets 2>&1
        if ($LASTEXITCODE -ne 0) {
            New-TcpkSkippedFinding -RuleId 'file-activity.etw-start-failed' `
                -Title "Could not start file-activity ETW session (exit $LASTEXITCODE)" `
                -Reason ($out -join ' ')
            return
        }
        $started = $true
        Write-Information -MessageData ("  Capturing {0}s of file-event ETW for {1} (pid {2}) -- exercise the app now..." -f $Seconds, $proc.ProcessName, $proc.Id) -InformationAction Continue
        Start-Sleep -Seconds $Seconds
    } finally {
        if ($started) { & logman stop $sess -ets 2>&1 | Out-Null }
    }

    if (-not (Test-Path $etl)) { return }

    # Paths that are security-relevant as output locations.
    # Note: \\Device\\ paths appear in kernel events before drive-letter translation.
    $sensPathRx = '(?i)(\\Temp\\|\\AppData\\Roaming\\|\\AppData\\Local\\|\\ProgramData\\)'
    $credNameRx = '(?i)(password|passwd|credential|token|secret|apikey|api[-_]?key|\.key$|\.pem$|\.pfx$|\.p12$|cookie|session|auth)'

    # System and ETW-noise paths: the ETW session itself, the log file, WER, etc.
    $noiseRx = '(?i)(\\Windows\\(System32|SysWOW64|WinSxS|Temp\\WER|Temp\\Etw)|\.etl$|\.log$\z)'

    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    try { $events = Get-WinEvent -Path $etl -Oldest -ErrorAction Stop } catch {
        New-TcpkSkippedFinding -RuleId 'file-activity.etw-parse-failed' `
            -Title 'Cannot parse captured file-activity ETL' -Reason $_.Exception.Message
        Remove-Item $etl -Force -ErrorAction SilentlyContinue
        return
    }

    foreach ($e in $events) {
        try { $xml = [xml]$e.ToXml() } catch { continue }
        try { $epid = [int]($xml.Event.System.Execution.ProcessID) } catch { continue }
        if ($epid -ne $proc.Id) { continue }

        $file = $null; $status = $null
        try {
            $file   = ($xml.Event.EventData.Data | Where-Object Name -eq 'FileName').'#text'
            $status = ($xml.Event.EventData.Data | Where-Object Name -eq 'Status').'#text'
        } catch { }
        if (-not $file) { continue }

        # Skip: DLL NAME NOT FOUND probes (Test-TcpkDllSearchTrace owns those)
        if ($file -match '\.dll$' -and $status -eq '0xC0000034') { continue }
        # Skip: OS noise paths and the ETL we just wrote
        if ($file -match $noiseRx) { continue }
        # Skip: Windows OS tree reads / system paths
        if ($file -match '(?i)^\\Device\\[^\\]+\\Windows\\(System32|SysWOW64|WinSxS)\\') { continue }

        $isSenspath  = $file -match $sensPathRx
        $isCredName  = $file -match $credNameRx
        # Anything outside the install dir that isn't a system path is "unexpected output"
        $isOutsideInstall = $false
        if ($installDir) {
            $fileLow = $file.ToLowerInvariant()
            # Kernel paths start with \Device\HarddiskVolume<N>\ -- normalise away the device prefix for comparison
            $fileNorm = $fileLow -replace '^\\device\\harddiskvolume\d+', ''
            $instNorm = $installDir -replace '^[a-z]:', ''
            $isOutsideInstall = $fileLow -notmatch '(?i)\\(Windows|WinSxS|System32|SysWOW64)\\' -and
                                $fileNorm -notlike "$instNorm*"
        }

        if (-not ($isSenspath -or $isCredName -or $isOutsideInstall)) { continue }
        if (-not $seen.Add($file)) { continue }

        if ($isCredName) {
            # A file whose name matches a credential pattern is worth confirming regardless of path.
            # Phase 2: ETW attributed the create/write to the target PID; filename is the proof.
            New-TcpkFinding -Module 'runtime' -RuleId 'file.write-credential-name' `
                -Severity 'HIGH' -Confidence 'Confirmed' `
                -Title "$($proc.ProcessName) wrote credential-named file: $file" `
                -File $file `
                -Evidence "PID=$($proc.Id) -- filename contains credential-related term" `
                -Cwe @('CWE-312') `
                -Description ('The process created or wrote a file with a name that matches a ' +
                    'credential pattern (password, token, key, pem, pfx, secret, cookie, etc.) ' +
                    'during the exercise window. This indicates the app may be persisting sensitive ' +
                    'material to disk. Read the file immediately after exercise to confirm whether ' +
                    'cleartext secret data is present.') `
                -Fix ('Do not write plaintext credentials or key material to disk. Use DPAPI ' +
                    '(ProtectedData.Protect) for on-disk secrets, or Windows Credential Manager. ' +
                    'If the file is a certificate bundle (.pfx/.p12), verify it is protected by a ' +
                    'strong passphrase and stored under a restricted DACL.')
        } else {
            # Path-based observation only: the app wrote to a temp or off-install-tree location.
            # This is NORMAL for many apps (temp extraction, cache, config files in AppData).
            # Confidence = Inferred -- lands in Leads, not Proven.
            # To promote to Confirmed: read the file content (is it sensitive?) and check the
            # DACL (is it readable by other users on the same machine?).
            $ruleId2 = if ($isSenspath) { 'file.write-user-writable-path' } else { 'file.write-outside-install' }
            $reason2 = if ($isSenspath) {
                'path is in a user-writable location (TEMP / AppData / ProgramData)'
            } else {
                "path is outside the inferred install directory ($installDir)"
            }
            New-TcpkFinding -Module 'runtime' -RuleId $ruleId2 `
                -Severity 'INFO' -Confidence 'Inferred' `
                -Title "Observed: $($proc.ProcessName) wrote file outside install tree: $file" `
                -File $file `
                -Evidence "PID=$($proc.Id) -- $reason2" `
                -Cwe @('CWE-377', 'CWE-732') `
                -Description ('ETW observed the target process write a file during the exercise window. ' +
                    $reason2 + '. This is an observation, not a confirmed vulnerability. ' +
                    'Many applications legitimately write to TEMP (extraction, cache) and AppData ' +
                    '(config, user data). To assess exploitability: ' +
                    '(1) read the file content -- if it contains sensitive data, escalate to Confirmed (CWE-312); ' +
                    '(2) check whether the filename is predictable (no random suffix) AND the file is ' +
                    'later opened by a higher-privilege process -- if so, this is a TOCTOU race (CWE-377); ' +
                    '(3) check the file DACL with Get-Acl -- if other local users can read it, escalate to Confirmed (CWE-732).') `
                -Fix ('No action required unless follow-up confirms sensitive content or a weak DACL. ' +
                    'For temp files: use [IO.Path]::GetTempFileName() (unique name) and set a ' +
                    'restrictive DACL immediately after creation. For config/data outside install: ' +
                    'store under a per-user subdirectory in %LOCALAPPDATA% with restricted ACL.')
        }
    }
    Remove-Item $etl -Force -ErrorAction SilentlyContinue
}
