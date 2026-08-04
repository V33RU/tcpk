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

.PARAMETER ProcessName
    Process name without .exe extension.

.PARAMETER ProcessId
    PID of the process to trace.

.PARAMETER Seconds
    Capture duration in seconds. Default 30. Set to 0 to return immediately after
    starting the session (useful for scripted orchestration -- stop the session
    manually with logman stop).

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding(DefaultParameterSetName = 'ByName')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'ByName')][string]$ProcessName,
        [Parameter(Mandatory, ParameterSetName = 'ById')][int]$ProcessId,
        [int]$Seconds = 30
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
        New-TcpkSkippedFinding -RuleId 'reg-writes.no-process' `
            -Title "Process not found: $who"
        return
    }

    $sess = "TCPK-RegWrites-$([Guid]::NewGuid().ToString().Substring(0, 8))"
    $etl  = Join-Path $env:TEMP "$sess.etl"
    $started = $false

    # Provider GUID for kernel-mode registry operations (documented, stable across Win10/11).
    # 0xffffffff captures all keyword flags (OpenKey, CreateKey, SetValue, DeleteKey, etc.).
    $provider = '{70EB4F03-C1DE-4F73-A051-33D13D5413BD}'
    try {
        $out = & logman create trace $sess -p $provider 0xffffffff 0xff -o $etl -ets 2>&1
        if ($LASTEXITCODE -ne 0) {
            New-TcpkSkippedFinding -RuleId 'reg-writes.etw-start-failed' `
                -Title "Could not start registry ETW session (exit $LASTEXITCODE)" `
                -Reason ($out -join ' ')
            return
        }
        $started = $true
        Write-Information -MessageData ("  Capturing {0}s of registry ETW for {1} (pid {2}) -- exercise the app now..." -f $Seconds, $proc.ProcessName, $proc.Id) -InformationAction Continue
        if ($Seconds -gt 0) { Start-Sleep -Seconds $Seconds }
    } finally {
        if ($started) { & logman stop $sess -ets 2>&1 | Out-Null }
    }

    if (-not (Test-Path $etl)) { return }

    # Key paths that are security-relevant: persistence, hijack, credential storage,
    # service/driver configuration, privilege escalation via IFEO or AppInit.
    $sensitiveRx = '(?i)(\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' +
        '|\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' +
        '|\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options' +
        '|\\System\\CurrentControlSet\\Services' +
        '|\\Software\\Classes\\CLSID' +
        '|\\Software\\Classes\\Interface' +
        '|\\Software\\Microsoft\\Windows\\CurrentVersion\\App Paths' +
        '|\\Software\\Microsoft\\Windows\\CurrentVersion\\ShellServiceObjectDelayLoad' +
        '|\\Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags' +
        '|\\Software\\Policies' +
        '|AppInit_DLLs' +
        '|password|passwd|credential|token|secret|apikey|api_key)'

    $credTermRx = '(?i)(password|passwd|credential|token|secret|apikey|api_key)'

    # Event IDs for the kernel-registry provider (documented in Microsoft ETW reference).
    $writeIds = [System.Collections.Generic.HashSet[int]]@(5, 6, 13, 14)
    # 5 = SetValue, 6 = DeleteValue, 13 = CreateKey, 14 = DeleteKey

    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    try { $events = Get-WinEvent -Path $etl -Oldest -ErrorAction Stop } catch {
        New-TcpkSkippedFinding -RuleId 'reg-writes.etw-parse-failed' `
            -Title 'Cannot parse captured registry ETL' -Reason $_.Exception.Message
        Remove-Item $etl -Force -ErrorAction SilentlyContinue
        return
    }

    foreach ($e in $events) {
        if (-not $writeIds.Contains($e.Id)) { continue }
        try { $xml = [xml]$e.ToXml() } catch { continue }
        try { $epid = [int]($xml.Event.System.Execution.ProcessID) } catch { continue }
        if ($epid -ne $proc.Id) { continue }

        $keyName = $null; $valName = $null
        try {
            $keyName = ($xml.Event.EventData.Data | Where-Object Name -eq 'KeyName').'#text'
            $valName = ($xml.Event.EventData.Data | Where-Object Name -eq 'ValueName').'#text'
        } catch { }
        # Fallback: some builds emit the MOF message string instead of structured EventData.
        if (-not $keyName -and $e.Message) {
            if ($e.Message -match 'KeyName\s*:\s*(.+?)(?:\r?\n|$)') { $keyName = $matches[1].Trim() }
            if ($e.Message -match 'ValueName\s*:\s*(.+?)(?:\r?\n|$)') { $valName = $matches[1].Trim() }
        }
        if (-not $keyName) { continue }
        if ($keyName -notmatch $sensitiveRx -and "$valName" -notmatch $sensitiveRx) { continue }

        $op = switch ($e.Id) {
            5  { 'SetValue' }
            6  { 'DeleteValue' }
            13 { 'CreateKey' }
            14 { 'DeleteKey' }
            default { "op$($e.Id)" }
        }
        $uniq = "$op|$keyName|$valName"
        if (-not $seen.Add($uniq)) { continue }

        $isCredential = ($keyName -match $credTermRx -or "$valName" -match $credTermRx)
        $severity = if ($isCredential) { 'HIGH' } else { 'MEDIUM' }
        $title = if ($valName) {
            "$($proc.ProcessName) wrote registry value: $keyName -> $valName"
        } else {
            "$($proc.ProcessName) $op registry key: $keyName"
        }
        New-TcpkFinding -Module 'runtime' -RuleId 'reg.write' `
            -Severity $severity -Confidence 'Confirmed' `
            -Title $title `
            -File $keyName `
            -Evidence "PID=$($proc.Id) op=$op" `
            -Cwe @('CWE-312', 'CWE-269') `
            -Description ('The process wrote to a persistence or security-relevant registry key during ' +
                'the capture window. Persistence keys can be used for privilege escalation or persistence ' +
                'if the key or its directory is writable by non-admin users. Credential values should use ' +
                'DPAPI-backed storage instead of cleartext registry values.') `
            -Fix ('Confirm the write is intentional. If it stores credentials, use Windows Credential ' +
                'Manager or DPAPI-encrypted values. If it registers a COM class or service path, verify ' +
                'the target path is not user-writable (combine with Test-TcpkInstallDirAcl).')
    }
    Remove-Item $etl -Force -ErrorAction SilentlyContinue
}
