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
    $etl  = Join-Path (Get-TcpkWorkDir -Kind 'trace') "$sess.etl"
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

        if ($isCredential) {
            # Writing a credential-named value is suspicious regardless of key path.
            # Phase 2: ETW attributed the SetValue to the target PID with a credential term.
            $title2 = if ($valName) {
                "$($proc.ProcessName) wrote credential-named registry value: $keyName -> $valName"
            } else {
                "$($proc.ProcessName) $op credential-named registry key: $keyName"
            }
            New-TcpkFinding -Module 'runtime' -RuleId 'reg.write.credential' `
                -Severity 'HIGH' -Confidence 'Confirmed' `
                -Title $title2 `
                -File $keyName `
                -Evidence "PID=$($proc.Id) op=$op" `
                -Cwe @('CWE-312') `
                -Description ('The process wrote a registry value whose name matches a credential pattern ' +
                    '(password, token, secret, apikey, etc.) during the exercise window. This indicates ' +
                    'the app may be persisting sensitive material in the registry in cleartext. ' +
                    'Retrieve the current value with: ' +
                    "Get-ItemPropertyValue 'Registry::$keyName' '$valName' " +
                    'to confirm whether cleartext secret data is present.') `
                -Fix ('Replace cleartext registry storage with Windows Credential Manager ' +
                    '(CredWrite/CredRead) or DPAPI-encrypted bytes (ProtectedData.Protect). ' +
                    'Never store plaintext tokens, passwords, or API keys in registry values.')
        } else {
            # Observation only: the app used a persistence or security-relevant registry path.
            # This is NORMAL for many applications (COM registration, service install, autorun).
            # Confidence = Inferred so it lands in Leads, not Proven.
            # To promote to Confirmed: check whether the registered path is user-writable
            # (run Test-TcpkInstallDirAcl on the value data) or the key ACL is weak (Get-Acl).
            $title2 = if ($valName) {
                "Observed: $($proc.ProcessName) wrote to $op path: $keyName -> $valName"
            } else {
                "Observed: $($proc.ProcessName) $op registry key: $keyName"
            }
            New-TcpkFinding -Module 'runtime' -RuleId 'reg.write.persistence-path' `
                -Severity 'INFO' -Confidence 'Inferred' `
                -Title $title2 `
                -File $keyName `
                -Evidence "PID=$($proc.Id) op=$op" `
                -Cwe @('CWE-269') `
                -Description ('ETW observed the target process write to a persistence or security-relevant ' +
                    'registry path during the exercise window. This is an observation, not a confirmed ' +
                    'vulnerability. Many applications legitimately write to Run keys (autorun), ' +
                    'CLSID keys (COM registration), or Services keys (service install). ' +
                    'To confirm exploitability: (1) retrieve the value data and check whether the ' +
                    'target path is user-writable with Test-TcpkInstallDirAcl -- a user-writable ' +
                    'autorun or COM path is a confirmed hijack candidate; ' +
                    '(2) check the key ACL with Get-Acl -- if non-admin users can write to the key, ' +
                    'it is a registry permission misconfiguration (CWE-732).') `
                -Fix ('No action required unless the follow-up ACL checks confirm a weakness. ' +
                    'If the registered path is user-writable, harden the ACL or move the binary ' +
                    'to a location writable only by admin/SYSTEM.')
        }
    }
    Remove-Item $etl -Force -ErrorAction SilentlyContinue
}
