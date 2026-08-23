#requires -Version 5.1
# Analysers for a captured ETW window. Pure functions over normalised records from
# Read-TcpkEtwEvents: no session, no admin, no sleep, therefore testable.
#
# One capture can be run through all three. That is the point: a DLL probe that got NAME NOT
# FOUND and the file the app wrote a moment later now come from the same window and can be
# reasoned about together, which was impossible when each check recorded its own.
#
# Rule ids, severities, CWEs and finding text are carried over unchanged from the three
# cmdlets these were extracted from. Only the attribution improved: evidence now names the PID
# that actually raised the event, which may be a child of the target rather than the target.

function ConvertTo-TcpkDllSearchFinding {
    [CmdletBinding()]
    param($Events, [string]$ProcName, [string[]]$Include, [string[]]$Exclude)

    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($ev in $Events) {
        if ($ev.Kind -ne 'file') { continue }
        $file = $ev.Path
        if (-not $file -or -not $ev.Status) { continue }
        # STATUS_OBJECT_NAME_NOT_FOUND against a .dll is the whole signal: the loader asked a
        # directory for a library that is not there, so a writable directory earlier in the
        # search order wins the next time it asks.
        if ($file -notmatch '\.dll$' -or $ev.Status -ne '0xC0000034') { continue }
        if (-not (Test-TcpkEtwPathFilter -Path $file -Include $Include -Exclude $Exclude)) { continue }
        if (-not $seen.Add("$($ev.ProcessId)|$file")) { continue }

        New-TcpkFinding -Module 'runtime' -RuleId 'dll-search.name-not-found' `
            -Severity 'HIGH' -Confidence 'Confirmed' `
            -Title "$ProcName probed $file and got NAME NOT FOUND" `
            -File $file -Evidence "PID=$($ev.ProcessId) status=$($ev.Status)" `
            -Cwe @('CWE-427') `
            -Fix 'Patch the call site to use a full path or LOAD_LIBRARY_SEARCH_SYSTEM32.'
    }
}

function ConvertTo-TcpkFileActivityFinding {
    [CmdletBinding()]
    param($Events, [string]$ProcName, [string]$InstallDir, [string[]]$Include, [string[]]$Exclude)

    $sensPathRx = '(?i)(\\Temp\\|\\AppData\\Roaming\\|\\AppData\\Local\\|\\ProgramData\\)'
    $credNameRx = '(?i)(password|passwd|credential|token|secret|apikey|api[-_]?key|\.key$|\.pem$|\.pfx$|\.p12$|cookie|session|auth)'
    # System and ETW-noise paths: the session's own ETL, WER, the OS tree.
    $noiseRx    = '(?i)(\\Windows\\(System32|SysWOW64|WinSxS|Temp\\WER|Temp\\Etw)|\.etl$|\.log$)'

    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($ev in $Events) {
        if ($ev.Kind -ne 'file') { continue }
        $file = $ev.Path
        if (-not $file) { continue }
        # DLL NAME NOT FOUND probes belong to ConvertTo-TcpkDllSearchFinding.
        if ($file -match '\.dll$' -and $ev.Status -eq '0xC0000034') { continue }
        if ($file -match $noiseRx) { continue }
        if ($file -match '(?i)^\\Device\\[^\\]+\\Windows\\(System32|SysWOW64|WinSxS)\\') { continue }
        if (-not (Test-TcpkEtwPathFilter -Path $file -Include $Include -Exclude $Exclude)) { continue }

        $isSenspath = $file -match $sensPathRx
        $isCredName = $file -match $credNameRx
        $isOutsideInstall = $false
        if ($InstallDir) {
            $fileLow = $file.ToLowerInvariant()
            # Kernel paths are \Device\HarddiskVolumeN\... ; drop the device prefix to compare.
            $fileNorm = $fileLow -replace '^\\device\\harddiskvolume\d+', ''
            $instNorm = $InstallDir -replace '^[a-z]:', ''
            $isOutsideInstall = $fileLow -notmatch '(?i)\\(Windows|WinSxS|System32|SysWOW64)\\' -and
                                $fileNorm -notlike "$instNorm*"
        }

        if (-not ($isSenspath -or $isCredName -or $isOutsideInstall)) { continue }
        if (-not $seen.Add($file)) { continue }

        if ($isCredName) {
            New-TcpkFinding -Module 'runtime' -RuleId 'file.write-credential-name' `
                -Severity 'HIGH' -Confidence 'Confirmed' `
                -Title "$ProcName wrote credential-named file: $file" `
                -File $file `
                -Evidence "PID=$($ev.ProcessId) -- filename contains credential-related term" `
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
            $ruleId2 = if ($isSenspath) { 'file.write-user-writable-path' } else { 'file.write-outside-install' }
            $reason2 = if ($isSenspath) {
                'path is in a user-writable location (TEMP / AppData / ProgramData)'
            } else {
                "path is outside the inferred install directory ($InstallDir)"
            }
            New-TcpkFinding -Module 'runtime' -RuleId $ruleId2 `
                -Severity 'INFO' -Confidence 'Inferred' `
                -Title "Observed: $ProcName wrote file outside install tree: $file" `
                -File $file `
                -Evidence "PID=$($ev.ProcessId) -- $reason2" `
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
}

function ConvertTo-TcpkRegistryFinding {
    [CmdletBinding()]
    param($Events, [string]$ProcName, [string[]]$Include, [string[]]$Exclude)

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

    # 5 SetValue, 6 DeleteValue, 13 CreateKey, 14 DeleteKey.
    $writeIds = [System.Collections.Generic.HashSet[int]]@(5, 6, 13, 14)
    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($ev in $Events) {
        if ($ev.Kind -ne 'registry') { continue }
        if (-not $writeIds.Contains([int]$ev.EventId)) { continue }
        $keyName = $ev.Path
        $valName = $ev.ValueName
        if (-not $keyName) { continue }
        if (-not (Test-TcpkEtwPathFilter -Path $keyName -Include $Include -Exclude $Exclude)) { continue }
        if ($keyName -notmatch $sensitiveRx -and "$valName" -notmatch $sensitiveRx) { continue }

        $op = switch ([int]$ev.EventId) {
            5  { 'SetValue' }
            6  { 'DeleteValue' }
            13 { 'CreateKey' }
            14 { 'DeleteKey' }
            default { "op$($ev.EventId)" }
        }
        $uniq = "$op|$keyName|$valName"
        if (-not $seen.Add($uniq)) { continue }

        $isCredential = ($keyName -match $credTermRx -or "$valName" -match $credTermRx)

        if ($isCredential) {
            # Writing a credential-named value is suspicious regardless of key path.
            # Phase 2: ETW attributed the SetValue to the target PID with a credential term.
            $title2 = if ($valName) {
                "$ProcName wrote credential-named registry value: $keyName -> $valName"
            } else {
                "$ProcName $op credential-named registry key: $keyName"
            }
            New-TcpkFinding -Module 'runtime' -RuleId 'reg.write.credential' `
                -Severity 'HIGH' -Confidence 'Confirmed' `
                -Title $title2 `
                -File $keyName `
                -Evidence "PID=$($ev.ProcessId) op=$op" `
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
            $title2 = if ($valName) {
                "Observed: $ProcName wrote to $op path: $keyName -> $valName"
            } else {
                "Observed: $ProcName $op registry key: $keyName"
            }
            New-TcpkFinding -Module 'runtime' -RuleId 'reg.write.persistence-path' `
                -Severity 'INFO' -Confidence 'Inferred' `
                -Title $title2 `
                -File $keyName `
                -Evidence "PID=$($ev.ProcessId) op=$op" `
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
}
