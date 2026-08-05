function Test-TcpkHollowingApis {
<#
.SYNOPSIS
    Detect process hollowing / injection API patterns in native and .NET PEs.

.DESCRIPTION
    Process hollowing requires: CreateProcess(SUSPENDED) -> NtUnmapViewOfSection ->
    VirtualAllocEx -> WriteProcessMemory -> SetThreadContext -> ResumeThread.
    SetThreadContext (or NtSetContextThread) is MANDATORY: without redirecting the
    thread context the replaced code never executes.

    DLL injection requires: VirtualAllocEx -> WriteProcessMemory -> CreateRemoteThread.
    APC injection: VirtualAllocEx -> QueueUserAPC / NtQueueApcThread.

    API provenance is classified per PE import/delay-import table parse:
      imported        - in the PE import directory (resolved at load time)
      delay-imported  - in the delay-load directory (resolved at first call)
      string-ref      - string present in the binary but NOT in either import table;
                        this is the GetProcAddress/LoadLibrary lookup pattern.
                        String-ref-only APIs contribute to MEDIUM findings only.

    Chromium / Electron / Sandbox context:
    VirtualAllocEx + WriteProcessMemory + ResumeThread is the exact sequence
    Chromium's sandbox broker uses to create, configure and start a sandboxed
    child process.  When sandbox/crashpad markers are present, this sequence is
    the documented process model of the runtime, not an injection capability.
    These findings are suppressed to INFO in that context.

    Google Cloud / hasherezade 2025 reference.

.PARAMETER Path
    File or directory to scan.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    # All APIs of interest, grouped by role
    $unmapApis   = @('NtUnmapViewOfSection','ZwUnmapViewOfSection')
    $writeApis   = @('WriteProcessMemory','NtWriteVirtualMemory')
    $allocApis   = @('VirtualAllocEx','NtAllocateVirtualMemory')
    $threadApis  = @('CreateRemoteThread','RtlCreateUserThread','NtCreateThreadEx')
    $contextApis = @('SetThreadContext','NtSetContextThread')
    $resumeApis  = @('ResumeThread','NtResumeThread')
    $apcApis     = @('QueueUserAPC','NtQueueApcThread','NtQueueApcThreadEx')
    $mapApis     = @('NtMapViewOfSection','NtCreateSection')
    $allApis     = $unmapApis + $writeApis + $allocApis + $threadApis +
                   $contextApis + $resumeApis + $apcApis + $mapApis

    # Thresholds that indicate this is a Chromium/Electron runtime binary.
    # Chromium's sandbox broker creates child processes with exactly VirtualAllocEx +
    # WriteProcessMemory + ResumeThread; Crashpad uses SuspendThread + GetThreadContext.
    # False-positive hollowing/dll-inject findings on these binaries are structural noise.
    $sandboxThreshold  = 50   # occurrences of "sandbox" in the binary
    $crashpadThreshold = 10   # occurrences of "crashpad"

    foreach ($pe in Get-TcpkPeFiles -Path $Path) {
        if (Test-TcpkIsFrameworkFile $pe.Name) { continue }

        $text = Read-TcpkAllText -Path $pe.FullName
        if (-not $text) { continue }

        # Step 1: string-scan to get candidates (fast)
        $candidates = @($allApis | Where-Object { $text.Contains($_) })
        if ($candidates.Count -eq 0) { continue }

        # Step 2: parse import tables for provenance
        $importInfo = $null
        try { $importInfo = Get-TcpkPeFunctionImports -Path $pe.FullName } catch { }

        # Collect every imported / delay-imported function name (case-insensitive)
        $importedFuncs = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
        $delayFuncs    = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
        if ($importInfo) {
            foreach ($dll in $importInfo.Imported.Keys) {
                foreach ($fn in $importInfo.Imported[$dll]) { [void]$importedFuncs.Add($fn) }
            }
            foreach ($dll in $importInfo.DelayImported.Keys) {
                foreach ($fn in $importInfo.DelayImported[$dll]) { [void]$delayFuncs.Add($fn) }
            }
        }

        # Classify each candidate into provenance buckets
        $byProvenance = @{ imported=@(); delay=@(); stringRef=@() }
        foreach ($api in $candidates) {
            if ($importedFuncs.Contains($api)) {
                $byProvenance.imported += $api
            } elseif ($delayFuncs.Contains($api)) {
                $byProvenance.delay += $api
            } else {
                $byProvenance.stringRef += $api
            }
        }

        # "Has" predicates: an API COUNTS for sequence detection only when imported or delay-imported.
        # String-only occurrences are GetProcAddress lookup strings and do not prove the API is used.
        $trueFound = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($a in ($byProvenance.imported + $byProvenance.delay)) { [void]$trueFound.Add($a) }

        $hasUnmap   = ($unmapApis   | Where-Object { $trueFound.Contains($_) }).Count -gt 0
        $hasWrite   = ($writeApis   | Where-Object { $trueFound.Contains($_) }).Count -gt 0
        $hasAlloc   = ($allocApis   | Where-Object { $trueFound.Contains($_) }).Count -gt 0
        $hasThread  = ($threadApis  | Where-Object { $trueFound.Contains($_) }).Count -gt 0
        $hasContext = ($contextApis | Where-Object { $trueFound.Contains($_) }).Count -gt 0
        $hasResume  = ($resumeApis  | Where-Object { $trueFound.Contains($_) }).Count -gt 0
        $hasApc     = ($apcApis     | Where-Object { $trueFound.Contains($_) }).Count -gt 0

        # Step 3: Chromium/sandbox context check
        $sandboxCount  = ($text.Split('sandbox')  | Measure-Object).Count - 1
        $crashpadCount = ($text.Split('crashpad') | Measure-Object).Count - 1
        $isChromeRuntime = (Test-TcpkIsChromiumRuntime -Name $pe.Name -Text $text) -or
                           ($sandboxCount -ge $sandboxThreshold) -or
                           ($crashpadCount -ge $crashpadThreshold)

        # Build provenance summary for evidence string
        function _ProvStr($apis, $label) {
            $m = @($apis | Where-Object { $candidates -contains $_ })
            if ($m.Count) { return "$label`: $($m -join ', ')" }
            return $null
        }
        $provParts = @(
            (_ProvStr $byProvenance.imported  'imported'),
            (_ProvStr $byProvenance.delay     'delay-imported'),
            (_ProvStr $byProvenance.stringRef 'string-ref')
        ) | Where-Object { $_ }
        $evidStr = "file=$($pe.Name); " + ($provParts -join '; ')

        # Step 4: Sequence detection and severity
        # Hollowing REQUIRES SetThreadContext/NtSetContextThread (entry-point redirect).
        # Without it, the replaced code cannot execute; the sequence is incomplete.
        $isHollowing = $hasUnmap -and $hasWrite -and $hasContext -and $hasResume
        $isDllInject = $hasAlloc -and $hasWrite -and $hasThread
        $isApcInject = $hasApc -and $hasAlloc

        if ($isHollowing) {
            if ($isChromeRuntime) {
                New-TcpkFinding -Module 'static' -RuleId 'injection.hollowing-apis' `
                    -Severity 'INFO' -Confidence 'Inferred' `
                    -Title "Hollowing-class APIs in $($pe.Name) (Chromium runtime -- suppressed)" `
                    -File $pe.FullName `
                    -Evidence $evidStr `
                    -Cwe @('CWE-94','CWE-829') `
                    -Description ('Imported APIs match the process hollowing sequence, but ' +
                        'this binary is identified as a Chromium/Electron/CEF runtime component ' +
                        "(sandbox=$sandboxCount, crashpad=$crashpadCount occurrences). " +
                        'NtUnmapViewOfSection + WriteProcessMemory + SetThreadContext + ResumeThread ' +
                        'are how the Chromium sandbox broker creates and starts sandboxed child ' +
                        'processes. This is the documented architecture of the runtime, not an ' +
                        'injection capability built into this application.') `
                    -Fix 'No action required for the Chromium sandbox mechanism. If this binary is not a Chromium component, investigate the usage.'
            } else {
                New-TcpkFinding -Module 'static' -RuleId 'injection.hollowing-apis' `
                    -Severity 'HIGH' -Confidence 'Inferred' `
                    -Title "Process hollowing API sequence in $($pe.Name)" `
                    -File $pe.FullName `
                    -Evidence $evidStr `
                    -Cwe @('CWE-94','CWE-829') `
                    -Description ('This PE imports the complete process hollowing API sequence: ' +
                        'NtUnmapViewOfSection + WriteProcessMemory + SetThreadContext + ResumeThread. ' +
                        'SetThreadContext is mandatory for hollowing to work (it redirects the entry ' +
                        'point); all four APIs are confirmed in the import/delay-import table. ' +
                        'This pattern hollows a suspended legitimate process and replaces its code ' +
                        'with an arbitrary payload. (Google Cloud / hasherezade 2025)') `
                    -Fix 'Verify the hollowing APIs are used for a documented, legitimate purpose (sandbox, debug). If not needed, remove the P/Invoke declarations.'
            }
        }

        if ($isDllInject -and -not $isHollowing) {
            if ($isChromeRuntime) {
                New-TcpkFinding -Module 'static' -RuleId 'injection.dll-inject-apis' `
                    -Severity 'INFO' -Confidence 'Inferred' `
                    -Title "DLL-inject-class APIs in $($pe.Name) (Chromium runtime -- suppressed)" `
                    -File $pe.FullName `
                    -Evidence $evidStr `
                    -Cwe @('CWE-94','CWE-829') `
                    -Description ('Imported APIs match the DLL injection sequence, but this binary is a ' +
                        "Chromium/Electron/CEF runtime component (sandbox=$sandboxCount occurrences). " +
                        'VirtualAllocEx + WriteProcessMemory + CreateRemoteThread is how Chromium creates ' +
                        'sandboxed child processes. This is documented runtime behavior.') `
                    -Fix 'No action required for the Chromium sandbox mechanism.'
            } else {
                New-TcpkFinding -Module 'static' -RuleId 'injection.dll-inject-apis' `
                    -Severity 'HIGH' -Confidence 'Inferred' `
                    -Title "DLL injection API sequence in $($pe.Name)" `
                    -File $pe.FullName `
                    -Evidence $evidStr `
                    -Cwe @('CWE-94','CWE-829') `
                    -Description ('This PE imports the DLL injection sequence: ' +
                        'VirtualAllocEx + WriteProcessMemory + CreateRemoteThread. ' +
                        'All three APIs are confirmed in the import/delay-import table. ' +
                        'This allows injecting code into other processes and is a common attack ' +
                        'technique, but may also be used legitimately by security or debugging tools.') `
                    -Fix 'Verify the injection APIs are used for a documented, legitimate purpose. If not needed, remove the P/Invoke declarations.'
            }
        }

        if ($isApcInject -and -not $isHollowing -and -not $isDllInject) {
            New-TcpkFinding -Module 'static' -RuleId 'injection.apc-inject-apis' `
                -Severity 'HIGH' -Confidence 'Inferred' `
                -Title "APC injection API sequence in $($pe.Name)" `
                -File $pe.FullName `
                -Evidence $evidStr `
                -Cwe @('CWE-94','CWE-829') `
                -Description ('This PE imports APC injection APIs with memory allocation: ' +
                    'VirtualAllocEx + QueueUserAPC/NtQueueApcThread. ' +
                    'All APIs confirmed in import/delay-import table. ' +
                    'APC injection queues code to run in another thread context, ' +
                    'a stealthier technique than CreateRemoteThread.') `
                -Fix 'Verify the APC APIs are used legitimately. If not needed, remove the P/Invoke declarations.'
        }

        # Partial match or string-only hits (no complete imported sequence)
        $hasAnyImported = $trueFound.Count -gt 0
        $hasAnyCandidate = $candidates.Count -gt 0
        if (-not $isHollowing -and -not $isDllInject -and -not ($isApcInject -and $hasAlloc) -and $hasAnyCandidate) {
            # Only if there are string-ref-only or partial imported APIs left
            $partialNote = if (-not $hasAnyImported -and $byProvenance.stringRef.Count -gt 0) {
                'No APIs were found in the import or delay-import table; all occurrences are string references only (GetProcAddress/LoadLibrary pattern). This does not constitute an imported injection sequence.'
            } else {
                'Incomplete sequence; does not meet the threshold for a complete hollowing or injection chain.'
            }
            New-TcpkFinding -Module 'static' -RuleId 'injection.suspicious-pinvoke' `
                -Severity 'MEDIUM' -Confidence 'Inferred' `
                -Title "Injection-related API references in $($pe.Name)" `
                -File $pe.FullName `
                -Evidence $evidStr `
                -Cwe @('CWE-94') `
                -Description ("This PE references one or more process injection-related APIs, but does " +
                    "not have a complete imported injection sequence. $partialNote") `
                -Fix 'Review the P/Invoke declarations and their usage context.'
        }
    }
}
