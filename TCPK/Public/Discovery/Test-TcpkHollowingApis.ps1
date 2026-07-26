function Test-TcpkHollowingApis {
<#
.SYNOPSIS
    Detect process hollowing / injection P/Invoke patterns in .NET PEs.

.DESCRIPTION
    Process hollowing is a code injection technique where a legitimate
    process is started in a suspended state, its memory is unmapped and
    replaced with malicious code, then resumed.  The API sequence is:

      CreateProcess(SUSPENDED) -> NtUnmapViewOfSection -> VirtualAllocEx
      -> WriteProcessMemory -> SetThreadContext -> ResumeThread

    Related injection patterns (classic DLL injection, APC injection):
      VirtualAllocEx -> WriteProcessMemory -> CreateRemoteThread
      QueueUserAPC -> NtQueueApcThread

    This scanner checks first-party PEs for string references to these APIs
    (which appear as DllImport/P/Invoke function names in .NET binaries or
    as import names in native PEs).  Individual suspicious APIs are flagged
    at MEDIUM; combinations that form a known injection sequence are HIGH.

    Google Cloud / hasherezade 2025 reference.

.PARAMETER Path
    File or directory to scan.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $hollowingApis = @(
        'NtUnmapViewOfSection', 'ZwUnmapViewOfSection',
        'WriteProcessMemory', 'NtWriteVirtualMemory',
        'VirtualAllocEx', 'NtAllocateVirtualMemory',
        'CreateRemoteThread', 'RtlCreateUserThread', 'NtCreateThreadEx',
        'SetThreadContext', 'NtSetContextThread',
        'ResumeThread', 'NtResumeThread',
        'QueueUserAPC', 'NtQueueApcThread', 'NtQueueApcThreadEx',
        'NtMapViewOfSection', 'NtCreateSection'
    )

    $unmapSet   = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($_ in 'NtUnmapViewOfSection','ZwUnmapViewOfSection') { [void]$unmapSet.Add($_) }
    $writeSet   = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($_ in 'WriteProcessMemory','NtWriteVirtualMemory') { [void]$writeSet.Add($_) }
    $allocSet   = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($_ in 'VirtualAllocEx','NtAllocateVirtualMemory') { [void]$allocSet.Add($_) }
    $threadSet  = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($_ in 'CreateRemoteThread','RtlCreateUserThread','NtCreateThreadEx') { [void]$threadSet.Add($_) }
    $contextSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($_ in 'SetThreadContext','NtSetContextThread') { [void]$contextSet.Add($_) }
    $resumeSet  = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($_ in 'ResumeThread','NtResumeThread') { [void]$resumeSet.Add($_) }

    foreach ($pe in Get-TcpkPeFiles -Path $Path) {
        if (Test-TcpkIsFrameworkFile $pe.Name) { continue }

        $text = Read-TcpkAllText -Path $pe.FullName
        if (-not $text) { continue }

        $found = @($hollowingApis | Where-Object { $text.Contains($_) })
        if ($found.Count -eq 0) { continue }

        $hasUnmap   = $false
        $hasWrite   = $false
        $hasAlloc   = $false
        $hasThread  = $false
        $hasContext  = $false
        $hasResume  = $false

        foreach ($api in $found) {
            if ($unmapSet.Contains($api))   { $hasUnmap   = $true }
            if ($writeSet.Contains($api))   { $hasWrite   = $true }
            if ($allocSet.Contains($api))   { $hasAlloc   = $true }
            if ($threadSet.Contains($api))  { $hasThread  = $true }
            if ($contextSet.Contains($api)) { $hasContext  = $true }
            if ($resumeSet.Contains($api))  { $hasResume  = $true }
        }

        $isHollowing  = $hasUnmap -and $hasWrite -and ($hasResume -or $hasContext)
        $isDllInject  = $hasAlloc -and $hasWrite -and $hasThread
        $isApcInject  = ($found -contains 'QueueUserAPC' -or $found -contains 'NtQueueApcThread' -or $found -contains 'NtQueueApcThreadEx')

        if ($isHollowing) {
            New-TcpkFinding -Module 'static' -RuleId 'injection.hollowing-apis' `
                -Severity 'HIGH' -Confidence 'Inferred' `
                -Title "Process hollowing API sequence in $($pe.Name)" `
                -File $pe.FullName `
                -Evidence "apis: $(($found | Select-Object -First 8) -join ', ')" `
                -Cwe @('CWE-94','CWE-829') `
                -Description ('This PE references the classic process hollowing API sequence: ' +
                    'NtUnmapViewOfSection + WriteProcessMemory + SetThreadContext/ResumeThread. ' +
                    'This pattern is used to hollow out a legitimate process and replace its ' +
                    'code with arbitrary payloads. While this may be legitimate (debugging tools, ' +
                    'security products), it is a high-risk capability that should be reviewed. ' +
                    '(Google Cloud / hasherezade 2025)') `
                -Fix 'Verify the hollowing APIs are used for a legitimate purpose (debugging, sandboxing). If not needed, remove the P/Invoke declarations.'
        }

        if ($isDllInject -and -not $isHollowing) {
            New-TcpkFinding -Module 'static' -RuleId 'injection.dll-inject-apis' `
                -Severity 'HIGH' -Confidence 'Inferred' `
                -Title "DLL injection API sequence in $($pe.Name)" `
                -File $pe.FullName `
                -Evidence "apis: $(($found | Select-Object -First 8) -join ', ')" `
                -Cwe @('CWE-94','CWE-829') `
                -Description ('This PE references the classic DLL injection sequence: ' +
                    'VirtualAllocEx + WriteProcessMemory + CreateRemoteThread. This allows ' +
                    'injecting code into other processes, which is a common attack technique ' +
                    'but may also be used legitimately by security or debugging tools.') `
                -Fix 'Verify the injection APIs are used for a legitimate purpose. If not needed, remove the P/Invoke declarations.'
        }

        if ($isApcInject -and $hasAlloc -and -not $isHollowing -and -not $isDllInject) {
            New-TcpkFinding -Module 'static' -RuleId 'injection.apc-inject-apis' `
                -Severity 'HIGH' -Confidence 'Inferred' `
                -Title "APC injection API sequence in $($pe.Name)" `
                -File $pe.FullName `
                -Evidence "apis: $(($found | Select-Object -First 8) -join ', ')" `
                -Cwe @('CWE-94','CWE-829') `
                -Description ('This PE references APC (Asynchronous Procedure Call) injection APIs ' +
                    'combined with memory allocation. APC injection queues code to run in the context ' +
                    'of another thread, which is a stealthier injection technique than CreateRemoteThread.') `
                -Fix 'Verify the APC APIs are used legitimately. If not needed, remove the P/Invoke declarations.'
        }

        if (-not $isHollowing -and -not $isDllInject -and -not ($isApcInject -and $hasAlloc)) {
            New-TcpkFinding -Module 'static' -RuleId 'injection.suspicious-pinvoke' `
                -Severity 'MEDIUM' -Confidence 'Inferred' `
                -Title "Suspicious injection-related APIs in $($pe.Name)" `
                -File $pe.FullName `
                -Evidence "apis: $(($found | Select-Object -First 8) -join ', ')" `
                -Cwe @('CWE-94') `
                -Description ('This PE references one or more process injection-related APIs ' +
                    '(memory manipulation, thread creation, or APC queueing) but not a complete ' +
                    'injection sequence. These APIs may be used legitimately but warrant review.') `
                -Fix 'Review the P/Invoke declarations and their usage context to determine if they are necessary.'
        }
    }
}
