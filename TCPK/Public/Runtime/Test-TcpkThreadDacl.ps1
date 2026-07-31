function Test-TcpkThreadDacl {
<#
.SYNOPSIS
    E12. Running-thread DACL -- hijackable by low-privileged users?

.DESCRIPTION
    Test-TcpkProcessDacl covers the process object. This covers the THREAD objects
    inside it, which are a separate injection primitive: THREAD_SET_CONTEXT lets a
    caller rewrite a thread's register state and redirect execution without ever
    needing PROCESS_VM_WRITE. A process whose DACL is sound can still be taken over
    through a thread whose DACL is not.

    Flags any allow-ACE granting a low-privilege well-known group (Everyone /
    Authenticated Users / Users / INTERACTIVE / Anonymous / Guests) one of:
    THREAD_SET_CONTEXT, THREAD_SUSPEND_RESUME, THREAD_SET_INFORMATION,
    THREAD_SET_THREAD_TOKEN, THREAD_DIRECT_IMPERSONATION, WRITE_DAC, WRITE_OWNER,
    or THREAD_ALL_ACCESS.

    Threads normally inherit a default DACL that grants none of this to those
    groups, so a hit here means something explicitly loosened it.

    Read-only: opens each thread with THREAD_QUERY_INFORMATION | READ_CONTROL.

.PARAMETER ProcessName
    Name of the running process (no .exe).

.PARAMETER ProcessId
    Specific PID instead of resolving by name.

.PARAMETER MaxThreads
    Cap on threads inspected per process (default 200). A busy process can hold
    thousands, and the DACL is almost always uniform across them.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ParameterSetName='ByName')][string]$ProcessName,
        [Parameter(Mandatory, ParameterSetName='ById')][int]$ProcessId,
        [int]$MaxThreads = 200
    )

    if (-not (Assert-TcpkWindows 'Test-TcpkThreadDacl')) { return }
    if (-not ('Tcpk.ObjSec' -as [type])) {
        New-TcpkSkippedFinding -RuleId 'thread-dacl.unavailable' `
            -Title 'Thread security-descriptor primitive unavailable' `
            -Reason 'Tcpk.ObjSec failed to compile.'
        return
    }

    $rights = [ordered]@{
        SET_CONTEXT = 0x0010; SUSPEND_RESUME = 0x0002; SET_INFORMATION = 0x0020
        SET_THREAD_TOKEN = 0x0080; DIRECT_IMPERSONATION = 0x0200
        WRITE_DAC = 0x40000; WRITE_OWNER = 0x80000; ALL_ACCESS = 0x1F03FF
    }

    $procs = if ($PSCmdlet.ParameterSetName -eq 'ByName') {
        Get-TcpkProcess -ProcessName $ProcessName
    } else {
        Get-TcpkProcess -ProcessId $ProcessId
    }

    foreach ($p in $procs) {
        $threads = @()
        try { $threads = @($p.Threads) } catch { }
        if (-not $threads.Count) { continue }

        $checked = 0
        $unreadable = 0
        # One finding per distinct (account, rights) combination rather than one per
        # thread: the DACL is normally uniform, and a 900-thread process would
        # otherwise emit 900 identical findings.
        $seen = New-Object 'System.Collections.Generic.HashSet[string]'

        foreach ($t in ($threads | Select-Object -First $MaxThreads)) {
            $tid = 0
            try { $tid = [int]$t.Id } catch { continue }
            if (-not $tid) { continue }
            $checked++

            $sddl = $null
            try { $sddl = [Tcpk.ObjSec]::GetThreadSddl($tid) } catch { }
            if (-not $sddl) { $unreadable++; continue }

            foreach ($g in (Get-TcpkSddlLowPrivGrants -Sddl $sddl -RightsMap $rights)) {
                $key = "$($g.Sid)|$($g.Granted -join ',')"
                if (-not $seen.Add($key)) { continue }
                New-TcpkFinding -Module 'runtime' -RuleId 'thread.dacl-hijackable' `
                    -Severity 'HIGH' -Confidence 'Confirmed' `
                    -Title "$($p.Name) thread DACL grants hijack rights to $($g.Account)" `
                    -File "$($p.Name) (PID $($p.Id), TID $tid)" `
                    -Evidence "$($g.Account) ($($g.Sid)) -> $($g.Granted -join ', ')" `
                    -Cwe @('CWE-732', 'CWE-269') `
                    -Description ('A low-privileged group holds rights over this process''s threads. ' +
                        'THREAD_SET_CONTEXT alone is enough to redirect execution by rewriting the ' +
                        'register state, without any process memory-write right. If the process runs ' +
                        'elevated or as SYSTEM, an unprivileged local user can escalate through it.') `
                    -Fix 'Do not loosen the default thread DACL. Remove explicit grants to Users, Everyone or Authenticated Users.'
            }
        }

        if ($checked -gt 0 -and $unreadable -eq $checked) {
            New-TcpkSkippedFinding -RuleId 'thread.dacl-unreadable' `
                -Title "Could not read any thread DACL for $($p.Name) (PID $($p.Id))" `
                -Reason 'OpenThread/GetSecurityInfo denied for every thread (likely insufficient rights).'
        }
    }
}
