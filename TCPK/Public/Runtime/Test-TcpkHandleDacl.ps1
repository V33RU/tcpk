function Test-TcpkHandleDacl {
<#
.SYNOPSIS
    E22. DACLs on the kernel objects a running process actually holds open.

.DESCRIPTION
    Test-TcpkNamedObjects is the STATIC half of this: it pulls named-object literals
    out of the binaries and infers a squatting or race surface. This is the RUNTIME
    half. It enumerates the handles the live process really holds and reads the DACL
    on each object, so an inferred risk becomes an observed one. Same pairing as
    dllsearch.phantom-dll (static) and dll-search.name-not-found (runtime).

    Flags any allow-ACE granting a low-privilege well-known group modify rights over
    a synchronisation or job object the process depends on:

      Event / Mutant / Semaphore   a writable DACL means a low-privileged user can
                                   signal, reset or abandon the object. Against a
                                   single-instance mutex that is a denial of service;
                                   against a state event it is a race the app does
                                   not expect to lose.
      Section                      shared memory the app treats as trusted input.
      Job                          a writable job object can have its limits changed
                                   or its processes terminated.
      Timer / Key / others         reported the same way when the DACL is loose.

    SCOPE. File-type handles are counted but never inspected, and their names are
    never queried. NtQueryObject(ObjectNameInformation) blocks indefinitely on a
    synchronous file or pipe handle with pending I/O, which is the classic trap that
    freezes naive handle enumerators. Rather than work around it with a sacrificial
    thread and a timeout, TCPK simply does not ask. Pipes already have a dedicated
    check in Test-TcpkNamedPipeDacl, and sections in Test-TcpkSharedMemoryDacl.

    Requires PROCESS_DUP_HANDLE on the target, so it generally needs to run elevated
    for anything not owned by the current user. It duplicates each handle read-only
    and closes it immediately; nothing is modified.

.PARAMETER ProcessName
    Name of the running process (no .exe).

.PARAMETER ProcessId
    Specific PID instead of resolving by name.

.PARAMETER MaxHandles
    Cap on handles inspected per process (default 2000). A busy process can hold tens
    of thousands and the interesting ones cluster early.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ParameterSetName='ByName')][string]$ProcessName,
        [Parameter(Mandatory, ParameterSetName='ById')][int]$ProcessId,
        [int]$MaxHandles = 2000
    )

    if (-not (Assert-TcpkWindows 'Test-TcpkHandleDacl')) { return }
    if (-not ('Tcpk.Handles' -as [type])) {
        New-TcpkSkippedFinding -RuleId 'handle-dacl.unavailable' `
            -Title 'Handle enumeration primitive unavailable' `
            -Reason 'Tcpk.Handles failed to compile.'
        return
    }

    # Object types worth judging a DACL on. Others are counted in the census but not
    # graded, because a loose DACL on them is not a meaningful finding on its own.
    $graded = @('Event', 'Mutant', 'Semaphore', 'Section', 'Job', 'Timer', 'Key')

    $rights = [ordered]@{
        MODIFY_STATE = 0x0002; WRITE_DAC = 0x40000; WRITE_OWNER = 0x80000
        GENERIC_WRITE = 0x40000000; ALL_ACCESS = 0x1F0000
    }

    $procs = if ($PSCmdlet.ParameterSetName -eq 'ByName') {
        Get-TcpkProcess -ProcessName $ProcessName
    } else {
        Get-TcpkProcess -ProcessId $ProcessId
    }

    foreach ($p in $procs) {
        $recs = @()
        try { $recs = @([Tcpk.Handles]::Inspect($p.Id, $MaxHandles)) } catch { }
        if (-not $recs.Count) {
            New-TcpkSkippedFinding -RuleId 'handle.dacl-unreadable' `
                -Title "Could not enumerate handles for $($p.Name) (PID $($p.Id))" `
                -Reason 'PROCESS_DUP_HANDLE denied or no inspectable handles. Re-run elevated.'
            continue
        }

        $byType = @{}
        # One finding per (type, account, rights) rather than per handle: a process can
        # hold hundreds of events with the same descriptor.
        $seen = New-Object 'System.Collections.Generic.HashSet[string]'

        foreach ($r in $recs) {
            # [char]0x1F, not `u{001F}: the `u escape is PowerShell 6+ and this module
            # targets 5.1. .Split(char) also avoids -split treating it as a regex.
            $parts = "$r".Split([char]0x1F)
            if ($parts.Count -lt 2) { continue }
            $type = $parts[0]
            $sddl = $parts[1]
            if (-not $type) { continue }

            if (-not $byType.ContainsKey($type)) { $byType[$type] = 0 }
            $byType[$type]++

            if ($graded -notcontains $type) { continue }
            if (-not $sddl) { continue }

            foreach ($g in (Get-TcpkSddlLowPrivGrants -Sddl $sddl -RightsMap $rights)) {
                $key = "$type|$($g.Sid)|$($g.Granted -join ',')"
                if (-not $seen.Add($key)) { continue }

                New-TcpkFinding -Module 'runtime' -RuleId 'handle.dacl-weak' `
                    -Severity 'MEDIUM' -Confidence 'Confirmed' `
                    -Title "$($p.Name) holds a $type with a permissive DACL ($($g.Account))" `
                    -File "$($p.Name) (PID $($p.Id))" `
                    -Evidence "$type -> $($g.Account) ($($g.Sid)) -> $($g.Granted -join ', ')" `
                    -Cwe @('CWE-732') `
                    -Description ('This process holds a kernel object whose DACL lets a low-privileged ' +
                        'user modify it. For an Event, Mutant or Semaphore that means the object can be ' +
                        'signalled, reset or abandoned by an unprivileged process: a single-instance ' +
                        'mutex becomes a denial of service, and a state event becomes a race the ' +
                        'application does not expect to lose. For a Section it means shared memory the ' +
                        'application treats as trusted input is attacker-writable.') `
                    -Fix 'Create these objects with an explicit restrictive security descriptor rather than the default, and namespace them under Local\ rather than Global\ unless cross-session access is genuinely required.'
            }
        }

        $census = (($byType.GetEnumerator() | Sort-Object -Property Value -Descending |
            Select-Object -First 12 | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join '; ')
        New-TcpkFinding -Module 'runtime' -RuleId 'handle.type-census' `
            -Severity 'INFO' -Confidence 'Confirmed' `
            -Title "$($p.Name): $($recs.Count) inspectable handle(s) across $($byType.Count) object type(s)" `
            -File "$($p.Name) (PID $($p.Id))" `
            -Evidence $census `
            -Description ('Kernel object types held open by the process. File-type handles are excluded ' +
                'because querying their names can block indefinitely; see Test-TcpkNamedPipeDacl for pipes.')
    }
}
