function Test-TcpkThreadStart {
<#
.SYNOPSIS
    E23. Thread start addresses that fall outside every loaded module (unbacked).

.DESCRIPTION
    A legitimate thread starts inside a mapped image: its Win32 start address lands
    in the address range of some loaded module. A thread created by injected code
    starts in private memory instead, because the code it runs never passed through
    the loader. That is the shape CreateRemoteThread against a manual-mapped or
    reflectively-loaded payload produces, and it is what Process Hacker's thread
    list makes visible. This check reads the same value.

    HOW IT WORKS
      1. Each thread is opened with THREAD_QUERY_INFORMATION (0x0040) only. The
         handle's owning PID is confirmed with GetProcessIdOfThread before anything
         is read, because Windows recycles thread IDs: a thread that exits between
         the snapshot and the query can leave its TID pointing at a thread of a
         DIFFERENT process, whose start address would then be compared against this
         process's modules and reported as unbacked. A TID whose owner does not
         match is discarded, not reported.
      2. The start address is read with NtQueryInformationThread, information class
         9 (ThreadQuerySetWin32StartAddress).
      3. The module ranges come from the target's own module list
         (BaseAddress .. BaseAddress + ModuleMemorySize).
      4. A start address inside any range is normal and is not reported. One outside
         every range is reported as unbacked.

    The only other handle this check opens is a process handle for the bitness probe
    below, requested as PROCESS_QUERY_LIMITED_INFORMATION (0x1000) and falling back
    to PROCESS_QUERY_INFORMATION (0x0400). Both are query-only.

    JIT CALIBRATION -- this is what keeps the check usable. .NET, the JVM, V8/Node
    and CEF/Chromium all generate code at runtime and can start threads in that
    generated code, so on those processes an unbacked start address is an expected
    consequence of the runtime, not evidence of injection. The check looks for a JIT
    runtime among the loaded modules (clr.dll, coreclr.dll, clrjit.dll, mscorwks.dll,
    jvm.dll, node.dll, libnode.dll, libcef.dll, chrome_elf.dll) and reports:

      no JIT runtime      MEDIUM. Nothing in the process explains a thread starting
                          outside every image, so it is worth running down.
      JIT runtime present INFO, as posture. Stated in the finding text so nobody
                          reads it as a defect.

    That module list is deliberately byte-identical to the one in
    Test-TcpkMemoryRegions so the two checks cannot drift apart and disagree about
    whether a process is a JIT host. The cost of that constraint is that runtimes
    outside the shared list are NOT calibrated and will be rated MEDIUM even though
    the runtime explains them. Known uncalibrated cases: Mono / Unity
    (mono-2.0-bdwgc.dll, mono-2.0-sgen.dll), a WinForms or WPF app hosting the legacy
    WebBrowser control (jscript9.dll, chakra.dll), and a WebView2 host process
    (EmbeddedBrowserWebView.dll, msedge.dll) whose own module list contains no
    chrome_elf.dll. On any of those, treat a MEDIUM here as unconfirmed until the
    region at the start address has been dumped.

    Findings are emitted PER DISTINCT START REGION, not per thread, so a thread pool
    with fifty workers off one address produces one finding.

    LIMITS -- what this does NOT do:
      * It does not read the memory at the start address. It cannot tell JIT-emitted
        code from injected code by inspection; the JIT-runtime check above is a
        calibration proxy, not proof either way.
      * Absence of a finding is not proof of a clean process. Win32StartAddress is
        writable by anyone holding THREAD_SET_INFORMATION on the thread, so an
        injector that bothers to overwrite it reads back as backed. Injected code
        that runs on an existing thread (APC queue, SetThreadContext, hooked call)
        never creates a thread at all and is invisible here.
      * Region grouping uses the 64 KB allocation granularity of the start address
        as a stand-in for the allocation base. The allocation base itself is not
        queried, so two separate allocations inside one 64 KB span group together.
      * The module list is a snapshot. A module that loads between the snapshot and
        the thread query would make its threads look unbacked, so every candidate is
        re-tested against a freshly refreshed module list before it is reported.
        That narrows the race, it does not remove it. If the refreshed list comes
        back unusable (fewer than two ranges, e.g. the process is exiting) the
        re-test is skipped and the original snapshot stands; the evidence then
        carries retested=no, so a finding that never got the second opinion is
        distinguishable from one that survived it.
      * Requires the PowerShell host and the target to be the same bitness. A 32-bit
        host cannot enumerate a 64-bit target's modules, so that combination is
        reported Skipped rather than guessed at.
      * Every count is scoped to the threads actually inspected, never to the
        process. -MaxThreads caps the sweep, so the evidence says
        unbacked-in-checked and regions-in-checked, alongside "checked=N of M" with
        the exact process thread total M. At most 10 regions are reported per
        process (the largest by thread count first); regions-in-checked stays exact
        in every finding, so a truncated report is visible as truncated.
      * A thread whose start address could not be read at all -- OpenThread denied,
        the thread exited, the query failed, the address came back null, or the TID
        now belongs to another process -- is counted as unreadable and never
        reported. If nothing was readable, or if the majority was unreadable and
        nothing was found, the check says so rather than returning silently.

    Read-only. Opens threads for query only and never suspends, modifies, or writes
    to the target.

.PARAMETER ProcessName
    Running process name (with or without .exe).

.PARAMETER ProcessId
    Specific PID instead of resolving by name.

.PARAMETER MaxThreads
    Cap on threads inspected per process (default 200, clamped to 1..5000). Busy
    processes hold thousands of pool threads that share a handful of start
    addresses. The exact thread total is reported separately from the number
    actually inspected, so a capped run is never mistaken for a full one.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ParameterSetName='ByName')][string]$ProcessName,
        [Parameter(Mandatory, ParameterSetName='ById')][int]$ProcessId,
        [int]$MaxThreads = 200
    )

    if (-not (Assert-TcpkWindows 'Test-TcpkThreadStart')) { return }

    # Distinct type name on purpose. Tcpk.ObjSec and Tcpk.MemRegions are guarded by an
    # -as [type] check, so a method added to an already-loaded type is silently ignored
    # until a fresh session. This one stands alone.
    if (-not ('Tcpk.ThreadStart' -as [type])) {
        $src = @'
using System;
using System.Runtime.InteropServices;
namespace Tcpk {
 public static class ThreadStart {
  [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr OpenThread(uint a, bool inh, int tid);
  [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr OpenProcess(uint a, bool inh, int pid);
  [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
  [DllImport("kernel32.dll", SetLastError=true)] static extern bool IsWow64Process(IntPtr h, out bool wow);
  [DllImport("kernel32.dll", SetLastError=true)] static extern int GetProcessIdOfThread(IntPtr h);
  [DllImport("ntdll.dll")] static extern int NtQueryInformationThread(IntPtr h, int cls, out IntPtr info, int len, IntPtr ret);

  const uint THREAD_QUERY_INFORMATION = 0x0040;
  const uint PROCESS_QUERY_INFORMATION = 0x0400;
  const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
  const int ThreadQuerySetWin32StartAddress = 9;

  // Win32 start address of a thread.
  //   -1  OpenThread denied, or the thread already exited.
  //   -2  NtQueryInformationThread failed.
  //   -3  ownerPid was supplied and the thread does not belong to it, or its owner
  //       could not be confirmed. Windows recycles thread IDs, so a TID captured in
  //       the snapshot can point at another process's thread by the time it is
  //       opened; reading that address and comparing it to THIS process's modules
  //       would manufacture an unbacked-thread finding out of nothing.
  //    0  query succeeded but returned a null address.
  // All four are "no usable address" and are counted, never reported. Otherwise the
  // start address. On a 32-bit host the pointer is widened without sign extension so
  // a >2 GB large-address-aware address stays positive.
  //
  // The one-argument overload skips the owner check and exists for direct callers
  // (tests, interactive triage) that already know the TID is live.
  public static long GetStart(int tid) {
     return GetStart(tid, 0);
  }

  public static long GetStart(int tid, int ownerPid) {
     IntPtr h = OpenThread(THREAD_QUERY_INFORMATION, false, tid);
     if (h == IntPtr.Zero) return -1;
     try {
        if (ownerPid != 0) {
           // A handle holding THREAD_QUERY_INFORMATION is granted
           // THREAD_QUERY_LIMITED_INFORMATION implicitly, which is what this needs.
           // 0 means the call failed, so the owner is unknown: fail closed.
           int owner = GetProcessIdOfThread(h);
           if (owner == 0 || owner != ownerPid) return -3;
        }
        IntPtr addr;
        int st = NtQueryInformationThread(h, ThreadQuerySetWin32StartAddress, out addr, IntPtr.Size, IntPtr.Zero);
        if (st != 0) return -2;
        if (IntPtr.Size == 4) return (long)((uint)addr.ToInt32());
        return addr.ToInt64();
     } catch {
        return -2;
     } finally {
        CloseHandle(h);
     }
  }

  // 1 = process is WOW64 (32-bit on 64-bit Windows), 0 = native, -1 = cannot tell.
  // Asks for the LIMITED right first: it is granted on far more processes than
  // PROCESS_QUERY_INFORMATION, and asking for the bigger right first would make the
  // cross-bitness guard below fail open on every process this host cannot fully open.
  public static int IsWow64(int pid) {
     IntPtr h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
     if (h == IntPtr.Zero) h = OpenProcess(PROCESS_QUERY_INFORMATION, false, pid);
     if (h == IntPtr.Zero) return -1;
     try {
        bool wow;
        if (!IsWow64Process(h, out wow)) return -1;
        if (wow) return 1;
        return 0;
     } catch {
        return -1;
     } finally {
        CloseHandle(h);
     }
  }
 }
}
'@
        try { Add-Type -TypeDefinition $src -ErrorAction Stop } catch { }
    }

    if (-not ('Tcpk.ThreadStart' -as [type])) {
        New-TcpkSkippedFinding -RuleId 'thread-start.unavailable' `
            -Title 'Thread start-address primitive unavailable' `
            -Reason 'Tcpk.ThreadStart failed to compile, so NtQueryInformationThread could not be called.'
        return
    }

    # Bound the work regardless of what the caller passes.
    if ($MaxThreads -lt 1) { $MaxThreads = 1 }
    if ($MaxThreads -gt 5000) { $MaxThreads = 5000 }

    # Build the target label as a statement, one branch per parameter set, rather than
    # interpolating both parameters into one string. In the ByName set the PID
    # parameter is an unbound [int] and therefore 0, so interpolating both together
    # renders a target of "notepad0".
    $procs = @()
    $target = ''
    if ($PSCmdlet.ParameterSetName -eq 'ByName') {
        $target = "$ProcessName"
        $procs = @(Get-TcpkProcess -ProcessName ($ProcessName -replace '\.exe$', ''))
    } else {
        $target = "PID $ProcessId"
        $procs = @(Get-TcpkProcess -ProcessId $ProcessId)
    }
    if (-not $procs.Count) {
        New-TcpkSkippedFinding -RuleId 'thread-start.unavailable' `
            -Title "Process not running: $target" `
            -Reason 'No matching live process, so no thread start address could be read.'
        return
    }

    # Runtimes that emit code at execution time. Their presence makes a start address
    # outside every image an expected product of the runtime rather than a defect.
    $jitModules = @(
        'clr.dll', 'coreclr.dll', 'clrjit.dll', 'mscorwks.dll',   # .NET
        'jvm.dll',                                                # Java
        'node.dll', 'libnode.dll',                                # Node
        'libcef.dll', 'chrome_elf.dll'                            # Chromium / Electron / CEF
    )

    # Module address ranges for one process. Returns an empty array when the module
    # list cannot be read at all (denied, exiting, cross-bitness).
    $getRanges = {
        param($proc)
        $acc = New-Object 'System.Collections.Generic.List[object]'
        try {
            foreach ($m in $proc.Modules) {
                # 0 is the "unusable" sentinel. Set it in the catch and test it after,
                # rather than using continue from inside the catch: loop flow control
                # out of a catch block that is itself nested in an outer try is not
                # worth relying on.
                $b = 0
                try { $b = $m.BaseAddress.ToInt64() } catch { $b = 0 }
                # On a 32-bit host ToInt64 sign-extends an address above 2 GB.
                if ([IntPtr]::Size -eq 4 -and $b -lt 0) { $b = $b + 4294967296 }
                $sz = 0
                try { $sz = [int64]$m.ModuleMemorySize } catch { $sz = 0 }
                if ($b -le 0 -or $sz -le 0) { continue }
                $acc.Add([pscustomobject]@{ Start = $b; End = ($b + $sz); Name = "$($m.ModuleName)" })
            }
        } catch { }
        return $acc.ToArray()
    }

    foreach ($p in $procs) {
        $pname = "$($p.Name)"
        $ppid = 0
        # Same reason as in $getRanges: set the 0 sentinel in the catch and test it
        # after, instead of using continue from inside a catch block.
        try { $ppid = [int]$p.Id } catch { $ppid = 0 }
        if (-not $ppid) { continue }
        $label = "$pname (PID $ppid)"

        # Cross-bitness guard. A 32-bit host sees neither a 64-bit target's module list
        # nor the full width of its start addresses, and every thread would look
        # unbacked. Say so instead of producing a page of false positives.
        if ([IntPtr]::Size -eq 4 -and [Environment]::Is64BitOperatingSystem) {
            $wow = -1
            try { $wow = [Tcpk.ThreadStart]::IsWow64($ppid) } catch { }
            if ($wow -eq 0) {
                New-TcpkSkippedFinding -RuleId 'thread-start.unavailable' `
                    -Title "Cannot inspect thread start addresses of $label" `
                    -Reason 'Target is 64-bit but this PowerShell host is 32-bit. Re-run in a 64-bit host.'
                continue
            }
        }

        $jitFound = New-Object 'System.Collections.Generic.List[string]'
        try {
            foreach ($m in $p.Modules) {
                $mn = "$($m.ModuleName)".ToLowerInvariant()
                if ($jitModules -contains $mn -and -not $jitFound.Contains($mn)) { $jitFound.Add($mn) }
            }
        } catch { }
        $hasJit = ($jitFound.Count -gt 0)
        $jitLabel = 'none'
        if ($hasJit) { $jitLabel = ($jitFound -join '+') }

        $ranges = @(& $getRanges $p)
        # Every live process has at least its own image plus ntdll.dll mapped. Fewer
        # than two ranges means the module list was not readable, and comparing thread
        # start addresses against a partial list would flag backed threads as unbacked.
        if ($ranges.Count -lt 2) {
            New-TcpkSkippedFinding -RuleId 'thread-start.unavailable' `
                -Title "Cannot read the module list of $label" `
                -Reason 'Module enumeration returned fewer than two ranges (access denied, process exiting, or protected). Without module ranges an unbacked start address cannot be distinguished from a backed one.'
            continue
        }

        $threads = @()
        try { $threads = @($p.Threads) } catch { }
        $totalThreads = $threads.Count
        if (-not $totalThreads) {
            New-TcpkSkippedFinding -RuleId 'thread-start.unavailable' `
                -Title "No threads visible for $label" `
                -Reason 'The process thread list was empty or unreadable.'
            continue
        }

        $checked = 0
        $unreadable = 0
        $stale = 0
        $cands = New-Object 'System.Collections.Generic.List[object]'

        foreach ($t in ($threads | Select-Object -First $MaxThreads)) {
            $tid = 0
            try { $tid = [int]$t.Id } catch { $tid = 0 }
            if (-not $tid) { continue }
            $checked++

            # Owner-scoped: the TID is only honoured if the opened thread still
            # belongs to $ppid. See the -3 sentinel comment in the C# above.
            $sa = -1
            try { $sa = [Tcpk.ThreadStart]::GetStart($tid, $ppid) } catch { $sa = -2 }
            if ($sa -eq -3) { $stale++ }
            # -1 denied / exited, -2 query failed, -3 not ours, 0 null address. None
            # of these is evidence of anything, so they are counted, not reported.
            if ($sa -le 0) { $unreadable++; continue }

            $backed = $false
            foreach ($r in $ranges) {
                if ($sa -ge $r.Start -and $sa -lt $r.End) { $backed = $true; break }
            }
            if (-not $backed) { $cands.Add([pscustomobject]@{ Tid = $tid; Addr = $sa }) }
        }

        # No thread yielded a usable ID at all -- nothing was inspected, so silence
        # here would be indistinguishable from a clean process.
        if ($checked -eq 0) {
            New-TcpkSkippedFinding -RuleId 'thread.start-unreadable' `
                -Title "No inspectable thread for $label" `
                -Reason "The process reported $totalThreads thread(s) but none exposed a usable thread ID, so no start address was queried."
            continue
        }

        if ($unreadable -eq $checked) {
            New-TcpkSkippedFinding -RuleId 'thread.start-unreadable' `
                -Title "Could not read any thread start address for $label" `
                -Reason "OpenThread/NtQueryInformationThread returned no usable address for all $checked inspected thread(s) ($stale of them had exited and had their thread ID reused). Re-run elevated, or the process is protected."
            continue
        }

        # Race guard. The module list above is a snapshot taken before the threads were
        # queried; a module loading in between would make its threads look unbacked.
        # Re-test every candidate against a freshly refreshed module list and keep only
        # those still outside every image.
        # $retested is a real boolean, never a 'yes'/'no' string: a non-empty string is
        # always true in an if(), so a string here would silently defeat the branch.
        $retested = $false
        if ($cands.Count -gt 0) {
            try { $p.Refresh() } catch { }
            $ranges2 = @(& $getRanges $p)
            if ($ranges2.Count -ge 2) {
                $retested = $true
                $still = New-Object 'System.Collections.Generic.List[object]'
                foreach ($c in $cands) {
                    $backed2 = $false
                    foreach ($r in $ranges2) {
                        if ($c.Addr -ge $r.Start -and $c.Addr -lt $r.End) { $backed2 = $true; break }
                    }
                    if (-not $backed2) { $still.Add($c) }
                }
                $cands = $still
            }
        }
        $retestLabel = 'no'
        if ($retested) { $retestLabel = 'yes' }

        if ($cands.Count -eq 0) {
            # Nothing to report. Say so explicitly when most of the sweep could not be
            # read, otherwise a 5%-coverage run is indistinguishable from a clean one.
            if (($unreadable * 2) -gt $checked) {
                New-TcpkSkippedFinding -RuleId 'thread.start-unreadable' `
                    -Title "Thread start addresses of $label were mostly unreadable" `
                    -Reason "No usable start address for $unreadable of $checked inspected thread(s) ($stale had exited and had their thread ID reused); the process has $totalThreads thread(s) in total. The remainder were all image-backed, but this run is not evidence that the process is clean. Re-run elevated."
            }
            continue
        }

        # Group by 64 KB allocation granularity: a stand-in for the allocation base,
        # which is not queried. One finding per region, not one per thread.
        $regions = @{}
        $order = New-Object 'System.Collections.Generic.List[int64]'
        foreach ($c in $cands) {
            $region = [int64]($c.Addr - ($c.Addr % 65536))
            if (-not $regions.ContainsKey($region)) {
                $regions[$region] = New-Object 'System.Collections.Generic.List[object]'
                $order.Add($region)
            }
            $regions[$region].Add($c)
        }
        $regionCount = $order.Count

        $sev = 'MEDIUM'
        $jitNote = ('None of the JIT runtime modules this check knows about is loaded in this process, ' +
            'so runtime code generation does not explain a thread starting outside every mapped image. ' +
            'That module list is shared with Test-TcpkMemoryRegions and is not exhaustive: Mono/Unity ' +
            '(mono-2.0-*.dll), the legacy WebBrowser control (jscript9.dll, chakra.dll) and a WebView2 ' +
            'host (EmbeddedBrowserWebView.dll, msedge.dll) also generate code at runtime and are not ' +
            'calibrated for, so check the loaded module list before treating this as anomalous.')
        if ($hasJit) {
            $sev = 'INFO'
            $jitNote = ('A JIT runtime is loaded (' + $jitLabel + '), and JIT runtimes start threads in ' +
                'code they generated at runtime, which is outside every mapped image by definition. ' +
                'This is therefore reported as posture, not as a defect. The check does not read the ' +
                'code at the start address, so it cannot confirm which of the two this is.')
        }

        # Cap the number of findings so a pathological process cannot flood the report.
        # $regionCount stays exact and is carried in every finding, so a truncated
        # report is visible as truncated rather than read as the whole picture.
        $emitted = 0
        $sorted = @($order | Sort-Object -Descending -Property { $regions[$_].Count })
        foreach ($region in $sorted) {
            if ($emitted -ge 10) { break }
            $emitted++
            $grp = $regions[$region]
            $tids = @($grp | Select-Object -First 8 | ForEach-Object { $_.Tid })
            $addrs = @($grp | Select-Object -First 4 | ForEach-Object { ('0x{0:X}' -f $_.Addr) } | Sort-Object -Unique)

            # Names say "in-checked", not "total": these are counts over the threads
            # this run actually inspected, which -MaxThreads caps. The exact process
            # thread total is the M in "checked=N of M" and is never merged into them.
            $ev1 = ('region=0x{0:X}; threads-here={1}; unbacked-in-checked={2}; regions-in-checked={3}; regions-reported={4} of {3}; ' -f $region, $grp.Count, $cands.Count, $regionCount, ([Math]::Min($regionCount, 10)))
            $ev2 = ('checked={0} of {1} thread(s); unreadable={2}; stale-tid={3}; modules={4}; jit={5}; retested={6}; ' -f $checked, $totalThreads, $unreadable, $stale, $ranges.Count, $jitLabel, $retestLabel)
            $ev3 = ('tids=' + ($tids -join ',') + '; addrs=' + ($addrs -join ','))
            $ev = $ev1 + $ev2 + $ev3

            New-TcpkFinding -Module 'runtime' -RuleId 'thread.unbacked-start' `
                -Severity $sev -Confidence 'Confirmed' `
                -Title ("{0}: {1} thread(s) start at 0x{2:X}, outside every loaded module" -f $pname, $grp.Count, $region) `
                -File $label `
                -Evidence $ev `
                -Cwe @('CWE-114', 'CWE-829') `
                -Description ('The Win32 start address of these threads does not fall inside the address ' +
                    'range of any module loaded in the process. Threads created by the loader start inside ' +
                    'a mapped image; a start address in private memory is the shape produced by ' +
                    'CreateRemoteThread against manual-mapped or reflectively-loaded code. ' + $jitNote +
                    ' The start address is reported by the kernel and is writable by any caller holding ' +
                    'THREAD_SET_INFORMATION, so this detects an injector that did not bother to hide, ' +
                    'and a clean result is not proof of absence.') `
                -Fix ('Identify what created the thread: dump the region at the start address and resolve ' +
                    'its origin (Process Hacker, or a live dump plus the !address extension). Where the ' +
                    'application does not need runtime code generation, enable the process mitigation ' +
                    'policy for dynamic code (ProcessDynamicCodePolicy) and Blocking of non-Microsoft ' +
                    'binaries, which stop non-image code from becoming executable at all.')
        }
    }
}
