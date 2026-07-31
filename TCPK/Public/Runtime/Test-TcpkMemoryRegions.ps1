function Test-TcpkMemoryRegions {
<#
.SYNOPSIS
    E11. Virtual memory region protection: RWX pages and private executable memory.

.DESCRIPTION
    Walks the target process address space with VirtualQueryEx and classifies every
    committed region by protection and type. Two conditions are reported:

      RWX             a region that is simultaneously WRITABLE and EXECUTABLE
                      (PAGE_EXECUTE_READWRITE / PAGE_EXECUTE_WRITECOPY). An
                      attacker who achieves a memory write does not then need to
                      defeat DEP or find a VirtualProtect gadget: the page is
                      already executable. It weakens every memory-safety
                      mitigation the process otherwise has.

      Private exec    executable memory NOT backed by a mapped image file
                      (MEM_PRIVATE). Loaded modules are MEM_IMAGE, so executable
                      private memory is either a JIT or code that arrived without
                      passing through the loader. It is the shape both JIT engines
                      and manual-map / reflective loaders produce.

    JIT CALIBRATION. This is the difference between a useful check and noise.
    .NET, V8 (Electron, Node) and the JVM all generate code at runtime, so on
    those processes private executable memory is EXPECTED and not a defect. The
    check therefore looks for a JIT runtime among the loaded modules and reports
    accordingly:

      no JIT runtime      RWX is a genuine hardening defect, reported HIGH.
                          A plain native application has no reason to hold a
                          writable-executable page.
      JIT runtime present reported MEDIUM as posture, not as a bug. Worth noting
                          rather than filing: .NET 7 and later enable W^X by
                          default, so RWX in a modern .NET process is no longer
                          the expected shape and is worth a question.

    Read-only. Opens the process with PROCESS_QUERY_INFORMATION only, the minimum
    VirtualQueryEx requires, and never reads or writes region contents.

.PARAMETER ProcessName
    Process name (no .exe) to inspect.

.PARAMETER ProcessId
    Specific PID to inspect, instead of resolving by name.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([string]$ProcessName, [int]$ProcessId)

    if (-not (Assert-TcpkWindows 'Test-TcpkMemoryRegions')) { return }

    if (-not ('Tcpk.MemRegions' -as [type])) {
        New-TcpkSkippedFinding -RuleId 'memregion.unavailable' `
            -Title 'Memory-region primitive unavailable' `
            -Reason 'Tcpk.MemRegions failed to compile.'
        return
    }

    $procs = @()
    if ($ProcessId) {
        $procs = @(Get-Process -Id $ProcessId -ErrorAction SilentlyContinue)
    } elseif ($ProcessName) {
        $procs = @(Get-Process -Name ($ProcessName -replace '\.exe$', '') -ErrorAction SilentlyContinue)
    }
    if (-not $procs.Count) {
        New-TcpkSkippedFinding -RuleId 'memregion.no-process' `
            -Title "Process not running: $ProcessName$ProcessId" `
            -Reason 'No matching live process.'
        return
    }

    # Runtimes that generate code at execution time. Their presence makes executable
    # private memory expected rather than suspicious.
    $jitModules = @(
        'clr.dll', 'coreclr.dll', 'clrjit.dll', 'mscorwks.dll',   # .NET
        'jvm.dll',                                                # Java
        'node.dll', 'libnode.dll',                                # Node
        'libcef.dll', 'chrome_elf.dll'                            # Chromium / Electron / CEF
    )

    foreach ($p in $procs) {
        $jitFound = New-Object 'System.Collections.Generic.List[string]'
        try {
            foreach ($m in $p.Modules) {
                $mn = "$($m.ModuleName)".ToLowerInvariant()
                if ($jitModules -contains $mn -and -not $jitFound.Contains($mn)) { $jitFound.Add($mn) }
            }
        } catch { }
        $hasJit = ($jitFound.Count -gt 0)

        $h = [IntPtr]::Zero
        try { $h = [Tcpk.MemRegions]::Open($p.Id) } catch { }
        if ($h -eq [IntPtr]::Zero) {
            New-TcpkSkippedFinding -RuleId 'memregion.open-denied' `
                -Title "Cannot query memory of $($p.Name) (PID $($p.Id))" `
                -Reason 'OpenProcess denied. Re-run elevated, or the process is protected.'
            continue
        }

        try {
            $flat = @()
            try { $flat = [Tcpk.MemRegions]::Enumerate($h) } catch { }
            if (-not $flat -or $flat.Count -lt 4) { continue }

            $rwxCount = 0; $rwxBytes = [int64]0
            $privExecCount = 0; $privExecBytes = [int64]0
            $total = 0
            $rwxSample = New-Object 'System.Collections.Generic.List[string]'
            $privSample = New-Object 'System.Collections.Generic.List[string]'

            for ($i = 0; ($i + 3) -lt $flat.Count; $i += 4) {
                $base = [int64]$flat[$i]
                $size = [int64]$flat[$i + 1]
                $prot = [int64]$flat[$i + 2]
                $type = [int64]$flat[$i + 3]
                $total++

                if (($prot -band 0x100) -ne 0) { continue }        # PAGE_GUARD
                $isExec = (($prot -band 0xF0) -ne 0)               # any EXECUTE_*
                if (-not $isExec) { continue }
                $isRwx = (($prot -band 0xC0) -ne 0)                # EXECUTE_READWRITE / WRITECOPY
                $isImage = ($type -eq 0x1000000)                   # MEM_IMAGE

                if ($isRwx) {
                    $rwxCount++; $rwxBytes += $size
                    if ($rwxSample.Count -lt 6) {
                        $rwxSample.Add(("0x{0:X} ({1} KB, prot 0x{2:X})" -f $base, [int]($size / 1KB), $prot))
                    }
                }
                if (-not $isImage) {
                    $privExecCount++; $privExecBytes += $size
                    if ($privSample.Count -lt 6) {
                        $privSample.Add(("0x{0:X} ({1} KB, prot 0x{2:X})" -f $base, [int]($size / 1KB), $prot))
                    }
                }
            }

            $jitNote = 'No JIT runtime module was found loaded, so runtime code generation does not explain this.'
            if ($hasJit) {
                $jitNote = ("A JIT runtime is loaded (" + ($jitFound -join ', ') +
                    '), which generates executable memory as a matter of course. Reported as posture rather ' +
                    'than as a defect. Note that .NET 7 and later enable W^X by default, so a writable-executable ' +
                    'page in a modern .NET process is no longer the expected shape.')
            }

            if ($rwxCount -gt 0) {
                $sev = 'HIGH'
                if ($hasJit) { $sev = 'MEDIUM' }
                New-TcpkFinding -Module 'runtime' -RuleId 'memregion.rwx' `
                    -Severity $sev -Confidence 'Confirmed' `
                    -Title "$($p.Name): $rwxCount writable-executable region(s), $([int]($rwxBytes / 1KB)) KB" `
                    -File "$($p.Name) (PID $($p.Id))" `
                    -Evidence (("rwx=$rwxCount ($([int]($rwxBytes / 1KB)) KB); jit=" + $(if ($hasJit) { ($jitFound -join '+') } else { 'none' }) + '; ') + ($rwxSample -join '; ')) `
                    -Cwe @('CWE-119', 'CWE-1327') `
                    -Description ('The process holds memory that is writable and executable at the same time. ' +
                        'An attacker who obtains a memory write into such a region does not then need to defeat ' +
                        'DEP or chain a VirtualProtect gadget, because the page is already executable. ' + $jitNote) `
                    -Fix 'Allocate as read-write, write the code, then VirtualProtect to read-execute (W^X). Never hold PAGE_EXECUTE_READWRITE. On .NET 7+ leave the default W^X policy enabled.'
            }

            if ($privExecCount -gt 0) {
                $sev = 'MEDIUM'
                if ($hasJit) { $sev = 'INFO' }
                New-TcpkFinding -Module 'runtime' -RuleId 'memregion.private-exec' `
                    -Severity $sev -Confidence 'Confirmed' `
                    -Title "$($p.Name): $privExecCount executable region(s) not backed by an image, $([int]($privExecBytes / 1KB)) KB" `
                    -File "$($p.Name) (PID $($p.Id))" `
                    -Evidence (("private-exec=$privExecCount ($([int]($privExecBytes / 1KB)) KB); jit=" + $(if ($hasJit) { ($jitFound -join '+') } else { 'none' }) + '; ') + ($privSample -join '; ')) `
                    -Cwe @('CWE-1327') `
                    -Description ('Executable memory that is not backed by a mapped image file. Loaded modules ' +
                        'are MEM_IMAGE, so this is code that either was generated at runtime or arrived without ' +
                        'passing through the loader, which is the shape a manual-map or reflective loader ' +
                        'produces. ' + $jitNote) `
                    -Fix 'Where this is not the JIT, identify what allocated it. Enabling the process mitigation policy for dynamic code (ProcessDynamicCodePolicy) prevents non-JIT code generation entirely.'
            }

            New-TcpkFinding -Module 'runtime' -RuleId 'memregion.summary' `
                -Severity 'INFO' -Confidence 'Confirmed' `
                -Title "$($p.Name): $total committed memory region(s)" `
                -File "$($p.Name) (PID $($p.Id))" `
                -Evidence ("regions=$total; rwx=$rwxCount; private-exec=$privExecCount; jit=" +
                    $(if ($hasJit) { ($jitFound -join '+') } else { 'none' })) `
                -Description 'Committed virtual memory region census for the process.'
        } finally {
            try { [void][Tcpk.MemRegions]::CloseHandle($h) } catch { }
        }
    }
}
