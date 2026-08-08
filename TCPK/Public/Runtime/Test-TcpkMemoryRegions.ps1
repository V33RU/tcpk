function Test-TcpkMemoryRegions {
<#
.SYNOPSIS
    E18. Virtual memory region protection: RWX pages and private executable memory.

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

    # Runtimes that generate code at execution time.  Detection is by MODULE NAME for
    # runtimes that ship as separate DLLs, and by RUNTIME-CLASS fingerprint for runtimes
    # that statically link their JIT (Electron/Chromium: V8 lives in the main .exe).
    # Electron does NOT ship chrome_elf.dll or libcef.dll as separate modules; it ships
    # libglesv2.dll, libegl.dll, vk_swiftshader.dll etc.  The old list missed every
    # Electron app that has ever shipped.
    $jitModuleNames = @(
        # .NET CLR
        'clr.dll', 'coreclr.dll', 'clrjit.dll', 'mscorwks.dll',
        # Java
        'jvm.dll',
        # Node.js (standalone, not Electron)
        'node.dll', 'libnode.dll',
        # Chromium / CEF companion DLLs.  Any one means V8 is present in the process.
        # Electron statically links V8 into the main exe; the companion DLLs are still
        # separate: libglesv2.dll, libegl.dll, vk_swiftshader.dll are always present.
        'libglesv2.dll', 'libegl.dll', 'vk_swiftshader.dll', 'libvk_swiftshader.dll',
        'libcef.dll',       # Chromium Embedded Framework host apps
        'chrome_elf.dll'    # branded Chromium browser builds only
        # DELIBERATELY NOT LISTED: vulkan-1.dll and d3dcompiler_47.dll. Both ship in
        # System32 and are loaded by ANY Vulkan or D3D shader-compiling process - games,
        # Unity and Qt apps, emulators, CAD - none of which carry V8, the CLR or a JVM.
        # Treating them as JIT proxies set $hasJit on those targets, and $hasJit drives
        # the RWX verdict down from HIGH to INFO, so a genuine writable-executable
        # finding was suppressed on a plain native app. ffmpeg.dll is out for the same
        # reason: Chromium ships one, but so does every media player.
        # The entries kept above are shipped BY the runtime itself, not by Windows.
    )

    foreach ($p in $procs) {
        $jitFound = New-Object 'System.Collections.Generic.List[string]'
        try {
            foreach ($m in $p.Modules) {
                $mn = "$($m.ModuleName)".ToLowerInvariant()
                if ($jitModuleNames -contains $mn -and -not $jitFound.Contains($mn)) { $jitFound.Add($mn) }
            }
        } catch { }

        # Runtime-class fallback: if no JIT DLL matched, probe the main module path.
        # Electron apps have all-in-one exes with V8 statically linked, so the module
        # list never shows a JIT-named DLL.  A 64 KB header read is enough for the
        # string markers Test-TcpkIsChromiumRuntime checks.
        if ($jitFound.Count -eq 0) {
            $mainModPath = ''
            try { $mainModPath = $p.MainModule.FileName } catch { }
            if ($mainModPath) {
                $headerText = ''
                try {
                    $hbuf = [byte[]]::new(65536)
                    $hfs = [System.IO.FileStream]::new($mainModPath,
                        [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read,
                        [System.IO.FileShare]::ReadWrite)
                    $hn = $hfs.Read($hbuf, 0, $hbuf.Length)
                    $hfs.Dispose()
                    if ($hn -gt 0) { $headerText = [System.Text.Encoding]::Latin1.GetString($hbuf, 0, $hn) }
                } catch { }
                if (Test-TcpkIsChromiumRuntime -Name ([System.IO.Path]::GetFileName($mainModPath)) -Text $headerText) {
                    $jitFound.Add('V8 (statically linked)')
                }
            }
        }

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

            $jitLabel = if ($hasJit) { ($jitFound -join '+') } else { 'none' }

            $jitNote = if ($hasJit) {
                # V8 / Electron special-case: every Chromium-derived app holds RWX V8 code-space
                # pages. These are MEM_PRIVATE, often reserved-NOACCESS then committed-RWX, and
                # appear identically in all renderer processes.  They are JIT output, not injected
                # code.  V8 supports --write-protect-code-memory and --jitless, but very few
                # Electron apps opt in.  Flagging this HIGH would flag the entire Chromium ecosystem.
                "JIT runtime detected ($jitLabel). Writable-executable pages are expected: V8 " +
                "writes machine code into private RWX pages at runtime.  This is the same shape " +
                "every Chromium-derived and Electron application produces.  Reported " +
                "as an INFO hardening note (W^X not enforced), not as a defect.  V8 does support " +
                "--write-protect-code-memory and --jitless; Electron apps can pass these via app.commandLine."
            } else {
                'No JIT runtime was detected. A plain native application has no legitimate reason ' +
                'to hold a writable-executable page; this is a genuine W^X hardening defect.'
            }

            if ($rwxCount -gt 0) {
                # Only HIGH when no plausible JIT is present.
                # When a JIT is confirmed (V8, .NET, JVM) downgrade to INFO: RWX is an
                # expected product of code generation, not an injected-code indicator.
                # MEDIUM was previously used here for JIT processes but was wrong: it implies
                # a real defect when the observation is normal behavior for that runtime class.
                $sev = if ($hasJit) { 'INFO' } else { 'HIGH' }
                New-TcpkFinding -Module 'runtime' -RuleId 'memregion.rwx' `
                    -Severity $sev -Confidence 'Confirmed' `
                    -Title "$($p.Name): $rwxCount writable-executable region(s), $([int]($rwxBytes / 1KB)) KB" `
                    -File "$($p.Name) (PID $($p.Id))" `
                    -Evidence ("rwx=$rwxCount ($([int]($rwxBytes / 1KB)) KB); jit=$jitLabel; " + ($rwxSample -join '; ')) `
                    -Cwe @('CWE-119', 'CWE-1327') `
                    -Description ('The process holds memory that is simultaneously writable and executable. ' +
                        $jitNote) `
                    -Fix 'For JIT runtimes: enable --write-protect-code-memory (V8/Electron) or leave .NET 7+ W^X defaults enabled. For native apps with no JIT: allocate read-write, write, then VirtualProtect to read-execute. Never hold PAGE_EXECUTE_READWRITE outside a JIT emit window.'
            }

            if ($privExecCount -gt 0) {
                $sev = if ($hasJit) { 'INFO' } else { 'MEDIUM' }
                New-TcpkFinding -Module 'runtime' -RuleId 'memregion.private-exec' `
                    -Severity $sev -Confidence 'Confirmed' `
                    -Title "$($p.Name): $privExecCount executable region(s) not backed by an image, $([int]($privExecBytes / 1KB)) KB" `
                    -File "$($p.Name) (PID $($p.Id))" `
                    -Evidence ("private-exec=$privExecCount ($([int]($privExecBytes / 1KB)) KB); jit=$jitLabel; " + ($privSample -join '; ')) `
                    -Cwe @('CWE-1327') `
                    -Description ('Executable memory not backed by a mapped image file. Loaded modules are ' +
                        'MEM_IMAGE; private executable memory is either JIT output or code that arrived ' +
                        'without passing through the loader (the shape a manual-map / reflective loader ' +
                        'produces). ' + $jitNote) `
                    -Fix 'Where this is not the JIT, identify what allocated it. Enabling ProcessDynamicCodePolicy prevents non-JIT code generation entirely.'
            }

            New-TcpkFinding -Module 'runtime' -RuleId 'memregion.summary' `
                -Severity 'INFO' -Confidence 'Confirmed' `
                -Title "$($p.Name): $total committed memory region(s)" `
                -File "$($p.Name) (PID $($p.Id))" `
                -Evidence ("regions=$total; rwx=$rwxCount; private-exec=$privExecCount; jit=$jitLabel") `
                -Description 'Committed virtual memory region census for the process.'
        } finally {
            try { [void][Tcpk.MemRegions]::CloseHandle($h) } catch { }
        }
    }
}
