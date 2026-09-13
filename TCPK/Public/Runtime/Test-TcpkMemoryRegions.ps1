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

    Read-only, and never writes to the target. The region WALK opens the process with
    PROCESS_QUERY_INFORMATION only, the minimum VirtualQueryEx requires. The entropy
    pass that calibrates the result needs to measure bytes, so it opens a SECOND handle
    with PROCESS_VM_READ and reads up to 64 KB from each flagged executable region. That
    pass is skipped with -NoEntropy, and it degrades to silence if the read handle is
    denied: the RWX and private-exec findings are emitted either way.

.PARAMETER ProcessName
    Process name (no .exe) to inspect.

.PARAMETER ProcessId
    Specific PID to inspect, instead of resolving by name.

.PARAMETER NoEntropy
    Skip the entropy pass and keep the query-only handle footprint. Use when the
    engagement forbids reading target memory, or to avoid a second OpenProcess on a
    sensitive target. The RWX and private-exec findings are unaffected.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([string]$ProcessName, [int]$ProcessId, [switch]$NoEntropy)

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
            # Flagged regions retained for the entropy pass after this loop.
            $flagged = New-Object 'System.Collections.Generic.List[object]'

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

                # Retain for the entropy pass: executable, and either writable or not
                # backed by an image, is exactly the set worth measuring.
                if (($isRwx -or -not $isImage) -and $flagged.Count -lt 16) {
                    $flagged.Add([pscustomobject]@{ Base = $base; Size = $size; Prot = $prot; IsRwx = $isRwx })
                }
            }

            # ---- entropy pass over the flagged executable regions ---------------
            # WHY. The JIT-module check above is a PROXY for "is code generation expected
            # in this process", and the comments there already concede it is not proof
            # either way. Entropy measures the region itself instead of inferring from the
            # module list. Compiled machine code, JIT output included, carries opcode
            # structure and repeated register encodings and sits around 5.5-6.7 bits/byte.
            # Compressed, encrypted or packed content approaches 8.0. An executable region
            # measuring above 7.2 is not plain machine code, whatever the module list says.
            #
            # This needs PROCESS_VM_READ, which the region walk deliberately does not take.
            # A second handle is opened only for this pass, and the pass degrades to
            # silence if it is denied: the RWX and private-exec findings below are emitted
            # either way, so a protected process loses calibration, never the finding.
            $entropyBy = @{}
            $entropyNote = ''
            if (-not $NoEntropy -and $flagged.Count -gt 0 -and ('Tcpk.MemRead' -as [type])) {
                $rh = [IntPtr]::Zero
                try { $rh = [Tcpk.MemRead]::Open($p.Id, $false) } catch { }
                if ($rh -ne [IntPtr]::Zero) {
                    try {
                        foreach ($fr in $flagged) {
                            $want = [int][Math]::Min([int64]65536, [int64]$fr.Size)
                            if ($want -lt 512) { continue }
                            $bytes = $null
                            try { $bytes = [Tcpk.MemRead]::ReadBytes($rh, $fr.Base, $want) } catch { $bytes = $null }
                            if ($null -eq $bytes -or $bytes.Length -lt 512) { continue }
                            $entropyBy[$fr.Base] = Get-TcpkByteEntropy -Bytes $bytes
                        }
                    } finally {
                        try { [void][Tcpk.MemRead]::CloseHandle($rh) } catch { }
                    }
                }
                if ($entropyBy.Count -gt 0) {
                    $maxEnt = (@($entropyBy.Values) | Measure-Object -Maximum).Maximum
                    $entropyNote = "; entropy max=$maxEnt over $($entropyBy.Count) sampled region(s)"
                }
            }

            $jitLabel = if ($hasJit) { ($jitFound -join '+') } else { 'none' }

            # High-entropy executable memory: reported separately because it is the one
            # observation here that a JIT runtime does NOT explain away.
            $hot = New-Object 'System.Collections.Generic.List[string]'
            foreach ($k in $entropyBy.Keys) {
                if ($entropyBy[$k] -ge 7.2) {
                    $hot.Add(("0x{0:X} = {1} bits/byte" -f [int64]$k, $entropyBy[$k]))
                }
            }
            if ($hot.Count -gt 0) {
                New-TcpkFinding -Module 'runtime' -RuleId 'memregion.high-entropy-exec' `
                    -Severity 'MEDIUM' -Confidence 'Confirmed' `
                    -Title "$($p.Name): $($hot.Count) executable region(s) measure as packed or encrypted, not machine code" `
                    -File "$($p.Name) (PID $($p.Id))" `
                    -Evidence (($hot -join '; ') + "; jit=$jitLabel") `
                    -Cwe @('CWE-1327') `
                    -Description ('Executable memory in this process measures at or above 7.2 bits/byte. ' +
                        'Compiled machine code does not look like this: x86/x64 code carries opcode ' +
                        'structure and repeated register encodings that hold real code, including JIT ' +
                        'output, well below 7 bits/byte. Content at this level is compressed, encrypted ' +
                        'or packed. In executable memory that means either a packer that has not yet ' +
                        'unpacked its payload, or data that is not code occupying an executable page. ' +
                        'Unlike the RWX and private-exec observations above, a JIT runtime does not ' +
                        'explain this one: V8 and the CLR emit ordinary machine code, not high-entropy ' +
                        'blobs. Entropy is a discriminator, not proof of malice. Confirm by dumping the ' +
                        'region with Save-TcpkMemoryRegion and inspecting it.') `
                    -Fix 'Dump the region with Save-TcpkMemoryRegion and identify the content. If the product legitimately ships a packer or an encrypted asset cache, confirm those pages do not need to be executable: data should live in non-executable memory. If the content is unaccounted for, treat it as the priority finding and trace what wrote it.'
            }

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
                    -Evidence ("rwx=$rwxCount ($([int]($rwxBytes / 1KB)) KB); jit=$jitLabel; " + ($rwxSample -join '; ') + $entropyNote) `
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
                    -Evidence ("private-exec=$privExecCount ($([int]($privExecBytes / 1KB)) KB); jit=$jitLabel; " + ($privSample -join '; ') + $entropyNote) `
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
