function Invoke-TcpkManagedCarve {
<#
.SYNOPSIS
    V22. Carve managed (.NET) assemblies out of a live process's private memory and
    prove each one by parsing it.

.DESCRIPTION
    WHY THIS EXISTS. Every managed analysis in TCPK reads a FILE: Get-TcpkCecilAssembly
    opens a path, Invoke-TcpkDecompile runs ilspycmd against a path. An assembly loaded
    with Assembly.Load(byte[]) never becomes a file, so none of that machinery can see
    it. Test-TcpkMemoryRegions and Test-TcpkThreadStart see only the SHAPE of such a
    load (executable memory not backed by an image) and cannot say what is in it.

    This closes that loop. It walks the target's committed, readable, NON-IMAGE regions,
    finds PE images sitting in them, keeps the ones that carry a CLI header, writes each
    to the work directory, and then PARSES the carved file with the bundled Mono.Cecil.

    THE PROOF IS THE PARSE. A byte pattern that looks like a PE is a hypothesis. A file
    that Cecil opens, and whose assembly name, module name and type list resolve, is an
    observable and reproducible effect: the same region carves to the same bytes and the
    same parse result on every run. That is why findings here are Confirmed (dynamic)
    rather than Inferred, and it is the difference between "there is odd memory here" and
    "here is the assembly that was in it, on disk, ready to decompile."

    LAYOUT. Assembly.Load(byte[]) keeps the assembly in the managed heap as the raw FILE
    bytes, so the carve is verbatim from MZ to the end of the last section as computed
    from the section table. That is the case this targets and it needs no fixup. An
    image-ALIGNED copy (one the loader or a manual mapper expanded to section virtual
    addresses) will not parse after a verbatim carve; rather than ship a fragile section
    rebuilder that can silently produce a corrupt file, this reports the header as found
    but unvalidated and says so. Do not read an unvalidated hit as a clean region.

    CALIBRATION, OR THIS BECOMES A NOISE CANNON. Legitimate .NET applications hold
    managed PE images in private memory routinely: self-extracting packers (Costura and
    friends), plugin hosts, and anything that embeds a dependency as a resource and loads
    it from bytes. So the mere presence of one is NOT a defect. What is reported, and
    what actually matters to an audit, is whether the carved assembly also exists on disk:

      memory.fileless-managed-assembly   MEDIUM  Carved and parsed, and its identity
                                                 matches NO module loaded from a file and
                                                 no file in the application directory.
                                                 Code executes here that no disk-based
                                                 review, no Authenticode check and no
                                                 file-integrity control ever covers.

      memory.in-memory-managed-assembly  INFO    Carved and parsed, but a file of the same
                                                 identity exists on disk. Normal for a
                                                 packer or resource-embedded dependency.
                                                 Scope information, not a defect.

      memory.managed-header-unparsed     INFO    A CLI-bearing PE header was found but the
                                                 carve did not parse (image-aligned, or
                                                 partially paged out). Recorded so the
                                                 region is not mistaken for clean.

.PARAMETER ProcessName
    Process name (no .exe).

.PARAMETER ProcessId
    Specific PID, instead of resolving by name.

.PARAMETER MaxScanMB
    Ceiling on total private memory read (default 512 MB). Reported in the summary so a
    partial scan is never mistaken for a complete one.

.PARAMETER KeepFiles
    Keep every carved file. By default only files that PARSED are kept; a candidate that
    failed to parse is deleted so the work directory does not fill with junk.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ParameterSetName = 'ByName')][string]$ProcessName,
        [Parameter(Mandatory, ParameterSetName = 'ById')][int]$ProcessId,
        [int]$MaxScanMB = 512,
        [switch]$KeepFiles
    )

    if (-not (Assert-TcpkWindows 'Invoke-TcpkManagedCarve')) { return }
    if (-not ('Tcpk.MemRead' -as [type])) {
        New-TcpkSkippedFinding -RuleId 'carve.unavailable' `
            -Title 'Memory-read primitive unavailable' -Reason 'Tcpk.MemRead failed to load.'
        return
    }
    if (-not (Initialize-TcpkCecil)) {
        New-TcpkSkippedFinding -RuleId 'carve.no-cecil' `
            -Title 'Managed carve skipped (Mono.Cecil unavailable)' `
            -Reason 'Carved bytes can only be proven by parsing them; without Cecil this would report guesses.'
        return
    }

    # --- little-endian readers with bounds checks -----------------------------
    function Get-U16([byte[]]$b, [int]$o) {
        if ($o -lt 0 -or ($o + 2) -gt $b.Length) { return -1 }
        return [int][BitConverter]::ToUInt16($b, $o)
    }
    function Get-U32([byte[]]$b, [int]$o) {
        if ($o -lt 0 -or ($o + 4) -gt $b.Length) { return [int64](-1) }
        return [int64][BitConverter]::ToUInt32($b, $o)
    }

    $procs = @()
    if ($PSCmdlet.ParameterSetName -eq 'ById') {
        $procs = @(Get-Process -Id $ProcessId -ErrorAction SilentlyContinue)
    } else {
        $procs = @(Get-Process -Name ($ProcessName -replace '\.exe$', '') -ErrorAction SilentlyContinue)
    }
    if (-not $procs.Count) {
        New-TcpkSkippedFinding -RuleId 'carve.no-process' `
            -Title "Process not running: $ProcessName$ProcessId" -Reason 'No matching live process.'
        return
    }

    foreach ($p in $procs) {

        # ---- what this process legitimately has on disk ----------------------
        # Identity comparison is by base file name without extension, which is how an
        # assembly name relates to its file. Kept as a hash set for O(1) lookup.
        $onDisk = @{}
        $appDir = ''
        try { $appDir = Split-Path -Parent $p.MainModule.FileName } catch { }
        try {
            foreach ($m in $p.Modules) {
                $n = ''
                try { $n = [System.IO.Path]::GetFileNameWithoutExtension("$($m.ModuleName)") } catch { }
                if ($n) { $onDisk[$n.ToLowerInvariant()] = $true }
            }
        } catch { }
        if ($appDir -and (Test-Path -LiteralPath $appDir)) {
            try {
                foreach ($f in (Get-ChildItem -LiteralPath $appDir -Recurse -File -Include '*.dll', '*.exe' -ErrorAction SilentlyContinue)) {
                    $onDisk[$f.BaseName.ToLowerInvariant()] = $true
                }
            } catch { }
        }

        $h = [IntPtr]::Zero
        try { $h = [Tcpk.MemRead]::Open($p.Id, $false) } catch { }
        if ($h -eq [IntPtr]::Zero) {
            New-TcpkSkippedFinding -RuleId 'carve.open-denied' `
                -Title "Cannot read memory of $($p.Name) (PID $($p.Id))" `
                -Reason 'OpenProcess denied. Re-run elevated, or the process is protected.'
            continue
        }

        $budget = [int64]$MaxScanMB * 1MB
        $scanned = [int64]0
        $regionCap = [int64]67108864          # 64 MB per region
        $carvedOk = 0; $carvedFail = 0; $regionsRead = 0
        $hitBudget = $false

        try {
            $flat = @()
            try { $flat = [Tcpk.MemRead]::Regions($h, $regionCap, $false) } catch { $flat = @() }
            if (-not $flat -or $flat.Count -lt 2) { continue }

            for ($i = 0; ($i + 1) -lt $flat.Count; $i += 2) {
                if ($scanned -ge $budget) { $hitBudget = $true; break }
                $rBase = [int64]$flat[$i]
                $rSize = [int64]$flat[$i + 1]
                if ($rSize -lt 1024) { continue }
                $take = $rSize
                if ($take -gt ($budget - $scanned)) { $take = ($budget - $scanned) }
                if ($take -gt [int64][int]::MaxValue) { $take = [int64]67108864 }

                $buf = $null
                try { $buf = [Tcpk.MemRead]::ReadBytes($h, $rBase, [int]$take) } catch { $buf = $null }
                if ($null -eq $buf -or $buf.Length -lt 1024) { continue }
                $scanned += $buf.Length
                $regionsRead++

                # ---- scan for MZ ---------------------------------------------
                # [Array]::IndexOf runs in native code; a per-byte PowerShell loop over
                # hundreds of MB would not finish in useful time.
                $pos = 0
                while ($pos -ge 0 -and $pos -lt ($buf.Length - 2)) {
                    $mz = [Array]::IndexOf($buf, [byte]0x4D, $pos)
                    if ($mz -lt 0 -or $mz -ge ($buf.Length - 2)) { break }
                    $pos = $mz + 1
                    if ($buf[$mz + 1] -ne 0x5A) { continue }

                    $lfanew = Get-U32 $buf ($mz + 0x3C)
                    if ($lfanew -lt 0x40 -or $lfanew -gt 0x1000) { continue }
                    $pe = $mz + [int]$lfanew
                    if (($pe + 24) -ge $buf.Length) { continue }
                    if ($buf[$pe] -ne 0x50 -or $buf[$pe + 1] -ne 0x45 -or
                        $buf[$pe + 2] -ne 0x00 -or $buf[$pe + 3] -ne 0x00) { continue }

                    $nSections = Get-U16 $buf ($pe + 4 + 2)
                    $optSize   = Get-U16 $buf ($pe + 4 + 16)
                    if ($nSections -le 0 -or $nSections -gt 96 -or $optSize -le 0) { continue }
                    $opt = $pe + 24
                    $magic = Get-U16 $buf $opt
                    if ($magic -ne 0x10B -and $magic -ne 0x20B) { continue }

                    # CLI header lives in data directory 14. Its presence is what makes
                    # this a MANAGED image rather than any native DLL in the heap.
                    $ddOff = 96
                    if ($magic -eq 0x20B) { $ddOff = 112 }
                    $cliRva  = Get-U32 $buf ($opt + $ddOff + (14 * 8))
                    $cliSize = Get-U32 $buf ($opt + $ddOff + (14 * 8) + 4)
                    if ($cliRva -le 0 -or $cliSize -le 0) { continue }

                    # ---- file-aligned extent from the section table ------------
                    $secTab = $opt + $optSize
                    $end = Get-U32 $buf ($opt + 60)              # SizeOfHeaders
                    if ($end -lt 0) { $end = 0 }
                    $sane = $true
                    for ($s = 0; $s -lt $nSections; $s++) {
                        $so = $secTab + ($s * 40)
                        if (($so + 40) -gt $buf.Length) { $sane = $false; break }
                        $rawSize = Get-U32 $buf ($so + 16)
                        $rawPtr  = Get-U32 $buf ($so + 20)
                        if ($rawSize -lt 0 -or $rawPtr -lt 0) { $sane = $false; break }
                        $secEnd = $rawPtr + $rawSize
                        if ($secEnd -gt $end) { $end = $secEnd }
                    }
                    if (-not $sane) { continue }
                    if ($end -lt 512 -or $end -gt 134217728) { continue }     # 128 MB ceiling
                    if (($mz + $end) -gt $buf.Length) { $end = $buf.Length - $mz }
                    if ($end -lt 512) { continue }

                    # ---- carve + prove ----------------------------------------
                    $addrHex = "{0:X}" -f ($rBase + $mz)
                    $outPath = New-TcpkWorkPath -Kind 'extract' -Prefix "carve-$($p.Id)-$addrHex" -Extension 'dll'
                    $wrote = $false
                    try {
                        $slice = New-Object 'byte[]' ([int]$end)
                        [Array]::Copy($buf, $mz, $slice, 0, [int]$end)
                        [System.IO.File]::WriteAllBytes($outPath, $slice)
                        $wrote = $true
                    } catch { $wrote = $false }
                    if (-not $wrote) { continue }

                    $asmName = ''; $modName = ''; $typeCount = 0; $parsed = $false
                    $asm = $null
                    try {
                        $asm = [Mono.Cecil.AssemblyDefinition]::ReadAssembly($outPath)
                        if ($asm) {
                            $asmName = "$($asm.Name.Name)"
                            $modName = "$($asm.MainModule.Name)"
                            try { $typeCount = @($asm.MainModule.GetTypes()).Count } catch { $typeCount = 0 }
                            $parsed = $true
                        }
                    } catch { $parsed = $false } finally {
                        if ($asm) { try { $asm.Dispose() } catch { } }
                    }

                    if (-not $parsed) {
                        $carvedFail++
                        if (-not $KeepFiles) {
                            try { Remove-Item -LiteralPath $outPath -Force -ErrorAction SilentlyContinue } catch { }
                        }
                        New-TcpkFinding -Module 'runtime' -RuleId 'memory.managed-header-unparsed' `
                            -Severity 'INFO' -Confidence 'Inferred' `
                            -Title "$($p.Name): managed PE header at 0x$addrHex did not parse after carve" `
                            -File "$($p.Name) (PID $($p.Id))" `
                            -Evidence ("base=0x$addrHex; cli-rva=0x{0:X}; sections=$nSections; carved={1} bytes" -f $cliRva, $end) `
                            -Description ('A PE header carrying a CLI (managed) data directory was found in ' +
                                'private memory, but a verbatim file-aligned carve of it did not parse. The ' +
                                'usual reason is that the copy is image-ALIGNED (expanded to section virtual ' +
                                'addresses by the loader or a manual mapper) rather than the raw file bytes, ' +
                                'or that part of it is paged out. The region is NOT clean: a managed image is ' +
                                'present, it simply needs a section rebuild to reconstruct.') `
                            -Fix 'Reconstruct by hand if this needs following up: dump the region with Save-TcpkMemoryRegion, then rebuild section offsets from virtual addresses back to file offsets before parsing.'
                        continue
                    }

                    $carvedOk++
                    $key = ''
                    if ($asmName) { $key = $asmName.ToLowerInvariant() }
                    $isFileless = ($key -and -not $onDisk.ContainsKey($key))

                    if ($isFileless) {
                        New-TcpkFinding -Module 'runtime' -RuleId 'memory.fileless-managed-assembly' `
                            -Severity 'MEDIUM' -Confidence 'Confirmed (dynamic)' `
                            -Title "$($p.Name) holds a managed assembly with no file on disk: $asmName" `
                            -File $outPath `
                            -Evidence ("pid=$($p.Id); base=0x$addrHex; assembly=$asmName; module=$modName; types=$typeCount; carved=$end bytes; parsed=yes") `
                            -Cwe @('CWE-494', 'CWE-506') `
                            -Description ('A .NET assembly is resident in this process''s private memory and ' +
                                'its identity matches no module loaded from a file and no file in the ' +
                                'application directory. It was loaded from bytes (Assembly.Load(byte[]) or ' +
                                'equivalent), so it never existed as a file. Security consequences for an ' +
                                'audit of this product: the code is invisible to any review performed against ' +
                                'the installed files, it carries no Authenticode signature that can be ' +
                                'verified, no file-integrity or allowlisting control covers it, and it does ' +
                                'not appear in the module list as a backed image. The carved assembly has ' +
                                'been written to the path in File and parses cleanly, so it can be ' +
                                'decompiled and reviewed like any other assembly.') `
                            -Fix 'Establish where these bytes come from. If the product legitimately loads assemblies from memory (a packer or plugin host), confirm the bytes are integrity-checked with a signature the application verifies BEFORE Assembly.Load, not merely decompressed from a resource. If the source is a network download or a writable path, that is a code-delivery channel with no signature check and it should be treated as the priority finding.'
                    } else {
                        New-TcpkFinding -Module 'runtime' -RuleId 'memory.in-memory-managed-assembly' `
                            -Severity 'INFO' -Confidence 'Confirmed (dynamic)' `
                            -Title "$($p.Name) loaded $asmName from memory (a copy also exists on disk)" `
                            -File $outPath `
                            -Evidence ("pid=$($p.Id); base=0x$addrHex; assembly=$asmName; module=$modName; types=$typeCount; carved=$end bytes; on-disk=yes") `
                            -Description ('A .NET assembly is resident in private memory as raw file bytes and ' +
                                'a file of the same identity exists on disk. This is the normal shape of a ' +
                                'self-extracting packer or a resource-embedded dependency being loaded from ' +
                                'bytes. Reported as scope information, not as a defect: it tells the reader ' +
                                'that this product loads code from memory, which is the mechanism to check if ' +
                                'a fileless assembly is found elsewhere in the same process.') `
                            -Fix 'No action required. Confirm the on-disk copy is the same build as the in-memory one if exact version accounting matters to the engagement.'
                    }
                }
            }
        } finally {
            try { [void][Tcpk.MemRead]::CloseHandle($h) } catch { }
        }

        # ---- coverage summary: never let a capped scan read as a clean scan ---
        $cov = "regions=$regionsRead; scanned=$([int]($scanned / 1MB)) MB; parsed=$carvedOk; unparsed=$carvedFail"
        if ($hitBudget) {
            New-TcpkFinding -Module 'runtime' -RuleId 'memory.carve-coverage-capped' `
                -Severity 'INFO' -Confidence 'Confirmed' `
                -Title "$($p.Name): managed carve stopped at the $MaxScanMB MB scan ceiling" `
                -File "$($p.Name) (PID $($p.Id))" -Evidence $cov `
                -Description ('The scan reached its byte ceiling before covering every private region, so ' +
                    'absence of a finding here is NOT evidence that the process holds no fileless assembly. ' +
                    'Re-run with a higher -MaxScanMB to cover the rest.') `
                -Fix 'Re-run with -MaxScanMB raised above the process private working set if complete coverage is required.'
        }
        Write-Verbose "Managed carve on $($p.Name) (PID $($p.Id)): $cov"
    }
}
