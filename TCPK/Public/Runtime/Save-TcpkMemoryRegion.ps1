function Save-TcpkMemoryRegion {
<#
.SYNOPSIS
    E24. Save the raw bytes of one live memory region to the tool work directory.

.DESCRIPTION
    WHY THIS EXISTS. Test-TcpkMemoryRegions and Test-TcpkThreadStart report the
    SHAPE of an anomaly: a writable-executable region, executable memory not backed
    by an image, a thread whose start address is outside every module. They report
    an address and a size and stop there, because both open the process with query
    rights only and never read region contents. That leaves a finding a vendor
    cannot triage: nobody can say what the region actually held.

    This reads the bytes of one region and writes them to the work directory so the
    region becomes an artifact: something to hash, to run strings over, to load into
    Ghidra for a native region, or to hand to Invoke-TcpkManagedCarve when it may
    hold a managed assembly.

    Read-only. The process is opened PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
    (what ReadProcessMemory requires) and nothing is written back to the target.

    The output file lands under the TCPK work directory via New-TcpkWorkPath, never
    %TEMP% and never the current directory.

.PARAMETER ProcessName
    Process name (no .exe).

.PARAMETER ProcessId
    Specific PID, instead of resolving by name.

.PARAMETER BaseAddress
    Region base address. Accepts the hex form the findings print (0x7FF6A2C10000)
    or a decimal string.

.PARAMETER MaxBytes
    Ceiling on bytes saved (default 16 MB). A region larger than this is saved
    truncated and the result says so, rather than being skipped.

.OUTPUTS
    [pscustomobject] with Path, ProcessId, BaseAddress, Size, Saved, Truncated,
    Protect, Type and Entropy. Returns nothing if the region cannot be read.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ParameterSetName = 'ByName')][string]$ProcessName,
        [Parameter(Mandatory, ParameterSetName = 'ById')][int]$ProcessId,
        [Parameter(Mandatory)][string]$BaseAddress,
        [int]$MaxBytes = 16777216
    )

    if (-not (Assert-TcpkWindows 'Save-TcpkMemoryRegion')) { return }
    if (-not ('Tcpk.MemRead' -as [type])) {
        Write-Verbose 'Tcpk.MemRead unavailable; cannot read process memory.'
        return
    }

    # Parse the address. Hex is the form every TCPK finding prints, so accept it first.
    # Never -match a literal here: a stray backslash in operator input would throw on
    # the \P / \W classes. Prefix tests are string operations only.
    $addr = [int64]0
    $raw = "$BaseAddress".Trim()
    $parsed = $false
    try {
        if ($raw.StartsWith('0x') -or $raw.StartsWith('0X')) {
            $addr = [Convert]::ToInt64($raw.Substring(2), 16); $parsed = $true
        } else {
            $addr = [Convert]::ToInt64($raw, 10); $parsed = $true
        }
    } catch { $parsed = $false }
    if (-not $parsed -or $addr -le 0) {
        Write-Verbose "Unparsable BaseAddress: $BaseAddress"
        return
    }

    $procs = @()
    if ($PSCmdlet.ParameterSetName -eq 'ById') {
        $procs = @(Get-Process -Id $ProcessId -ErrorAction SilentlyContinue)
    } else {
        $procs = @(Get-Process -Name ($ProcessName -replace '\.exe$', '') -ErrorAction SilentlyContinue)
    }
    if (-not $procs.Count) { Write-Verbose 'No matching live process.'; return }
    $p = $procs[0]

    # Region metadata (size / protect / type) comes from the query-only primitive;
    # the bytes come from the read primitive. Two handles, each with the minimum
    # rights its own call needs.
    $size = [int64]0; $prot = [int64]0; $type = [int64]0
    $qh = [IntPtr]::Zero
    try { $qh = [Tcpk.MemRegions]::Open($p.Id) } catch { }
    if ($qh -ne [IntPtr]::Zero) {
        try {
            $flat = [Tcpk.MemRegions]::Enumerate($qh)
            for ($i = 0; ($i + 3) -lt $flat.Count; $i += 4) {
                $b = [int64]$flat[$i]
                $s = [int64]$flat[$i + 1]
                if ($addr -ge $b -and $addr -lt ($b + $s)) {
                    # Report the region from the requested address to its end, so an
                    # address taken from the middle of a region still yields the tail.
                    $size = ($b + $s) - $addr
                    $prot = [int64]$flat[$i + 2]
                    $type = [int64]$flat[$i + 3]
                    break
                }
            }
        } catch { }
        try { [void][Tcpk.MemRead]::CloseHandle($qh) } catch { }
    }
    if ($size -le 0) {
        Write-Verbose ("No committed region contains 0x{0:X} in PID {1}." -f $addr, $p.Id)
        return
    }

    $truncated = $false
    $want = $size
    if ($want -gt $MaxBytes) { $want = [int64]$MaxBytes; $truncated = $true }

    $h = [IntPtr]::Zero
    try { $h = [Tcpk.MemRead]::Open($p.Id, $false) } catch { }
    if ($h -eq [IntPtr]::Zero) {
        Write-Verbose "OpenProcess denied for PID $($p.Id). Re-run elevated, or the process is protected."
        return
    }

    $outPath = New-TcpkWorkPath -Kind 'dump' -Prefix ("region-$($p.Id)-{0:X}" -f $addr) -Extension 'bin'
    $written = [int64]0
    $chunk = 1048576
    $fs = $null
    # Entropy is measured over the first chunk only: enough to characterise the
    # region without holding the whole thing in memory a second time.
    $firstChunk = $null
    try {
        $fs = [System.IO.File]::Create($outPath)
        while ($written -lt $want) {
            $take = [int][Math]::Min([int64]$chunk, ($want - $written))
            $buf = $null
            try { $buf = [Tcpk.MemRead]::ReadBytes($h, ($addr + $written), $take) } catch { $buf = $null }
            if ($null -eq $buf -or $buf.Length -eq 0) { break }
            $fs.Write($buf, 0, $buf.Length)
            if ($null -eq $firstChunk) { $firstChunk = $buf }
            $written += $buf.Length
            # A short read means the region ended early or turned unreadable.
            if ($buf.Length -lt $take) { break }
        }
    } catch {
        Write-Verbose "Read/write failed: $($_.Exception.Message)"
    } finally {
        if ($fs) { try { $fs.Dispose() } catch { } }
        try { [void][Tcpk.MemRead]::CloseHandle($h) } catch { }
    }

    if ($written -le 0) {
        try { Remove-Item -LiteralPath $outPath -Force -ErrorAction SilentlyContinue } catch { }
        Write-Verbose ("Region 0x{0:X} in PID {1} could not be read." -f $addr, $p.Id)
        return
    }
    if ($written -lt $want) { $truncated = $true }

    $ent = 0.0
    if ($firstChunk) { $ent = Get-TcpkByteEntropy -Bytes $firstChunk }

    return [pscustomobject]@{
        Path        = $outPath
        ProcessId   = $p.Id
        ProcessName = $p.Name
        BaseAddress = ("0x{0:X}" -f $addr)
        Size        = $size
        Saved       = $written
        Truncated   = $truncated
        Protect     = ("0x{0:X}" -f $prot)
        Type        = ("0x{0:X}" -f $type)
        Entropy     = $ent
    }
}
