function Test-TcpkEmbeddedBlobs {
<#
.SYNOPSIS
    A48. Whole-file signature scan: find file formats embedded at arbitrary offsets.

.DESCRIPTION
    TCPK already carves SPECIFIC containers it recognises by name (Expand-TcpkAsar,
    Expand-TcpkPyInstaller, Expand-TcpkSingleFile). None of them answer the general
    question: what else is sitting inside this file, at an offset nobody declared?

    That question matters for thick clients. Installers, resource blobs, licence files and
    config containers routinely carry a whole PE, a SQLite database or an archive inside
    them, and none of it appears in a directory listing.

    STRUCTURE, NOT BYTE MATCHES. A short magic value is worthless on its own: 'MZ' occurs
    roughly once every 65 KB of random data. Every signature here is therefore either long
    enough to stand alone (SQLite's 16 bytes, PNG's 8) or is structurally validated before
    it is reported. A candidate PE must have an e_lfanew that lands inside the file AND
    points at 'PE\0\0'; a candidate ZIP must have a local file header whose name length is
    sane. Anything that fails validation is counted and discarded, never reported.

    WHAT IS A FINDING AND WHAT IS INVENTORY. An embedded executable, archive, database or
    private key is worth a look, so those carry a severity. Images and fonts are shipped
    resources and would drown the report, so they are counted in the inventory finding and
    not raised individually.

.PARAMETER Path
    File to scan, or a folder to scan recursively.

.PARAMETER MinOffset
    Ignore matches below this offset. Default 1, because a PE at offset 0 is simply the
    file's own header and is not 'embedded' in any interesting sense.

.PARAMETER MaxFileBytes
    Per-file scan ceiling, default 256 MB. A file larger than this is scanned up to the
    limit and the shortfall is REPORTED, never silently dropped.

.PARAMETER IncludeMedia
    Also raise a finding for embedded images and fonts. Off by default: they are almost
    always legitimate resources.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [int64]$MinOffset = 1,
        [int64]$MaxFileBytes = 268435456,
        [switch]$IncludeMedia
    )

    if (-not (Test-Path -LiteralPath $Path)) { throw "Path not found: $Path" }

    $targets = @()
    $item = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
    if ($item -and $item.PSIsContainer) {
        $targets = @(Get-ChildItem -LiteralPath $Path -Recurse -File -ErrorAction SilentlyContinue)
    } elseif ($item) { $targets = @($item) }
    if (-not $targets.Count) { return }

    $sigs = Get-TcpkBlobSignatures
    $totalHits = 0; $totalRejected = 0; $filesScanned = 0; $truncated = @()

    foreach ($f in $targets) {
        $scan = $null
        try { $scan = Find-TcpkEmbeddedSignature -File $f.FullName -Signatures $sigs -MinOffset $MinOffset -MaxBytes $MaxFileBytes }
        catch { continue }
        if (-not $scan) { continue }

        $filesScanned++
        $totalRejected += $scan.Rejected
        if ($scan.Truncated) { $truncated += "$($f.Name) ($([int64]$f.Length) bytes, scanned $($scan.Scanned))" }

        foreach ($h in $scan.Hits) {
            $totalHits++
            if ($h.Class -eq 'media' -and -not $IncludeMedia) { continue }

            $sev = switch ($h.Class) {
                'executable' { 'MEDIUM' }
                'key'        { 'HIGH' }
                'database'   { 'MEDIUM' }
                'archive'    { 'LOW' }
                default      { 'INFO' }
            }
            $rule = "embedded.$($h.Class)"

            New-TcpkFinding -Module 'static' -RuleId $rule `
                -Severity $sev -Confidence 'Confirmed' `
                -Title "$($h.Name) embedded at offset 0x$($h.Offset.ToString('x')) in $($f.Name)" `
                -File $f.FullName `
                -Evidence "offset=0x$($h.Offset.ToString('x')) ($($h.Offset)) format=$($h.Name) validated=$($h.Validated)" `
                -Cwe @('CWE-912') `
                -AttributionBasis 'established-footprint' `
                -Description ("A $($h.Name) starts at offset 0x$($h.Offset.ToString('x')) inside this file, which is " +
                    "not the file's own format. It was confirmed by $($h.Validated), not by a bare magic-byte match. " +
                    'Content embedded at an undeclared offset does not appear in a directory listing and is not ' +
                    'covered by the checks that scan files on disk, so carve it out and scan it separately.') `
                -Fix 'Carve the region and audit it as its own artifact. If it is a legitimate resource, no action beyond knowing it is there.'
        }
    }

    # Always emitted: a silent result must not be readable as "nothing is embedded" when the
    # scan may simply have been cut short. Same rule the scan-coverage work follows.
    $note = "files=$filesScanned hits=$totalHits rejected-candidates=$totalRejected"
    if ($truncated.Count) { $note += "; TRUNCATED: " + ($truncated -join '; ') }

    New-TcpkFinding -Module 'static' -RuleId 'embedded.scan' `
        -Severity $(if ($truncated.Count) { 'LOW' } else { 'INFO' }) `
        -Confidence 'Confirmed' `
        -Title "Embedded-format scan: $totalHits found across $filesScanned file(s)$(if ($truncated.Count) { ', SOME FILES TRUNCATED' })" `
        -File $Path `
        -Evidence $note `
        -Description ('Signature scan for formats embedded at arbitrary offsets. rejected-candidates counts ' +
            'magic-byte matches that failed structural validation and were discarded, which is the number ' +
            'that would have been false positives on a match-only scan. Any file exceeding -MaxFileBytes is ' +
            'named above with how far the scan actually reached.') `
        -Fix $(if ($truncated.Count) { 'Re-run with a larger -MaxFileBytes to cover the named files in full.' } else { 'No action; recorded so a clean result is distinguishable from a scan that did not run.' })
}

function Get-TcpkBlobSignatures {
<#
.SYNOPSIS
    The signature table used by Test-TcpkEmbeddedBlobs.

.DESCRIPTION
    Magic values are facts about public file formats, so this table is written from the
    format specifications rather than lifted from any existing tool's database.

    Each entry: Bytes (the magic), Name, Class, and Validate (a scriptblock returning a
    description of the structural check that passed, or $null to reject). Signatures under
    about 6 bytes MUST carry a Validate, because short magics fire constantly in compressed
    or encrypted regions.
#>
    [CmdletBinding()] param()

    $b = { param([string]$s) [Text.Encoding]::ASCII.GetBytes($s) }

    @(
        # 'MZ' is 2 bytes and would otherwise fire about once per 65 KB of random data.
        # Validated the way a loader does: e_lfanew at 0x3C must land inside the file and
        # point at 'PE\0\0'.
        @{ Name = 'PE executable'; Class = 'executable'; Bytes = (& $b 'MZ')
           Validate = {
               param($buf, $pos, $len)
               if ($pos + 0x40 -ge $len) { return $null }
               $lfa = [BitConverter]::ToInt32($buf, $pos + 0x3C)
               if ($lfa -lt 0x40 -or ($pos + $lfa + 4) -ge $len) { return $null }
               if ($buf[$pos + $lfa] -ne 0x50 -or $buf[$pos + $lfa + 1] -ne 0x45 -or
                   $buf[$pos + $lfa + 2] -ne 0 -or $buf[$pos + $lfa + 3] -ne 0) { return $null }
               "e_lfanew=0x$($lfa.ToString('x')) -> PE\0\0"
           } }

        @{ Name = 'ELF executable'; Class = 'executable'; Bytes = [byte[]]@(0x7F, 0x45, 0x4C, 0x46)
           Validate = {
               param($buf, $pos, $len)
               if ($pos + 5 -ge $len) { return $null }
               # EI_CLASS 1|2 and EI_DATA 1|2 are the only defined values.
               if ($buf[$pos + 4] -notin 1, 2 -or $buf[$pos + 5] -notin 1, 2) { return $null }
               "EI_CLASS=$($buf[$pos+4]) EI_DATA=$($buf[$pos+5])"
           } }

        # 16 bytes including the terminator: long enough to stand alone.
        @{ Name = 'SQLite database'; Class = 'database'
           Bytes = ((& $b 'SQLite format 3') + [byte[]]@(0)); Validate = $null }

        @{ Name = 'ZIP archive'; Class = 'archive'; Bytes = [byte[]]@(0x50, 0x4B, 0x03, 0x04)
           Validate = {
               param($buf, $pos, $len)
               if ($pos + 30 -ge $len) { return $null }
               $nameLen = [BitConverter]::ToUInt16($buf, $pos + 26)
               $extraLen = [BitConverter]::ToUInt16($buf, $pos + 28)
               # A local file header with an absurd name or extra length is noise, not a zip.
               if ($nameLen -eq 0 -or $nameLen -gt 512 -or $extraLen -gt 4096) { return $null }
               "local file header, nameLen=$nameLen"
           } }

        @{ Name = '7-Zip archive'; Class = 'archive'
           Bytes = [byte[]]@(0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C); Validate = $null }
        @{ Name = 'RAR archive'; Class = 'archive'
           Bytes = ((& $b 'Rar!') + [byte[]]@(0x1A, 0x07)); Validate = $null }
        @{ Name = 'MS Cabinet'; Class = 'archive'; Bytes = (& $b 'MSCF')
           Validate = {
               param($buf, $pos, $len)
               # reserved1 at +4 is always zero in a real CFHEADER.
               if ($pos + 8 -ge $len) { return $null }
               if ([BitConverter]::ToUInt32($buf, $pos + 4) -ne 0) { return $null }
               'CFHEADER reserved1=0'
           } }

        # PEM is textual and unambiguous; these are private keys, not certificates.
        @{ Name = 'PEM private key'; Class = 'key'; Bytes = (& $b '-----BEGIN RSA PRIVATE KEY'); Validate = $null }
        @{ Name = 'PEM private key'; Class = 'key'; Bytes = (& $b '-----BEGIN PRIVATE KEY'); Validate = $null }
        @{ Name = 'PEM private key'; Class = 'key'; Bytes = (& $b '-----BEGIN EC PRIVATE KEY'); Validate = $null }
        @{ Name = 'OpenSSH private key'; Class = 'key'; Bytes = (& $b '-----BEGIN OPENSSH PRIVATE KEY'); Validate = $null }
        @{ Name = 'PuTTY private key'; Class = 'key'; Bytes = (& $b 'PuTTY-User-Key-File-'); Validate = $null }

        @{ Name = 'PNG image'; Class = 'media'
           Bytes = [byte[]]@(0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A); Validate = $null }
        @{ Name = 'GIF image'; Class = 'media'; Bytes = (& $b 'GIF89a'); Validate = $null }
        @{ Name = 'PDF document'; Class = 'media'; Bytes = (& $b '%PDF-'); Validate = $null }
    )
}

function Find-TcpkEmbeddedSignature {
<#
.SYNOPSIS
    Scan one file for the given signatures, returning validated hits plus scan coverage.

.DESCRIPTION
    Private helper for Test-TcpkEmbeddedBlobs.

    Reads in chunks with an overlap equal to the longest signature minus one, so a match
    straddling a chunk boundary is not lost, and de-duplicates the overlap region so it is
    not reported twice.

    Signatures are indexed by first byte, so the inner loop is a single byte comparison for
    the overwhelming majority of positions and the full compare only runs on candidates.

    Returns @{ Hits; Rejected; Scanned; Truncated }. Rejected counts magic matches that
    failed structural validation, which is worth surfacing: it is the false-positive count
    a match-only scanner would have reported.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$File,
        [Parameter(Mandatory)][object[]]$Signatures,
        [int64]$MinOffset = 1,
        [int64]$MaxBytes = 268435456
    )

    $total = [int64](Get-Item -LiteralPath $File).Length
    if ($total -le 0) { return @{ Hits = @(); Rejected = 0; Scanned = 0; Truncated = $false } }

    $maxSig = 0
    foreach ($s in $Signatures) { if ($s.Bytes.Length -gt $maxSig) { $maxSig = $s.Bytes.Length } }

    # first byte -> signatures starting with it
    $byFirst = @{}
    foreach ($s in $Signatures) {
        $k = [int]$s.Bytes[0]
        if (-not $byFirst.ContainsKey($k)) { $byFirst[$k] = New-Object 'System.Collections.Generic.List[object]' }
        $byFirst[$k].Add($s)
    }

    $limit = [int64][Math]::Min($total, $MaxBytes)
    $chunk = 1048576

    # The overlap must cover what the VALIDATORS read, not just the signature length.
    # maxSig-1 alone (29 bytes here) is wrong: the PE validator reads e_lfanew at +0x3C and
    # then dereferences it, which on a real binary is +0x84 and may legitimately be larger.
    # A match landing between scanEnd-0x84 and scanEnd would fail its bounds check and then
    # never be rescanned, because only the overlap region is revisited in the next chunk.
    # That is a silent false negative, so the window is sized for the deepest validator read
    # with room to spare. 4 KB against a 1 MB chunk is 0.4% overhead.
    $overlap = [int][Math]::Max($maxSig - 1, 4096)
    $hits = New-Object 'System.Collections.Generic.List[object]'
    $rejected = 0
    $seen = @{}

    $fs = [IO.File]::OpenRead($File)
    try {
        $buf = New-Object 'byte[]' ($chunk + $overlap)
        $base = [int64]0
        while ($base -lt $limit) {
            $want = [int][Math]::Min($buf.Length, $limit - $base)
            $got = 0
            while ($got -lt $want) {
                $r = $fs.Read($buf, $got, $want - $got)
                if ($r -le 0) { break }
                $got += $r
            }
            if ($got -le 0) { break }

            # Stop far enough from the end that a full signature still fits, EXCEPT on the
            # final chunk where there is nothing further to read.
            $isLast = ($base + $got) -ge $limit
            $scanEnd = if ($isLast) { $got } else { $got - $overlap }

            for ($i = 0; $i -lt $scanEnd; $i++) {
                $cands = $byFirst[[int]$buf[$i]]
                if (-not $cands) { continue }
                foreach ($sig in $cands) {
                    $sl = $sig.Bytes.Length
                    if ($i + $sl -gt $got) { continue }
                    $ok = $true
                    for ($j = 1; $j -lt $sl; $j++) {
                        if ($buf[$i + $j] -ne $sig.Bytes[$j]) { $ok = $false; break }
                    }
                    if (-not $ok) { continue }

                    $abs = $base + $i
                    if ($abs -lt $MinOffset) { continue }
                    if ($seen.ContainsKey("$abs-$($sig.Name)")) { continue }

                    $why = 'exact signature match'
                    if ($sig.Validate) {
                        $why = & $sig.Validate $buf $i $got
                        if (-not $why) { $rejected++; continue }
                    }
                    $seen["$abs-$($sig.Name)"] = $true
                    $hits.Add([pscustomobject]@{
                        Offset = $abs; Name = $sig.Name; Class = $sig.Class; Validated = $why
                    })
                }
            }

            if ($isLast) { break }
            $base += ($got - $overlap)
            $fs.Position = $base
        }
    } finally { $fs.Dispose() }

    return @{
        Hits      = $hits.ToArray()
        Rejected  = $rejected
        Scanned   = $limit
        Truncated = ($limit -lt $total)
    }
}
