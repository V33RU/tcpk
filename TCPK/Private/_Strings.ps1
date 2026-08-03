# String-extraction helpers.
# .NET assemblies embed strings as UTF-8 (in metadata) and as wide-char
# literals (UTF-16LE in #US heap). We always read both views so we don't
# miss things.

# Per-audit cache of decoded string-views. Many static checks read the SAME
# first-party DLLs and re-decode UTF-8 + UTF-16 each time; caching the decoded
# views eliminates that redundant work (the dominant cost of a full audit).
# Bounded by a byte budget so memory stays in check; cleared at audit start.
$script:TcpkViewCache       = @{}
$script:TcpkViewCacheBytes  = 0
$script:TcpkViewCacheBudget = 220MB

function Clear-TcpkTextCache {
    [CmdletBinding()] param()
    $script:TcpkViewCache      = @{}
    $script:TcpkViewCacheBytes = 0
}

function Read-TcpkStringViews {
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Path)
    if ($script:TcpkViewCache.ContainsKey($Path)) { return $script:TcpkViewCache[$Path] }
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    # Open with FileShare.ReadWrite|Delete so we can read files a RUNNING target holds open
    # (Chromium cache block files, logs, SQLite WAL/journal, ...). The default
    # File.ReadAllBytes uses FileShare.Read, which a process that has the file open for WRITE
    # denies -- so live artifacts were silently skipped and their secrets never scanned. This
    # is strictly read-only on our side.
    try {
        $fs = [System.IO.FileStream]::new($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read,
              ([System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete))
        try {
            $ms = New-Object System.IO.MemoryStream
            $fs.CopyTo($ms)
            $bytes = $ms.ToArray()
            $ms.Dispose()
        } finally { $fs.Dispose() }
    } catch {
        return $null
    }
    # UTF-16LE strings (the #US literal heap) are only decoded correctly when the
    # decode starts on the same byte parity as the string. Decoding from offset 0
    # misses every wide string that happens to begin at an ODD file offset (~half
    # of them). We decode BOTH alignments so literal-string scans (secrets,
    # endpoints, callsites) are not silently alignment-dependent.
    $utf16Odd = if ($bytes.Length -gt 1) { [Text.Encoding]::Unicode.GetString($bytes, 1, $bytes.Length - 1) } else { '' }
    $obj = [pscustomobject]@{
        Path       = $Path
        Utf8       = [Text.Encoding]::UTF8.GetString($bytes)
        Utf16Le    = [Text.Encoding]::Unicode.GetString($bytes)
        Utf16LeOdd = $utf16Odd
        Length     = $bytes.Length
    }
    # cache while within the byte budget (decoded views cost ~5x file size)
    $cost = [int64]$bytes.Length * 5
    if (($script:TcpkViewCacheBytes + $cost) -lt $script:TcpkViewCacheBudget) {
        $script:TcpkViewCache[$Path] = $obj
        $script:TcpkViewCacheBytes  += $cost
    }
    return $obj
}

# Returns the combined UTF-8 + UTF-16LE view as a single string.
# Use when you only need to test "is this substring present somewhere".
function Read-TcpkAllText {
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Path)
    $v = Read-TcpkStringViews -Path $Path
    if (-not $v) { return '' }
    "$($v.Utf8)`n$($v.Utf16Le)`n$($v.Utf16LeOdd)"
}

# Count occurrences of a literal substring across both views. Streams, so a huge file
# is counted rather than skipped and memory stays bounded.
function Get-TcpkSubstringCount {
    [CmdletBinding()] param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Needle
    )
    if (-not $Needle) { return 0 }
    $state = @{ Stop = $false; Count = 0 }
    Invoke-TcpkOnFileText -Path $Path -State $state -OnText {
        param($Text, $Src, $St)
        if (-not $Text) { return }
        $i = 0
        while ($true) {
            $i = $Text.IndexOf($Needle, $i, [System.StringComparison]::Ordinal)
            if ($i -lt 0) { break }
            $St.Count++
            $i += $Needle.Length
        }
    }
    return $state.Count
}

# ---------------------------------------------------------------------------
# STREAMING TEXT ACCESS -- no file is ever skipped for being large.
#
# WHY THIS EXISTS. Two opposite bugs used to live side by side:
#   * Eight checks SKIPPED a file above a size threshold, silently. A skip nobody
#     declares is indistinguishable from a clean result, which is the failure this
#     project treats as a bug rather than a limitation.
#   * Eleven other checks had NO cap and called Read-TcpkAllText on anything. For a
#     200 MB file that is ~200 MB of bytes plus a ~400 MB UTF-8 string plus two
#     ~200 MB UTF-16 strings, and Read-TcpkAllText then CONCATENATES all three into
#     one more ~800 MB string. Roughly 2 GB per call, all on the Large Object Heap,
#     which .NET Framework does not compact. Worse, the view cache admits an entry
#     only while bytes*5 stays under a 220 MB budget, so nothing at or above ~44 MB
#     is ever cached and every caller re-does the whole decode. That is how a scan
#     ends up wedged for hours.
#
# The fix for both is the same, and it is NOT a size cap: stream. A small file is
# decoded whole (and cached, as before). A large file is walked in bounded
# OVERLAPPING chunks, so memory is flat regardless of file size and nothing is
# skipped. The overlap is what keeps a match that straddles a chunk boundary
# findable; Test-TcpkSecrets has used exactly this shape on >64 MB files already.
#
# THRESHOLD. 40 MB, deliberately just under the ~44 MB point where the view cache
# stops admitting entries. Above that a whole-file load would be re-done by every
# caller, so streaming is both safer AND faster there.
# ---------------------------------------------------------------------------
$script:TcpkWholeFileMaxBytes = 40MB
$script:TcpkChunkBytes        = 16MB
$script:TcpkChunkOverlap      = 64KB

# Feed a file's decoded text to $OnText in bounded pieces.
#
# $OnText receives (Text, Src, State):
#   Text  a decoded view, or a chunk of one
#   Src   'utf8' | 'utf16le' | 'utf16le-odd', suffixed '#N' for chunk N of a large file
#   State the caller's own hashtable; set $State.Stop = $true to stop early
#
# Every file is processed. There is no size at which this returns without reading.
# -Utf8Only: skip the two UTF-16 views. Correct for a source/config/JS file, where a
# UTF-16 decode of UTF-8 bytes is meaningless noise and costs 2x the work. Leave it OFF
# for PE files, whose wide string literals only appear in the UTF-16 views.
function Invoke-TcpkOnFileText {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][scriptblock]$OnText,
        [hashtable]$State,
        [switch]$Utf8Only
    )
    if ($null -eq $State) { $State = @{ Stop = $false } }
    if (-not $State.ContainsKey('Stop')) { $State['Stop'] = $false }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return }

    $len = 0
    try { $len = (Get-Item -LiteralPath $Path -ErrorAction Stop).Length } catch { return }

    # Small enough to decode whole: reuse the existing cached-view path unchanged.
    if ($len -le $script:TcpkWholeFileMaxBytes) {
        $v = Read-TcpkStringViews -Path $Path
        if (-not $v) { return }
        $views = if ($Utf8Only) { @(, @($v.Utf8, 'utf8')) }
                 else { @(@($v.Utf8, 'utf8'), @($v.Utf16Le, 'utf16le'), @($v.Utf16LeOdd, 'utf16le-odd')) }
        foreach ($pair in $views) {
            if ($State.Stop) { return }
            & $OnText $pair[0] $pair[1] $State
        }
        return
    }

    # Large file: overlapping chunk walk. FileShare.ReadWrite|Delete for the same
    # reason Read-TcpkStringViews uses it -- a running target holds its own files open.
    $fsr = $null
    try {
        $fsr = [System.IO.FileStream]::new($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read,
               ([System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete))
    } catch { return }
    try {
        $chunk   = [int]$script:TcpkChunkBytes
        $overlap = [int]$script:TcpkChunkOverlap
        $buf     = New-Object byte[] ($chunk + $overlap)
        $carry   = 0
        $chunkNo = 0
        while (-not $State.Stop) {
            # Byte count and chunk ordinal are separate counters on purpose: the loop
            # terminates on the former, the Src label reports the latter.
            $read  = $fsr.Read($buf, $carry, $chunk)
            $total = $carry + $read
            if ($total -le 0) { break }
            $chunkNo++
            $tag = "#$chunkNo"
            & $OnText ([System.Text.Encoding]::UTF8.GetString($buf, 0, $total))    "utf8$tag"        $State
            if (-not $Utf8Only) {
                if (-not $State.Stop) { & $OnText ([System.Text.Encoding]::Unicode.GetString($buf, 0, $total)) "utf16le$tag" $State }
                if (-not $State.Stop -and $total -gt 1) {
                    & $OnText ([System.Text.Encoding]::Unicode.GetString($buf, 1, $total - 1)) "utf16le-odd$tag" $State
                }
            }
            if ($read -le 0) { break }
            # Carry the tail forward so a match straddling the boundary is still found.
            $keep  = [Math]::Min($overlap, $total)
            [System.Array]::Copy($buf, $total - $keep, $buf, 0, $keep)
            $carry = $keep
        }
    } catch {
    } finally { $fsr.Dispose() }
}

# Does the file contain any of these literals? Streams and short-circuits on the
# first hit, so a 2 GB file costs one chunk when the needle is near the front.
function Test-TcpkFileContainsAny {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string[]]$Needles,
        [switch]$CaseSensitive
    )
    $nd = @($Needles | Where-Object { $_ })
    if (-not $nd.Count) { return $false }
    $cmp = if ($CaseSensitive) { [System.StringComparison]::Ordinal } else { [System.StringComparison]::OrdinalIgnoreCase }
    $state = @{ Stop = $false; Hit = $false; Cmp = $cmp; Nd = $nd }
    Invoke-TcpkOnFileText -Path $Path -State $state -OnText {
        param($Text, $Src, $St)
        if (-not $Text) { return }
        foreach ($needle in $St.Nd) {
            if ($Text.IndexOf($needle, $St.Cmp) -ge 0) { $St.Hit = $true; $St.Stop = $true; return }
        }
    }
    return [bool]$state.Hit
}

# Regex matches across a file's text views, streamed. Returns the matched strings,
# deduplicated -- the chunk overlap deliberately re-presents boundary bytes, so the
# same match can be seen twice and the dedup is required for an honest count.
#
# $MaxMatches bounds the RESULT SET, never the reading: the whole file is always
# walked. Callers that need to know whether the set was truncated should compare
# the returned count against $MaxMatches.
function Select-TcpkFileMatch {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Pattern,
        [int]$MaxMatches = 200,
        [switch]$CaseSensitive
    )
    $opts = [System.Text.RegularExpressions.RegexOptions]::None
    if (-not $CaseSensitive) { $opts = [System.Text.RegularExpressions.RegexOptions]::IgnoreCase }
    $rx = $null
    try { $rx = New-Object System.Text.RegularExpressions.Regex($Pattern, $opts) } catch { return @() }

    $state = @{ Stop = $false; Rx = $rx; Seen = @{}; Out = (New-Object 'System.Collections.Generic.List[string]'); Max = $MaxMatches }
    Invoke-TcpkOnFileText -Path $Path -State $state -OnText {
        param($Text, $Src, $St)
        if (-not $Text) { return }
        foreach ($m in $St.Rx.Matches($Text)) {
            $v = $m.Value
            if ($St.Seen.ContainsKey($v)) { continue }
            $St.Seen[$v] = $true
            $St.Out.Add($v)
            if ($St.Out.Count -ge $St.Max) { $St.Stop = $true; return }
        }
    }
    return @($state.Out.ToArray())
}

# First regex match in a file's text, or '' when there is none. Streams and stops
# at the first hit. Use where the old code did:  if ($t -match $rx) { $matches[0] }
function Get-TcpkFirstFileMatch {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Pattern,
        [switch]$CaseSensitive
    )
    $r = @(Select-TcpkFileMatch -Path $Path -Pattern $Pattern -MaxMatches 1 -CaseSensitive:$CaseSensitive)
    if ($r.Count) { return $r[0] }
    return ''
}
