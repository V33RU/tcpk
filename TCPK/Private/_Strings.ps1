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

# Count occurrences of a literal substring across both views.
function Get-TcpkSubstringCount {
    [CmdletBinding()] param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Needle
    )
    $t = Read-TcpkAllText -Path $Path
    if (-not $t) { return 0 }
    return ([regex]::Matches($t, [regex]::Escape($Needle))).Count
}
