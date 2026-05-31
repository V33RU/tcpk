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
    try {
        $bytes = [IO.File]::ReadAllBytes($Path)
    } catch {
        return $null
    }
    $obj = [pscustomobject]@{
        Path     = $Path
        Utf8     = [Text.Encoding]::UTF8.GetString($bytes)
        Utf16Le  = [Text.Encoding]::Unicode.GetString($bytes)
        Length   = $bytes.Length
    }
    # cache while within the byte budget (decoded views cost ~4x file size)
    $cost = [int64]$bytes.Length * 4
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
    "$($v.Utf8)`n$($v.Utf16Le)"
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
