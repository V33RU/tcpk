# Byte search over a whole file, streamed, with the encodings a Windows binary actually uses.
#
# THE DEFECT THIS FIXES. The Hex tab searched 'ascii' or 'hex' only. Windows stores string
# literals as UTF-16LE, so searching a PE for a string it demonstrably contains returned
# nothing. That is worse than a missing feature: the operator concludes the string is absent.
# TCPK's own string extractor has always read utf8, utf16le and utf16le-odd views, so the
# search was the odd one out.
#
# Lives in the module rather than in Start-TCPKGui.ps1 so it can be tested.

function Convert-TcpkSearchNeedle {
<#
.SYNOPSIS
    Turn a query string into the byte pattern(s) to look for.

.DESCRIPTION
    Private helper for Find-TcpkByteMatches. Returns a list of @{ Bytes; Label }, because
    one query can legitimately expand to more than one pattern: 'auto' looks for the same
    text as both ASCII and UTF-16LE, which is what an operator searching a Windows binary
    almost always means.

    Throws on a malformed hex query rather than returning empty, so "bad input" and "no
    match" stay distinguishable at the call site.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Query,
        [Parameter(Mandatory)][ValidateSet('ascii', 'hex', 'utf16le', 'utf8', 'auto')][string]$Kind
    )

    $out = New-Object 'System.Collections.Generic.List[object]'
    if ([string]::IsNullOrEmpty($Query)) { return , $out.ToArray() }

    switch ($Kind) {
        'hex' {
            $hx = ($Query -replace '[^0-9a-fA-F]', '')
            if ($hx.Length -lt 2 -or ($hx.Length % 2)) {
                throw "Hex search needs an even number of hex digits (got $($hx.Length))."
            }
            $b = New-Object 'byte[]' ($hx.Length / 2)
            for ($i = 0; $i -lt $b.Length; $i++) { $b[$i] = [Convert]::ToByte($hx.Substring($i * 2, 2), 16) }
            $out.Add(@{ Bytes = $b; Label = 'hex' })
        }
        'ascii'   { $out.Add(@{ Bytes = [Text.Encoding]::ASCII.GetBytes($Query);   Label = 'ascii' }) }
        'utf8'    { $out.Add(@{ Bytes = [Text.Encoding]::UTF8.GetBytes($Query);    Label = 'utf8' }) }
        'utf16le' { $out.Add(@{ Bytes = [Text.Encoding]::Unicode.GetBytes($Query); Label = 'utf16le' }) }
        'auto' {
            # Both, deduped: for pure ASCII input the UTF-8 and ASCII byte patterns are
            # identical, and reporting the same offset twice under two labels is noise.
            $a = [Text.Encoding]::UTF8.GetBytes($Query)
            $w = [Text.Encoding]::Unicode.GetBytes($Query)
            $out.Add(@{ Bytes = $a; Label = 'utf8' })
            $out.Add(@{ Bytes = $w; Label = 'utf16le' })
        }
    }
    return , $out.ToArray()
}

function Find-TcpkByteMatches {
<#
.SYNOPSIS
    Every offset in a file matching a query, by byte pattern or regex.

.DESCRIPTION
    Streams the file in overlapping chunks so there is no size limit and no
    ReadAllBytes, and returns ALL matches rather than only the next one, so a caller can
    populate a results list instead of forcing the operator to press Find repeatedly.

    KINDS
      ascii    the query as ASCII bytes
      utf8     the query as UTF-8 bytes
      utf16le  the query as UTF-16LE bytes, which is how Windows stores string literals
      auto     utf8 AND utf16le, deduped. The sensible default for a Windows binary
      hex      a literal byte pattern, e.g. '4D 5A' or '4d5a'
      regex    a .NET regex over a latin1 view of the bytes

    ON REGEX. The bytes are mapped to chars 1:1 (latin1) rather than decoded as text, so a
    character index IS a byte offset and no encoding can shift the mapping. That makes '.'
    mean "any byte" and keeps reported offsets exact. It also means a regex will not match
    UTF-16 text, where every other byte is 0x00; search utf16le for that instead.

    Regex runs per chunk with an overlap, so a match longer than the overlap can be missed
    at a boundary. The overlap is 64 KB, which is far beyond any realistic pattern, and
    -RegexTimeoutMs bounds catastrophic backtracking the same way the secrets scanner does.

.PARAMETER MaxMatches
    Stop after this many. The result carries Truncated so a caller can say the list is
    partial rather than presenting it as complete.

.OUTPUTS
    [hashtable] @{ Matches; Truncated; Scanned }
    Each match: @{ Offset; Length; Kind }
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Query,
        [ValidateSet('ascii', 'hex', 'utf16le', 'utf8', 'auto', 'regex')][string]$Kind = 'auto',
        [switch]$CaseInsensitive,
        [int64]$From = 0,
        [int]$MaxMatches = 5000,
        [int]$RegexTimeoutMs = 5000
    )

    $empty = @{ Matches = @(); Truncated = $false; Scanned = [int64]0 }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $empty }
    if ([string]::IsNullOrEmpty($Query)) { return $empty }

    $flen = [int64](Get-Item -LiteralPath $Path).Length
    if ($flen -le 0) { return $empty }
    if ($From -lt 0) { $From = 0 }

    $matches = New-Object 'System.Collections.Generic.List[object]'
    $truncated = $false
    $chunk = 8MB

    if ($Kind -eq 'regex') {
        $opts = [Text.RegularExpressions.RegexOptions]::Singleline
        if ($CaseInsensitive) { $opts = $opts -bor [Text.RegularExpressions.RegexOptions]::IgnoreCase }
        # 3-arg ctor: the match timeout. Without it one pathological pattern hangs the GUI,
        # which is the same failure the secrets scanner was given a timeout for.
        $rx = [regex]::new($Query, $opts, [TimeSpan]::FromMilliseconds($RegexTimeoutMs))
        $ov = 65536
    } else {
        $needles = Convert-TcpkSearchNeedle -Query $Query -Kind $Kind
        $needles = @($needles | Where-Object { $_.Bytes.Length -gt 0 })
        if (-not $needles.Count) { return $empty }
        $maxN = 0
        foreach ($n in $needles) { if ($n.Bytes.Length -gt $maxN) { $maxN = $n.Bytes.Length } }
        $ov = [Math]::Max(0, $maxN - 1)
    }

    $fs = $null
    try {
        $fs = [IO.FileStream]::new($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read,
              ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
        $buf = New-Object 'byte[]' ($chunk + $ov)
        $pos = $From
        $seen = @{}

        while ($pos -lt $flen) {
            $fs.Position = $pos
            $want = [int][Math]::Min($buf.Length, $flen - $pos)
            $got = 0
            while ($got -lt $want) {
                $r = $fs.Read($buf, $got, $want - $got)
                if ($r -le 0) { break }
                $got += $r
            }
            if ($got -le 0) { break }

            if ($Kind -eq 'regex') {
                # latin1: byte value == char value, so char index == byte offset.
                $text = [Text.Encoding]::GetEncoding(28591).GetString($buf, 0, $got)
                foreach ($m in $rx.Matches($text)) {
                    $abs = $pos + $m.Index
                    if ($seen.ContainsKey($abs)) { continue }
                    $seen[$abs] = $true
                    $matches.Add(@{ Offset = $abs; Length = $m.Length; Kind = 'regex' })
                    if ($matches.Count -ge $MaxMatches) { $truncated = $true; break }
                }
            } else {
                foreach ($n in $needles) {
                    $nb = $n.Bytes; $nl = $nb.Length
                    $lim = $got - $nl
                    for ($i = 0; $i -le $lim; $i++) {
                        $ok = $true
                        for ($j = 0; $j -lt $nl; $j++) {
                            $a = $buf[$i + $j]; $b2 = $nb[$j]
                            if ($CaseInsensitive) {
                                if ($a -ge 65 -and $a -le 90) { $a = $a + 32 }
                                if ($b2 -ge 65 -and $b2 -le 90) { $b2 = $b2 + 32 }
                            }
                            if ($a -ne $b2) { $ok = $false; break }
                        }
                        if (-not $ok) { continue }
                        $abs = $pos + $i
                        if ($seen.ContainsKey($abs)) { continue }
                        $seen[$abs] = $true
                        $matches.Add(@{ Offset = $abs; Length = $nl; Kind = $n.Label })
                        if ($matches.Count -ge $MaxMatches) { $truncated = $true; break }
                    }
                    if ($truncated) { break }
                }
            }

            if ($truncated) { break }
            if (($pos + $got) -ge $flen) { break }
            $pos += ($got - $ov)
        }
    } finally { if ($fs) { $fs.Dispose() } }

    $sorted = @($matches | Sort-Object { [int64]$_.Offset })
    return @{ Matches = $sorted; Truncated = $truncated; Scanned = $flen }
}
