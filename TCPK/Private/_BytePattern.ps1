# Byte patterns: a declarative field table applied to a file, so an opaque blob renders as
# named, decoded fields instead of a hex dump.
#
# This is deliberately NOT a pattern LANGUAGE. There is no control flow, no structs, no
# loops, no scripting. A pattern is a flat list of {Name, Offset, Size, Type, Colour}, which
# is enough to describe a header and cheap enough to be trustworthy. Anything that needs
# conditionals belongs in a dedicated tool, not here.
#
# The Hex tab already colours byte ranges from a map of {Name, RawOff, RawSize, R, G, B}
# (Get-GuiHexRtfEx), which the PE Map produces with a hardcoded producer. A pattern is the
# same shape with a loadable producer and a decoded value per row.
#
# Lives in the module so the decode and validation logic is testable; the GUI stays a
# renderer.

# Field types. Each entry: Size (0 = caller supplies), and a Decode scriptblock taking
# (byte[] $b, int $off, int $len) and returning a display string.
#
# Every decoder is bounds-checked by Resolve-TcpkBytePattern BEFORE it is called, so a
# decoder never has to defend against a short read. That check is the point: a field
# running past the end of the file must be reported as out of range, never rendered from
# whatever bytes happened to be in the buffer.
function Get-TcpkBytePatternTypes {
    [CmdletBinding()] param()
    @{
        'string'   = @{ Fixed = 0; Decode = { param($b, $o, $l)
                        # Trim at the first NUL: C strings in a fixed-width field are
                        # NUL-padded, and showing the padding as dots is noise.
                        $s = [Text.Encoding]::ASCII.GetString($b, $o, $l)
                        $z = $s.IndexOf([char]0); if ($z -ge 0) { $s = $s.Substring(0, $z) }
                        ($s -replace '[^\x20-\x7E]', '.') } }

        'wstring'  = @{ Fixed = 0; Decode = { param($b, $o, $l)
                        $s = [Text.Encoding]::Unicode.GetString($b, $o, ($l - ($l % 2)))
                        $z = $s.IndexOf([char]0); if ($z -ge 0) { $s = $s.Substring(0, $z) }
                        ($s -replace '[^\x20-\x7E]', '.') } }

        'leint'    = @{ Fixed = 0; Decode = { param($b, $o, $l) [string](Convert-TcpkPatternInt $b $o $l $true  $true) } }
        'beint'    = @{ Fixed = 0; Decode = { param($b, $o, $l) [string](Convert-TcpkPatternInt $b $o $l $false $true) } }
        'leuint'   = @{ Fixed = 0; Decode = { param($b, $o, $l) [string](Convert-TcpkPatternInt $b $o $l $true  $false) } }
        'beuint'   = @{ Fixed = 0; Decode = { param($b, $o, $l) [string](Convert-TcpkPatternInt $b $o $l $false $false) } }

        'float'    = @{ Fixed = 4;  Decode = { param($b, $o, $l) [string][BitConverter]::ToSingle($b, $o) } }
        'double'   = @{ Fixed = 8;  Decode = { param($b, $o, $l) [string][BitConverter]::ToDouble($b, $o) } }

        'guid'     = @{ Fixed = 16; Decode = { param($b, $o, $l)
                        $g = New-Object 'byte[]' 16; [Array]::Copy($b, $o, $g, 0, 16)
                        ([guid]::new($g)).ToString('B').ToUpperInvariant() } }

        'filetime' = @{ Fixed = 8;  Decode = { param($b, $o, $l)
                        $t = [BitConverter]::ToInt64($b, $o)
                        if ($t -le 0 -or $t -ge 2650467744000000000) { "(not a FILETIME: $t)" }
                        else { [DateTime]::FromFileTimeUtc($t).ToString('u') } } }

        'bytes'    = @{ Fixed = 0;  Decode = { param($b, $o, $l)
                        $n = [Math]::Min($l, 32)
                        $h = ($b[$o..($o + $n - 1)] | ForEach-Object { $_.ToString('X2') }) -join ' '
                        if ($l -gt $n) { "$h ... (+$($l - $n) bytes)" } else { $h } } }
    }
}

function Convert-TcpkPatternInt {
<#
.SYNOPSIS
    Decode 1/2/4/8 bytes as an integer with the given endianness and signedness.

.DESCRIPTION
    Private helper for the byte-pattern type table. Sizes other than 1, 2, 4 or 8 have no
    BitConverter equivalent and are rejected by the caller's validation rather than being
    guessed at here.
#>
    [CmdletBinding()]
    param([byte[]]$Bytes, [int]$Offset, [int]$Length, [bool]$Little, [bool]$Signed)

    $s = New-Object 'byte[]' $Length
    [Array]::Copy($Bytes, $Offset, $s, 0, $Length)
    # BitConverter is little-endian on every platform TCPK runs on, so a big-endian field is
    # the same bytes reversed. Reversing the COPY leaves the caller's buffer untouched.
    if (-not $Little) { [Array]::Reverse($s) }

    switch ($Length) {
        1 { if ($Signed) { return [sbyte]$s[0] } else { return [int]$s[0] } }
        2 { if ($Signed) { return [BitConverter]::ToInt16($s, 0) } else { return [BitConverter]::ToUInt16($s, 0) } }
        4 { if ($Signed) { return [BitConverter]::ToInt32($s, 0) } else { return [BitConverter]::ToUInt32($s, 0) } }
        8 { if ($Signed) { return [BitConverter]::ToInt64($s, 0) } else { return [BitConverter]::ToUInt64($s, 0) } }
    }
    return 0
}

function Read-TcpkBytePattern {
<#
.SYNOPSIS
    Load and VALIDATE a byte-pattern definition from JSON.

.DESCRIPTION
    A pattern is a JSON array of field objects:

        [ { "name":"MAGIC", "offset":0,  "size":4, "type":"string",  "color":"#3A7BD5" },
          { "name":"SIZE",  "offset":4,  "size":4, "type":"leuint" } ]

    Validation happens here rather than at render time so a malformed pattern fails once,
    loudly, with the offending field named, instead of producing a row of blanks that reads
    like a legitimately empty value.

    Returns @{ Fields; Errors }. A caller with a non-empty Errors list should refuse to
    render rather than show a partial table.

.PARAMETER Json
    The pattern text. Use -Path to read from a file instead.
#>
    [CmdletBinding()]
    param(
        [string]$Json,
        [string]$Path
    )

    if ($Path) {
        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
            return @{ Fields = @(); Errors = @("Pattern file not found: $Path") }
        }
        $Json = Get-Content -LiteralPath $Path -Raw
    }
    if ([string]::IsNullOrWhiteSpace($Json)) { return @{ Fields = @(); Errors = @('Pattern is empty.') } }

    $parsed = $null
    try { $parsed = ConvertFrom-Json $Json }
    catch { return @{ Fields = @(); Errors = @("Pattern is not valid JSON: $($_.Exception.Message)") } }

    $types = Get-TcpkBytePatternTypes
    $fields = New-Object 'System.Collections.Generic.List[object]'
    $errors = New-Object 'System.Collections.Generic.List[string]'
    $i = 0

    foreach ($f in @($parsed)) {
        $i++
        $name = "$($f.name)"; if (-not $name) { $name = "field$i" }
        $type = "$($f.type)".ToLowerInvariant(); if (-not $type) { $type = 'bytes' }

        if (-not $types.ContainsKey($type)) {
            $errors.Add("$name : unknown type '$type'. Known: $(($types.Keys | Sort-Object) -join ', ')")
            continue
        }

        $off = 0L; $size = 0
        if (-not [int64]::TryParse("$($f.offset)", [ref]$off) -or $off -lt 0) {
            $errors.Add("$name : offset must be a non-negative integer (got '$($f.offset)')"); continue
        }

        $fixed = $types[$type].Fixed
        if ($fixed -gt 0) {
            # A fixed-width type ignores any size the pattern supplies, but silently
            # overriding it would hide a mistake, so say so.
            if ($f.PSObject.Properties['size'] -and "$($f.size)" -ne '' -and [int]"$($f.size)" -ne $fixed) {
                $errors.Add("$name : type '$type' is always $fixed bytes, but size=$($f.size) was given")
                continue
            }
            $size = $fixed
        } else {
            if (-not [int]::TryParse("$($f.size)", [ref]$size) -or $size -le 0) {
                $errors.Add("$name : size must be a positive integer for type '$type' (got '$($f.size)')"); continue
            }
        }

        if ($type -in 'leint', 'beint', 'leuint', 'beuint' -and $size -notin 1, 2, 4, 8) {
            $errors.Add("$name : integer size must be 1, 2, 4 or 8 (got $size)"); continue
        }

        $rgb = ConvertFrom-TcpkPatternColour "$($f.color)" $i
        $fields.Add([pscustomobject]@{
            Name = $name; Offset = $off; Size = $size; Type = $type
            R = $rgb[0]; G = $rgb[1]; B = $rgb[2]
        })
    }

    return @{ Fields = $fields.ToArray(); Errors = $errors.ToArray() }
}

function ConvertFrom-TcpkPatternColour {
<#
.SYNOPSIS
    '#RRGGBB' to an r,g,b triple, with a readable fallback per field index.

.DESCRIPTION
    Private helper for Read-TcpkBytePattern. When a field omits a colour it gets one from a
    fixed palette rather than a random value, so the same pattern always renders the same
    way and two adjacent fields never come out indistinguishable.
#>
    [CmdletBinding()]
    param([AllowEmptyString()][string]$Hex, [int]$Index)

    if ($Hex -match '^#?([0-9a-fA-F]{6})$') {
        $h = $Matches[1]
        return @([Convert]::ToInt32($h.Substring(0, 2), 16),
                 [Convert]::ToInt32($h.Substring(2, 2), 16),
                 [Convert]::ToInt32($h.Substring(4, 2), 16))
    }
    # Distinguishable on a dark ground, and stable: index N always gets the same colour.
    $pal = @(
        @(58, 123, 213), @(46, 160, 100), @(200, 120, 40), @(160, 90, 190),
        @(200, 80, 90),  @(60, 170, 175), @(180, 160, 60), @(120, 130, 200)
    )
    return $pal[(($Index - 1) % $pal.Count)]
}

function Resolve-TcpkBytePattern {
<#
.SYNOPSIS
    Apply a validated pattern to a file and return one decoded row per field.

.DESCRIPTION
    Reads only the span the pattern actually covers, so a 4-field header pattern against a
    200 MB installer reads a few dozen bytes rather than the file.

    A field extending past the end of the file is returned with Status='out-of-range' and
    an empty Value. It is NOT dropped and NOT rendered from stale buffer bytes: an operator
    must be able to see that the pattern does not fit this file, which is usually the most
    interesting thing the pattern can tell them.

.PARAMETER BaseOffset
    Added to every field offset, so one header pattern can be applied at an arbitrary
    position, for example to a structure Test-TcpkEmbeddedBlobs located mid-file.

.OUTPUTS
    [pscustomobject[]] Name, Offset, Size, Type, Value, Status, R, G, B
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Fields,
        [int64]$BaseOffset = 0
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return , @() }
    if (-not $Fields.Count) { return , @() }
    $flen = [int64](Get-Item -LiteralPath $Path).Length

    $lo = [int64]::MaxValue; $hi = [int64]0
    foreach ($f in $Fields) {
        $s = $BaseOffset + $f.Offset
        if ($s -lt $lo) { $lo = $s }
        if (($s + $f.Size) -gt $hi) { $hi = $s + $f.Size }
    }
    if ($lo -lt 0) { $lo = 0 }
    if ($hi -gt $flen) { $hi = $flen }

    $span = [int][Math]::Max(0, $hi - $lo)
    $buf = New-Object 'byte[]' $span
    if ($span -gt 0) {
        $fs = [IO.File]::OpenRead($Path)
        try {
            $fs.Position = $lo
            $got = 0
            while ($got -lt $span) {
                $r = $fs.Read($buf, $got, $span - $got)
                if ($r -le 0) { break }
                $got += $r
            }
            $span = $got
        } finally { $fs.Dispose() }
    }

    $types = Get-TcpkBytePatternTypes
    $out = New-Object 'System.Collections.Generic.List[object]'

    foreach ($f in $Fields) {
        $abs = $BaseOffset + $f.Offset
        $rel = [int]($abs - $lo)
        $value = ''; $status = 'ok'

        if ($abs -lt 0 -or ($abs + $f.Size) -gt $flen) {
            $status = 'out-of-range'
        } elseif ($rel -lt 0 -or ($rel + $f.Size) -gt $span) {
            $status = 'unread'
        } else {
            try { $value = & $types[$f.Type].Decode $buf $rel $f.Size }
            catch { $status = 'decode-error'; $value = "$($_.Exception.Message)" }
        }

        $out.Add([pscustomobject]@{
            Name = $f.Name; Offset = $abs; Size = $f.Size; Type = $f.Type
            Value = "$value"; Status = $status
            R = $f.R; G = $f.G; B = $f.B
        })
    }
    return , $out.ToArray()
}
