# Byte map: one pixel per byte (or per block), so the SHAPE of a file is visible without
# reading a single offset.
#
# Different question from the byte-frequency histogram, which answers "how often does 0x47
# appear". This answers "where does this file change character", which is what makes an
# embedded PNG, a run of padding or a packed region obvious at a glance.
#
# Sampling is the whole risk here. Taking every Nth byte preserves texture but ALIASES:
# a 4-byte-periodic structure sampled every 4 bytes renders as a flat colour, and worse, a
# random region can alias into apparent stripes. Inventing structure that is not there is a
# bad failure for a tool whose findings are meant to be evidence, so blocks are averaged and
# the ratio is reported. An operator seeing BytesPerPixel > 1 knows they are looking at an
# average and can zoom to an exact view with -Offset.

function Get-TcpkByteMapSamples {
<#
.SYNOPSIS
    Sample a file into a Columns-wide grid of 0-255 values for a byte-map view.

.DESCRIPTION
    Returns rows of byte values plus the mapping needed to turn a clicked pixel back into a
    file offset, so the view stays navigable rather than being a picture.

    TWO MODES, chosen automatically and always reported:

      exact   the requested span fits in Columns x MaxRows pixels, so one pixel is one
              byte and Values are the bytes themselves.
      block   the span is larger, so one pixel is the MEAN of BytesPerPixel bytes.

    The mean is deliberate. Sampling every Nth byte keeps texture crisper but aliases, and
    an aliasing artifact reads as real structure. Averaging degrades honestly: a region
    that looks uniform under averaging genuinely has a uniform average.

.PARAMETER Columns
    Pixels per row. 256 makes a 256-byte period render as vertical stripes, which is why
    it is a common default for this kind of view.

.PARAMETER MaxRows
    Ceiling on rows produced, which together with Columns bounds the work regardless of
    file size.

.PARAMETER Offset
    Start of the span to map. With -Length, this is how you zoom to an exact 1:1 view of a
    region an overview flagged.

.PARAMETER Length
    Bytes to map. 0 means from Offset to end of file.

.OUTPUTS
    [hashtable] @{ Rows; Columns; RowCount; Mode; BytesPerPixel; Offset; Length; FileLength }
    Rows is an array of byte[] (each Columns long, the final row zero-padded and its real
    width given by LastRowValid).
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [int]$Columns = 256,
        [int]$MaxRows = 512,
        [int64]$Offset = 0,
        [int64]$Length = 0
    )

    $empty = @{
        Rows = @(); Columns = $Columns; RowCount = 0; Mode = 'empty'
        BytesPerPixel = 1; Offset = 0; Length = 0; FileLength = 0; LastRowValid = 0
    }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $empty }
    if ($Columns -lt 1) { $Columns = 1 }
    if ($MaxRows -lt 1) { $MaxRows = 1 }

    $flen = [int64](Get-Item -LiteralPath $Path).Length
    if ($flen -le 0) { return $empty }
    if ($Offset -lt 0) { $Offset = 0 }
    if ($Offset -ge $flen) { return $empty }

    $span = if ($Length -le 0) { $flen - $Offset } else { [Math]::Min($Length, $flen - $Offset) }
    if ($span -le 0) { return $empty }

    $capacity = [int64]$Columns * [int64]$MaxRows
    $bpp = [int][Math]::Max(1, [Math]::Ceiling($span / [double]$capacity))
    $mode = if ($bpp -eq 1) { 'exact' } else { 'block' }

    $pixels = [int][Math]::Ceiling($span / [double]$bpp)
    $rowCount = [int][Math]::Ceiling($pixels / [double]$Columns)
    $lastValid = $pixels - (($rowCount - 1) * $Columns)

    $rows = New-Object 'System.Collections.Generic.List[object]'
    $fs = [IO.File]::OpenRead($Path)
    try {
        $fs.Position = $Offset
        # One row's worth of source bytes at a time: Columns * bpp, which is bounded because
        # bpp was derived from a fixed pixel capacity.
        $rowBytes = $Columns * $bpp
        $buf = New-Object 'byte[]' $rowBytes
        $remaining = $span

        for ($r = 0; $r -lt $rowCount; $r++) {
            $want = [int][Math]::Min($rowBytes, $remaining)
            $got = 0
            while ($got -lt $want) {
                $n = $fs.Read($buf, $got, $want - $got)
                if ($n -le 0) { break }
                $got += $n
            }
            if ($got -le 0) { break }
            $remaining -= $got

            $row = New-Object 'byte[]' $Columns
            if ($bpp -eq 1) {
                [Array]::Copy($buf, 0, $row, 0, $got)
            } else {
                $px = [int][Math]::Ceiling($got / [double]$bpp)
                for ($c = 0; $c -lt $px; $c++) {
                    $s = $c * $bpp
                    $e = [Math]::Min($s + $bpp, $got)
                    $sum = 0
                    for ($k = $s; $k -lt $e; $k++) { $sum += $buf[$k] }
                    $row[$c] = [byte]([int]($sum / ($e - $s)))
                }
            }
            $rows.Add($row)
        }
    } finally { $fs.Dispose() }

    return @{
        Rows          = $rows.ToArray()
        Columns       = $Columns
        RowCount      = $rows.Count
        Mode          = $mode
        BytesPerPixel = $bpp
        Offset        = $Offset
        Length        = $span
        FileLength    = $flen
        LastRowValid  = [Math]::Max(0, $lastValid)
    }
}

function Get-TcpkByteMapOffset {
<#
.SYNOPSIS
    Turn a byte-map pixel back into the file offset it represents.

.DESCRIPTION
    Private helper for the Byte Map view. Kept next to the sampler and tested with it,
    because a click that jumps to the wrong offset is the failure that makes the whole view
    untrustworthy, and it is entirely arithmetic.

    In block mode a pixel covers BytesPerPixel bytes; this returns the FIRST of them, which
    is the one an operator wants the hex view scrolled to.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Map,
        [Parameter(Mandatory)][int]$Column,
        [Parameter(Mandatory)][int]$Row
    )

    if ($Map.RowCount -le 0) { return [int64]-1 }
    if ($Column -lt 0 -or $Column -ge $Map.Columns) { return [int64]-1 }
    if ($Row -lt 0 -or $Row -ge $Map.RowCount) { return [int64]-1 }
    if ($Row -eq ($Map.RowCount - 1) -and $Column -ge $Map.LastRowValid) { return [int64]-1 }

    $pixelIndex = ([int64]$Row * $Map.Columns) + $Column
    $off = [int64]$Map.Offset + ($pixelIndex * $Map.BytesPerPixel)
    if ($off -ge ($Map.Offset + $Map.Length)) { return [int64]-1 }
    return $off
}
