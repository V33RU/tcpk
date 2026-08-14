# Whole-file byte diff: where do two files differ, and how far apart.
#
# The Hex tab already colours differing bytes, but only within the page currently on
# screen: Load-GuiHex reads min(PageSize, len - offset) bytes of the other file and compares
# just those. So diffing two 5 MB builds whose only change sits at 0x3A0000 shows
# "diff: 0 bytes" on every page until you happen to scroll to the right one, and "0" on the
# current page reads exactly like "the files are identical". Same false-clean shape as a
# truncated table that does not say it is truncated.
#
# These make the question answerable without scrolling: how many differences are there in
# the whole file, and where is the next one.
#
# SIZE MISMATCH is handled deliberately. If the files differ in length, every byte past the
# shorter one is trivially "different", which would drown a real difference count and park
# a Next-Difference button at the truncation point forever. Differences are therefore
# counted and searched only within the COMMON prefix, and the length delta is reported
# separately as the distinct fact it is.

function Get-TcpkFileDiffSummary {
<#
.SYNOPSIS
    Compare two files and report where and how much they differ.

.DESCRIPTION
    Streams both files in parallel; neither is loaded whole.

    DifferingBytes and FirstDifference cover the COMMON prefix only. A length difference is
    reported by LengthDelta rather than being folded into the byte count, because "these
    files differ in 3 bytes and one is 4 KB longer" and "these files differ in 4099 bytes"
    describe very different situations.

.PARAMETER MaxScan
    Stop after this many bytes of the common prefix. Truncated is set so a partial answer
    cannot be read as a complete one.

.OUTPUTS
    [hashtable] LengthA, LengthB, CommonLength, DifferingBytes, FirstDifference,
                LengthDelta, Identical, Truncated, Scanned
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$PathA,
        [Parameter(Mandatory)][string]$PathB,
        [int64]$MaxScan = 1073741824
    )

    $r = @{
        LengthA = [int64]0; LengthB = [int64]0; CommonLength = [int64]0
        DifferingBytes = [int64]0; FirstDifference = [int64]-1; LengthDelta = [int64]0
        Identical = $false; Truncated = $false; Scanned = [int64]0
    }
    if (-not (Test-Path -LiteralPath $PathA -PathType Leaf)) { return $r }
    if (-not (Test-Path -LiteralPath $PathB -PathType Leaf)) { return $r }

    $r.LengthA = [int64](Get-Item -LiteralPath $PathA).Length
    $r.LengthB = [int64](Get-Item -LiteralPath $PathB).Length
    $r.LengthDelta = $r.LengthB - $r.LengthA
    $common = [int64][Math]::Min($r.LengthA, $r.LengthB)
    $r.CommonLength = $common

    $limit = [int64][Math]::Min($common, $MaxScan)
    $r.Truncated = ($limit -lt $common)

    $chunk = 1048576
    $fa = $null; $fb = $null
    try {
        $fa = [IO.File]::OpenRead($PathA)
        $fb = [IO.File]::OpenRead($PathB)
        $ba = New-Object 'byte[]' $chunk
        $bb = New-Object 'byte[]' $chunk
        $pos = [int64]0
        while ($pos -lt $limit) {
            $want = [int][Math]::Min($chunk, $limit - $pos)
            $ga = Read-TcpkFull $fa $ba $want
            $gb = Read-TcpkFull $fb $bb $want
            $n = [Math]::Min($ga, $gb)
            if ($n -le 0) { break }
            for ($i = 0; $i -lt $n; $i++) {
                if ($ba[$i] -ne $bb[$i]) {
                    $r.DifferingBytes++
                    if ($r.FirstDifference -lt 0) { $r.FirstDifference = $pos + $i }
                }
            }
            $pos += $n
            if ($n -lt $want) { break }
        }
        $r.Scanned = $pos
    } finally {
        if ($fa) { $fa.Dispose() }
        if ($fb) { $fb.Dispose() }
    }

    # Identical means BOTH: same length and no differing byte. Same-length-with-differences
    # and same-prefix-different-length are both "not identical" and must not collapse.
    $r.Identical = ($r.LengthDelta -eq 0 -and $r.DifferingBytes -eq 0 -and -not $r.Truncated)
    return $r
}

function Read-TcpkFull {
<#
.SYNOPSIS
    Read exactly Count bytes unless the stream ends first.

.DESCRIPTION
    Private helper. Stream.Read may return fewer bytes than asked for even mid-file, and a
    short read treated as a full one would compare stale buffer contents from the previous
    iteration against real data, inventing differences.
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][IO.Stream]$Stream, [Parameter(Mandatory)][byte[]]$Buffer, [Parameter(Mandatory)][int]$Count)
    $got = 0
    while ($got -lt $Count) {
        $n = $Stream.Read($Buffer, $got, $Count - $got)
        if ($n -le 0) { break }
        $got += $n
    }
    return $got
}

function Find-TcpkByteDifference {
<#
.SYNOPSIS
    The next or previous offset at which two files differ.

.DESCRIPTION
    Searches only the common prefix, for the reason given at the top of this file: past the
    end of the shorter file every byte differs, so a navigator that included the tail would
    stop there and never move again.

.PARAMETER From
    Where to start. Forward returns the first differing offset at or after From; backward
    returns the last one at or before it. A caller stepping through differences passes
    current+1 or current-1 so it advances rather than finding the same byte again.

.OUTPUTS
    [int64] the offset, or -1 when there is none in that direction.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$PathA,
        [Parameter(Mandatory)][string]$PathB,
        [int64]$From = 0,
        [switch]$Backward
    )

    if (-not (Test-Path -LiteralPath $PathA -PathType Leaf)) { return [int64]-1 }
    if (-not (Test-Path -LiteralPath $PathB -PathType Leaf)) { return [int64]-1 }
    $la = [int64](Get-Item -LiteralPath $PathA).Length
    $lb = [int64](Get-Item -LiteralPath $PathB).Length
    $common = [int64][Math]::Min($la, $lb)
    if ($common -le 0) { return [int64]-1 }

    $chunk = 1048576
    $fa = $null; $fb = $null
    try {
        $fa = [IO.File]::OpenRead($PathA)
        $fb = [IO.File]::OpenRead($PathB)
        $ba = New-Object 'byte[]' $chunk
        $bb = New-Object 'byte[]' $chunk

        if (-not $Backward) {
            $pos = [int64][Math]::Max(0, $From)
            if ($pos -ge $common) { return [int64]-1 }
            $fa.Position = $pos; $fb.Position = $pos
            while ($pos -lt $common) {
                $want = [int][Math]::Min($chunk, $common - $pos)
                $ga = Read-TcpkFull $fa $ba $want
                $gb = Read-TcpkFull $fb $bb $want
                $n = [Math]::Min($ga, $gb)
                if ($n -le 0) { break }
                for ($i = 0; $i -lt $n; $i++) {
                    if ($ba[$i] -ne $bb[$i]) { return [int64]($pos + $i) }
                }
                $pos += $n
                if ($n -lt $want) { break }
            }
            return [int64]-1
        }

        # Backward: walk block-aligned windows from From downwards and scan each in reverse,
        # so the FIRST hit found is the nearest preceding difference rather than the
        # earliest one in the window.
        $end = [int64][Math]::Min($From, $common - 1)
        if ($end -lt 0) { return [int64]-1 }
        while ($end -ge 0) {
            $start = [int64][Math]::Max(0, $end - $chunk + 1)
            $want = [int]($end - $start + 1)
            $fa.Position = $start; $fb.Position = $start
            $ga = Read-TcpkFull $fa $ba $want
            $gb = Read-TcpkFull $fb $bb $want
            $n = [Math]::Min($ga, $gb)
            for ($i = $n - 1; $i -ge 0; $i--) {
                if ($ba[$i] -ne $bb[$i]) { return [int64]($start + $i) }
            }
            if ($start -le 0) { break }
            $end = $start - 1
        }
        return [int64]-1
    } finally {
        if ($fa) { $fa.Dispose() }
        if ($fb) { $fb.Dispose() }
    }
}
