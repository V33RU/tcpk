# Entropy + encoding helpers shared by secret/key hunters.

# Shannon entropy in bits-per-character. Random base64 ~5.5-6.0, random hex
# ~3.9-4.0, English prose ~3.5-4.5, a repeated/structured string is much lower.
function Get-TcpkShannonEntropy {
    [CmdletBinding()] param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return 0.0 }
    $len  = $Text.Length
    $freq = @{}
    foreach ($ch in $Text.ToCharArray()) {
        if ($freq.ContainsKey($ch)) { $freq[$ch]++ } else { $freq[$ch] = 1 }
    }
    $h = 0.0
    foreach ($c in $freq.Values) {
        $p = $c / $len
        $h -= $p * [Math]::Log($p, 2)
    }
    return [Math]::Round($h, 3)
}

# base64url -> bytes (JWT segments). Returns $null on failure.
function Convert-TcpkFromB64Url {
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Text)
    try {
        $s = $Text.Replace('-', '+').Replace('_', '/')
        switch ($s.Length % 4) { 2 { $s += '==' } 3 { $s += '=' } 1 { return $null } }
        return [Convert]::FromBase64String($s)
    } catch { return $null }
}

# bytes -> base64url (JWT segments): padding stripped, +/ -> -_. Round-trips with
# Convert-TcpkFromB64Url. Used to forge JWT header/payload/signature segments.
function Convert-TcpkToB64Url {
    [CmdletBinding()] param([Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Bytes)
    if ($null -eq $Bytes -or $Bytes.Length -eq 0) { return '' }
    return [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

# ------------------------------------------------------- block entropy over a file ----
#
# NOT a duplicate of Get-TcpkShannonEntropy above, and the two should stay separate. That
# one measures a STRING in bits-per-character with a hashtable, for the secret hunters.
# This one measures BYTES in bits-per-byte with a reusable int[256], because it runs once
# per block and a file produces thousands of them; building a hashtable and a string per
# block would be both slower and wrong for binary data.
#
# It lives here rather than in Start-TCPKGui.ps1 so it can be tested. The GUI copy it
# replaces could not be, being a script-local function inside a 7500-line WinForms file,
# which is why the following bug survived.
#
# THE BUG. The GUI caller sized blocks to span the entire file:
#     $ebs = [Math]::Max(256, [Math]::Ceiling($fileLength / 2000))
# always asking for ~2000 blocks whatever the size. The callee ignored that and read only
# the first 10 MB. On a 22 MB binary it returned 952 blocks covering the first 45%, while
# the entropy strip painted them across its FULL height and its click handler mapped that
# same height to the FULL file size. Colours and offsets disagreed: clicking halfway down
# jumped to 11 MB while the colour there described offset ~5 MB. Not truncated, actively
# wrong, and thick clients are routinely over 10 MB so it was the normal case.
#
# Streaming removes the cap rather than raising it. The caller fixes the block COUNT, so
# work stays bounded at any file size and peak memory drops from a 10 MB buffer to one
# block (~11 KB on that 22 MB file).

function Get-TcpkBlockEntropy {
<#
.SYNOPSIS
    Shannon entropy (0.0-8.0 bits/byte) per fixed-size block across an entire file.

.DESCRIPTION
    Streams the file one block at a time and returns one double per block, in order, so
    index i covers bytes [i*BlockSize, (i+1)*BlockSize). The whole file is always covered:
    any caller mapping the result onto a full-height control can trust that position i
    corresponds to offset i*BlockSize and nothing is silently missing.

    Entropy is bits per byte, so 0.0 is a single repeated value and 8.0 is uniform random.
    Compressed, encrypted and packed regions sit near 8.0; English text near 4.5; padding
    and long null runs near 0.0.

.PARAMETER Path
    File to measure.

.PARAMETER BlockSize
    Bytes per block. Values under 64 are raised to 256, because entropy over a handful of
    bytes is dominated by sample size rather than content: a 16-byte block can never exceed
    4.0 bits/byte no matter how random it is, which would read as "structured" and is
    misleading.

.PARAMETER MaxBlocks
    Safety ceiling on the returned array. If BlockSize would produce more than this, the
    block size is raised so the whole file is still covered by at most MaxBlocks entries.
    Coverage is never traded away; only resolution is.

.OUTPUTS
    [double[]] -- one entropy value per block, covering the entire file.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [int]$BlockSize = 4096,
        [int]$MaxBlocks = 20000
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return , @() }
    $total = [int64](Get-Item -LiteralPath $Path).Length
    if ($total -le 0) { return , @() }

    if ($BlockSize -lt 64) { $BlockSize = 256 }
    if ($MaxBlocks -lt 1) { $MaxBlocks = 1 }

    # Raise the block size rather than stop early. Growing the block loses detail; stopping
    # early loses the end of the file, and a viewer cannot tell that it happened.
    $needed = [int64][Math]::Ceiling($total / [double]$BlockSize)
    if ($needed -gt $MaxBlocks) {
        $BlockSize = [int][Math]::Ceiling($total / [double]$MaxBlocks)
        $needed = [int64][Math]::Ceiling($total / [double]$BlockSize)
    }

    $blocks = [int]$needed
    $result = New-Object 'double[]' $blocks
    $log2 = [Math]::Log(2)
    $buf = New-Object 'byte[]' $BlockSize
    $freq = New-Object 'int[]' 256

    $fs = [IO.File]::OpenRead($Path)
    try {
        for ($bi = 0; $bi -lt $blocks; $bi++) {
            # Read may return fewer bytes than asked for even mid-file, so loop until the
            # block is full or the stream ends. A short read treated as a full block would
            # count stale bytes from the previous iteration.
            $got = 0
            while ($got -lt $BlockSize) {
                $r = $fs.Read($buf, $got, $BlockSize - $got)
                if ($r -le 0) { break }
                $got += $r
            }
            if ($got -le 0) { break }

            [System.Array]::Clear($freq, 0, 256)
            for ($i = 0; $i -lt $got; $i++) { $freq[$buf[$i]]++ }

            $ent = [double]0
            for ($v = 0; $v -lt 256; $v++) {
                if ($freq[$v] -gt 0) {
                    $p = [double]$freq[$v] / $got
                    $ent -= $p * [Math]::Log($p) / $log2
                }
            }
            $result[$bi] = $ent
        }
    } finally { $fs.Dispose() }

    return , $result
}
