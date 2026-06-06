# .NET single-file bundle reader.
#
# `dotnet publish -p:PublishSingleFile=true` produces an apphost .exe with all
# managed assemblies (and optionally native libs) appended after the PE image as
# a "bundle". TCPK's static scanners read loose .dll/.exe files -- for a single-
# file app there are none on disk, so without this extractor those scanners would
# silently see almost nothing. This parses the bundle manifest (Microsoft.NET.
# HostModel format, major versions 1/2/6) and carves each embedded file back out,
# decompressing Deflate-compressed entries (EnableCompressionInSingleFile).
#
# Format (little-endian):
#   - A 16-byte signature is compiled into the apphost; the 8 bytes immediately
#     BEFORE it hold the int64 offset of the bundle header.
#   - Header @ offset: int32 major, int32 minor, int32 fileCount, string bundleId,
#     (major>=2) int64 depsOffset/depsSize/rtcfgOffset/rtcfgSize/flags,
#     then fileCount entries: int64 offset, int64 size,
#       (major>=6) int64 compressedSize, byte type, string relativePath.
#   - Strings use BinaryReader's 7-bit length-prefixed UTF-8 form.

# Signature the .NET bundler embeds in every single-file apphost.
$script:TcpkBundleSignature = [byte[]]@(
    0x8b, 0x12, 0x02, 0xb9, 0x6a, 0x61, 0x20, 0x38,
    0x72, 0x7b, 0x93, 0x02, 0x14, 0xd7, 0xa0, 0x32
)

# FileType enum (Microsoft.NET.HostModel.Bundle.FileType).
$script:TcpkBundleFileType = @{
    0 = 'Unknown'; 1 = 'Assembly'; 2 = 'NativeBinary'
    3 = 'DepsJson'; 4 = 'RuntimeConfigJson'; 5 = 'Symbols'
}

# Find a byte sub-sequence using Array.IndexOf to skip between first-byte
# candidates (native, so this stays fast even on a 100 MB+ apphost).
function Find-TcpkByteSequence {
    [CmdletBinding()] param(
        [Parameter(Mandatory)][byte[]]$Haystack,
        [Parameter(Mandatory)][byte[]]$Needle
    )
    $n = $Needle.Length
    $h = $Haystack.Length
    if ($n -eq 0 -or $h -lt $n) { return -1 }
    $first = $Needle[0]
    $idx = [Array]::IndexOf($Haystack, $first, 0)
    while ($idx -ge 0 -and $idx -le ($h - $n)) {
        $match = $true
        for ($j = 1; $j -lt $n; $j++) {
            if ($Haystack[$idx + $j] -ne $Needle[$j]) { $match = $false; break }
        }
        if ($match) { return $idx }
        $idx = [Array]::IndexOf($Haystack, $first, $idx + 1)
    }
    return -1
}

# Read the bundle header offset from an already-loaded byte[]. Returns -1 if the
# file is not a single-file bundle (signature absent / offset implausible).
function Get-TcpkBundleHeaderOffset {
    [CmdletBinding()] param([Parameter(Mandatory)][byte[]]$Bytes)
    $sig = Find-TcpkByteSequence -Haystack $Bytes -Needle $script:TcpkBundleSignature
    if ($sig -lt 8) { return -1 }
    try {
        $headerOffset = [BitConverter]::ToInt64($Bytes, $sig - 8)
    } catch { return -1 }
    if ($headerOffset -le 0 -or $headerOffset -ge $Bytes.Length) { return -1 }
    return $headerOffset
}

# Cheap-ish single-file probe: returns the header offset (int64) if $Path is a
# single-file apphost, else $null. Caps the read so a pathological huge file
# cannot exhaust memory.
function Test-TcpkSingleFileExe {
    [CmdletBinding()] param(
        [Parameter(Mandatory)][string]$Path,
        [int64]$MaxBytes = 734003200   # 700 MB
    )
    try {
        $fi = Get-Item -LiteralPath $Path -ErrorAction Stop
    } catch { return $null }
    if ($fi.PSIsContainer -or $fi.Length -lt 64 -or $fi.Length -gt $MaxBytes) { return $null }
    try {
        $bytes = [IO.File]::ReadAllBytes($Path)
    } catch { return $null }
    $off = Get-TcpkBundleHeaderOffset -Bytes $bytes
    if ($off -lt 0) { return $null }
    # sanity-check the header so a random signature collision is not treated as a bundle
    try {
        $ms = New-Object System.IO.MemoryStream(, $bytes)
        $br = New-Object System.IO.BinaryReader($ms, [Text.Encoding]::UTF8)
        $ms.Position = $off
        $major = $br.ReadInt32()
        $null  = $br.ReadInt32()
        $count = $br.ReadInt32()
        $br.Dispose(); $ms.Dispose()
    } catch { return $null }
    if ($major -lt 1 -or $major -gt 6) { return $null }
    if ($count -le 0 -or $count -gt 100000) { return $null }
    return $off
}

# Parse + carve every embedded file from a single-file apphost into $OutDir.
# Returns one record per extracted file (Name/Type/Size/Path/Compressed). Throws
# only on unreadable input; per-entry failures are skipped.
function Expand-TcpkSingleFileBundle {
    [CmdletBinding()] param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$OutDir
    )
    $bytes = [IO.File]::ReadAllBytes($Path)
    $headerOffset = Get-TcpkBundleHeaderOffset -Bytes $bytes
    if ($headerOffset -lt 0) { throw "Not a single-file bundle: $Path" }

    $ms = New-Object System.IO.MemoryStream(, $bytes)
    $br = New-Object System.IO.BinaryReader($ms, [Text.Encoding]::UTF8)
    $entries = New-Object System.Collections.Generic.List[object]
    try {
        $ms.Position = $headerOffset
        $major = $br.ReadInt32()
        $null  = $br.ReadInt32()        # minor
        $count = $br.ReadInt32()
        $null  = $br.ReadString()       # bundleId
        if ($major -ge 2) {
            $null = $br.ReadInt64(); $null = $br.ReadInt64()   # deps json offset/size
            $null = $br.ReadInt64(); $null = $br.ReadInt64()   # runtimeconfig offset/size
            $null = $br.ReadInt64()                            # flags
        }
        for ($i = 0; $i -lt $count; $i++) {
            $off  = $br.ReadInt64()
            $size = $br.ReadInt64()
            $csize = 0
            if ($major -ge 6) { $csize = $br.ReadInt64() }
            $type = [int]$br.ReadByte()
            $rel  = $br.ReadString()
            $entries.Add([pscustomobject]@{ Offset = $off; Size = $size; CompressedSize = $csize; Type = $type; Rel = $rel })
        }
    } finally {
        $br.Dispose(); $ms.Dispose()
    }

    if (-not (Test-Path -LiteralPath $OutDir)) {
        New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
    }

    $out = New-Object System.Collections.Generic.List[object]
    $n = 0
    foreach ($e in $entries) {
        $srcLen = if ($e.CompressedSize -gt 0) { $e.CompressedSize } else { $e.Size }
        if ($e.Offset -lt 0 -or $srcLen -le 0 -or ($e.Offset + $srcLen) -gt $bytes.Length) { continue }
        $slice = New-Object byte[] $srcLen
        [Array]::Copy($bytes, $e.Offset, $slice, 0, $srcLen)

        $data = $slice
        if ($e.CompressedSize -gt 0) {
            try {
                $in  = New-Object System.IO.MemoryStream(, $slice)
                $ds  = New-Object System.IO.Compression.DeflateStream($in, [System.IO.Compression.CompressionMode]::Decompress)
                $o   = New-Object System.IO.MemoryStream
                $ds.CopyTo($o); $ds.Dispose(); $in.Dispose()
                $data = $o.ToArray(); $o.Dispose()
            } catch { continue }
        }

        # Sanitize the relative path so a hostile manifest cannot write outside OutDir.
        $rel = ($e.Rel -replace '/', '\') -replace '\.\.', ''
        $rel = $rel.TrimStart('\')
        if (-not $rel) { $rel = "bundle_entry_$n.bin" }
        $dest = Join-Path $OutDir $rel
        $destDir = Split-Path $dest -Parent
        if ($destDir -and -not (Test-Path -LiteralPath $destDir)) {
            New-Item -ItemType Directory -Path $destDir -Force | Out-Null
        }
        try { [IO.File]::WriteAllBytes($dest, $data) } catch { continue }

        $out.Add([pscustomobject]@{
            Name       = [IO.Path]::GetFileName($rel)
            Rel        = $rel
            Type       = if ($script:TcpkBundleFileType.ContainsKey($e.Type)) { $script:TcpkBundleFileType[$e.Type] } else { "Type$($e.Type)" }
            Size       = $data.Length
            Compressed = ($e.CompressedSize -gt 0)
            Path       = $dest
        })
        $n++
    }
    return $out
}

# Audit helper: find single-file exes under $Path, extract each into one temp
# root, and return that root (or $null if nothing was a single-file bundle).
function Expand-TcpkSingleFileForScan {
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Path)
    $item = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
    if (-not $item) { return $null }
    $exes = if ($item.PSIsContainer) {
        Get-ChildItem -LiteralPath $Path -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension.ToLowerInvariant() -eq '.exe' }
    } else { @($item) }

    $outRoot = $null
    foreach ($exe in $exes) {
        if ($null -eq (Test-TcpkSingleFileExe -Path $exe.FullName)) { continue }
        if (-not $outRoot) {
            $outRoot = Join-Path $env:TEMP ("TCPK_sf_" + [IO.Path]::GetRandomFileName().Replace('.', ''))
            New-Item -ItemType Directory -Path $outRoot -Force | Out-Null
        }
        $sub = Join-Path $outRoot $exe.BaseName
        try { [void](Expand-TcpkSingleFileBundle -Path $exe.FullName -OutDir $sub) } catch { }
    }
    return $outRoot
}
