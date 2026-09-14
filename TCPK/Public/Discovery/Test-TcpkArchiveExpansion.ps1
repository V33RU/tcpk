function Test-TcpkArchiveExpansion {
<#
.SYNOPSIS
    A75. Shipped archives whose expansion ratio makes them a resource-exhaustion hazard,
    and extraction code that does not bound what it writes.

.DESCRIPTION
    A compressed archive states its uncompressed size in its own directory, so the ratio
    between the two is readable without expanding anything. Ordinary content sits in single
    digits; a file of repeated bytes compresses by orders of magnitude. That gap is what a
    decompression bomb exploits: a few hundred kilobytes on disk that becomes gigabytes in
    memory when something extracts it without asking how big the result will be.

    This matters for a desktop client in two directions. An archive SHIPPED inside the
    product with an extreme ratio is worth a question about what it is. More importantly,
    extraction code that never checks the declared size before writing will happily expand
    whatever it is handed, so an archive arriving from a network peer, an update feed or a
    user-opened file becomes a way to exhaust memory or fill the volume.

    Rules:
      archive.extreme-expansion-ratio  MEDIUM  A shipped archive expands by more than 100x.
      archive.unbounded-extraction     LOW     Extraction APIs are used with no evidence of
                                               a size or entry-count check.

    Ratio is computed from the archive's own central directory, never by extracting, so
    reading a hostile archive here cannot itself cause the exhaustion being looked for.

.PARAMETER Path
    File or directory.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { return }

    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue

    $zips = @()
    try {
        $zips = @(Get-ChildItem -LiteralPath $Path -Recurse -File -ErrorAction SilentlyContinue |
                  Where-Object { $_.Extension -match '(?i)^\.(zip|nupkg|vsix|jar|appx|msix|asar)$' -and $_.Length -gt 1024 } |
                  Select-Object -First 200)
    } catch { $zips = @() }

    foreach ($z in $zips) {
        $comp = [int64]$z.Length
        $unc  = [int64]0
        $entries = 0
        $za = $null
        try {
            $za = [System.IO.Compression.ZipFile]::OpenRead($z.FullName)
            foreach ($e in $za.Entries) {
                $entries++
                try { $unc += [int64]$e.Length } catch { }
                if ($entries -gt 20000) { break }
            }
        } catch {
            continue    # not a readable zip container; nothing to measure
        } finally {
            if ($za) { try { $za.Dispose() } catch { } }
        }
        if ($unc -le 0 -or $comp -le 0) { continue }

        $ratio = [math]::Round($unc / [double]$comp, 1)
        if ($ratio -lt 100) { continue }

        New-TcpkFinding -Module 'static' -RuleId 'archive.extreme-expansion-ratio' `
            -Severity 'MEDIUM' -Confidence 'Confirmed' `
            -Title "Shipped archive expands ${ratio}x: $($z.Name)" `
            -File $z.FullName `
            -Evidence ("compressed=$comp bytes; declared uncompressed=$unc bytes; ratio=${ratio}x; entries=$entries") `
            -Cwe @('CWE-409', 'CWE-400') `
            -Description ('The archive declares an uncompressed size more than a hundred times its size on ' +
                'disk. Ordinary mixed content does not compress anything like that well, so a ratio at ' +
                'this level means the contents are highly repetitive, which is either a large sparse or ' +
                'padded asset or a deliberately constructed expansion bomb. The figure comes from the ' +
                'archive''s own directory, so nothing was extracted to obtain it. Worth establishing what ' +
                'this file is and whether the code that opens it bounds the result.') `
            -Fix 'Confirm the archive is a legitimate asset. Wherever the product extracts archives, check the declared uncompressed size and entry count before writing, and abort past a threshold rather than streaming until the disk or heap runs out.'
    }

    # ---- extraction code with no size discipline -----------------------------
    $extractApis = @('ExtractToDirectory', 'ExtractToFile', 'ZipFile.OpenRead', 'ZipArchive',
                     'GZipStream', 'DeflateStream', 'TarFile', 'SharpZipLib', 'SharpCompress')
    $boundMarkers = @('MaxLength', 'maxSize', 'MaxSize', 'sizeLimit', 'SizeLimit', 'entryCount',
                      'EntryCount', 'MaxEntries', 'maxEntries', 'quota', 'Quota')

    foreach ($pe in Get-TcpkPeFiles -Path $Path) {
        if (Test-TcpkIsFrameworkFile $pe.Name) { continue }
        $text = ''
        try { $text = Read-TcpkAllText -Path $pe.FullName } catch { $text = '' }
        if (-not $text) { continue }

        $used = @($extractApis | Where-Object { $text.Contains($_) })
        if ($used.Count -eq 0) { continue }
        $bounded = $false
        foreach ($b in $boundMarkers) { if ($text.Contains($b)) { $bounded = $true; break } }
        if ($bounded) { continue }

        New-TcpkFinding -Module 'static' -RuleId 'archive.unbounded-extraction' `
            -Severity 'LOW' -Confidence 'Inferred' `
            -Title "$($pe.Name) extracts archives with no visible size bound" `
            -File $pe.FullName -Evidence (($used | Select-Object -Unique) -join ', ') `
            -Cwe @('CWE-409', 'CWE-770') `
            -Description ('The assembly calls archive extraction APIs and carries no identifier suggesting ' +
                'a size, quota or entry-count limit. Extraction that streams until the input is exhausted ' +
                'expands whatever it is given, so an archive from an update feed, a network peer or a file ' +
                'the user opened can consume memory or disk far beyond its apparent size. This is a ' +
                'name-level observation rather than a proof: a limit enforced without any of these ' +
                'identifiers would not be seen, which is why it is reported as a lead at LOW.') `
            -Fix 'Before extracting, read the declared uncompressed size and entry count from the archive directory and refuse anything past a threshold. While writing, count bytes actually written and abort if they exceed the declared size, since the declaration itself is attacker-controlled.'
    }
}
