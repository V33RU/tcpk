function Test-TcpkZipSlip {
<#
.SYNOPSIS
    A15. Archive-extraction (zip-slip / path-traversal) surface detection.

.DESCRIPTION
    Apps that extract archives (updates, imported projects, backups) are prone
    to "zip slip": a crafted entry name like ..\..\Windows\System32\evil.dll
    escapes the destination directory if the code does Path.Combine(dest,
    entry.FullName) without canonicalising. This static check flags first-party
    assemblies that reference archive-extraction APIs so the analyst can confirm
    whether entry paths are validated.

    Higher confidence when a known unsafe-by-default library (SharpZipLib,
    Ionic.Zip, SharpCompress, Tar) is combined with manual entry handling.

.PARAMETER Path
    File or directory.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    # extraction APIs; value = whether the library defaults to UNSAFE entry handling
    $apis = @(
        @{ needle='ZipFile.ExtractToDirectory'; lib='System.IO.Compression'; safeIsh=$true },
        @{ needle='ExtractToFile';              lib='ZipArchiveEntry';        safeIsh=$false },
        @{ needle='ICSharpCode.SharpZipLib';    lib='SharpZipLib';            safeIsh=$false },
        @{ needle='Ionic.Zip';                  lib='DotNetZip';              safeIsh=$false },
        @{ needle='SharpCompress';              lib='SharpCompress';          safeIsh=$false },
        @{ needle='TarFile.ExtractToDirectory'; lib='System.Formats.Tar';     safeIsh=$true },
        @{ needle='ExtractToDirectoryAsync';    lib='System.IO.Compression'; safeIsh=$true }
    )

    foreach ($pe in Get-TcpkPeFiles -Path $Path) {
        if ($pe.Extension -notin '.dll','.exe') { continue }
        if (Test-TcpkIsFrameworkFile $pe.Name) { continue }
        if (Test-TcpkIsNativeNoise $pe.Name)   { continue }
        $text = Read-TcpkAllText -Path $pe.FullName
        if (-not $text) { continue }

        $hits = @()
        $unsafeLib = $false
        foreach ($a in $apis) {
            if ($text.IndexOf($a.needle, [StringComparison]::Ordinal) -ge 0) {
                $hits += $a.lib
                if (-not $a.safeIsh) { $unsafeLib = $true }
            }
        }
        if ($hits.Count -eq 0) { continue }

        # If they also touch entry.FullName / Path.Combine, the traversal pattern is plausible.
        $manualEntry = ($text.IndexOf('FullName', [StringComparison]::Ordinal) -ge 0 -and
                        $text.IndexOf('Path.Combine', [StringComparison]::Ordinal) -ge 0)

        $sev = if ($unsafeLib -or $manualEntry) { 'MEDIUM' } else { 'LOW' }
        New-TcpkFinding -Module 'static' -RuleId 'zipslip.extraction-surface' `
            -Severity $sev -Confidence 'Inferred' `
            -Title "Archive extraction in $($pe.Name) (review for zip-slip)" `
            -File $pe.FullName `
            -Evidence ("libs: " + (($hits | Select-Object -Unique) -join ', ') + $(if ($manualEntry) { ' | manual entry.FullName + Path.Combine' } else { '' })) `
            -Cwe @('CWE-22','CWE-29') `
            -Description 'The assembly extracts archives. If entry names are not canonicalised and verified to stay under the destination root, a crafted archive can write files outside it (zip slip), enabling code execution or config overwrite.' `
            -Fix 'Before writing each entry, resolve the full destination path and verify it StartsWith the destination root (Path.GetFullPath + ordinal compare). Reject entries containing .. or rooted paths.'
    }
}
