function Test-TcpkPdbPathLeak {
<#
.SYNOPSIS
    A59. PDB path leakage from the PE debug directory (CodeView RSDS record).

.DESCRIPTION
    Every unstripped MSVC / clang build stamps the absolute build-time PDB path into the
    PE's IMAGE_DEBUG_DIRECTORY as a CodeView RSDS record. That string is present in the
    shipped .exe / .dll even when the .pdb itself is not shipped, and it leaks:
      * the developer's Windows account name (C:\Users\<username>\...)
      * the internal source-tree layout (D:\repos\<product>\src\...)
      * the build agent hostname when a UNC path is used (\\bld-01\shared\...)
      * the CI system when the path has an agent-name segment
    Distinct from Test-TcpkDevArtifacts which fires only when the .pdb FILE ships in the
    install tree; this rule reads what's stamped inside the PE.

    Detection:
      1. Enumerate PE files under Path (skip framework binaries via Test-TcpkIsFrameworkFile).
      2. For each, scan the file bytes for the 4-byte 'RSDS' marker, skip 20 bytes (GUID
         + Age), and read a null-terminated ASCII path.
      3. Emit findings graded by what the path leaks.

    Rules:
      pe.debug.pdb-path-leak            LOW      Confirmed  Any PdbPath present in the PE.
      pe.debug.pdb-path-userprofile     MEDIUM   Confirmed  Path contains C:\Users\<name>\
                                                              (developer account leaked).
      pe.debug.pdb-path-unc             MEDIUM   Confirmed  Path is a UNC (\\host\...) so
                                                              the build server hostname leaks.
      pe.debug.pdb-path-repo            LOW      Confirmed  Path contains \src\, \repo\,
                                                              \code\ or \projects\ segments.

    Confidence is Confirmed for what the RSDS bytes literally say.

.PARAMETER Path
    Install directory or a single PE file.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { return }

    $items = @()
    $item = Get-Item -LiteralPath $Path
    if ($item.PSIsContainer) {
        try { $items = @(Get-TcpkPeFiles -Path $Path) } catch { return }
    } else {
        try { $items = @([IO.FileInfo]::new((Resolve-Path -LiteralPath $Path).Path)) } catch { return }
    }

    # RSDS marker + fixed header layout:
    #   'RSDS' (4)  Guid (16)  Age (4)  PdbPath (null-terminated ASCII/UTF-8)
    # We scan the raw file bytes for the marker rather than walking DataDirectories[6]
    # so this cmdlet has no dependency on the PE parser (a stripped or unusual DataDir
    # count would otherwise miss it). The RSDS marker is 4 ASCII bytes; false-positive
    # risk on a real PE is negligible - the extension filter of Get-TcpkPeFiles keeps
    # us off .txt / .json / .config where 'RSDS' could appear as prose.

    foreach ($pe in $items) {
        if (Test-TcpkIsFrameworkFile $pe.Name) { continue }
        # Cap read size. The OUTER PE's own debug directory always sits early in the file
        # (headers + .rdata are the first sections after the DOS stub). Beyond ~8 MB the
        # RSDS records we find belong to EMBEDDED PEs shipped as resources, .NET single-file
        # bundles, WiX / MSI payloads etc; attributing those to the outer file makes the
        # fix ('/PDBALTPATH on the outer build') not apply. Two safeguards:
        #   1. Cap the scan at 8 MB.
        #   2. Take the FIRST RSDS in that window and stop (see loop below), so a
        #      lower-level PE that sits inside the outer PE's own resources cannot bump
        #      the outer file's finding count.
        $bytes = $null
        try {
            $len = [Math]::Min(8 * 1024 * 1024, [int64]$pe.Length)
            $fs  = [IO.File]::OpenRead($pe.FullName)
            try {
                $bytes = New-Object byte[] $len
                $read = 0
                while ($read -lt $len) {
                    $chunk = $fs.Read($bytes, $read, $len - $read)
                    if ($chunk -le 0) { break }
                    $read += $chunk
                }
                if ($read -ne $len) { [Array]::Resize([ref]$bytes, $read) }
            } finally { $fs.Dispose() }
        } catch { continue }
        if (-not $bytes -or $bytes.Length -lt 40) { continue }

        # Find 'RSDS' (52 53 44 53) in the byte array, then check that the 20 header bytes
        # after it plus at least one ASCII char + null terminator all fit within the buffer.
        # There should be at most a handful of RSDS records per PE; a small loop is fine.
        $paths = New-Object 'System.Collections.Generic.List[string]'
        $i = 0
        while ($i -lt ($bytes.Length - 25)) {
            if ($bytes[$i]     -eq 0x52 -and
                $bytes[$i + 1] -eq 0x53 -and
                $bytes[$i + 2] -eq 0x44 -and
                $bytes[$i + 3] -eq 0x53) {
                # Header: 4 (RSDS) + 16 (GUID) + 4 (Age) = 24. Path starts at +24.
                $pStart = $i + 24
                if ($pStart -ge $bytes.Length) { $i += 4; continue }
                # Read until null terminator or a max path length. PdbFileName is UTF-8
                # per the CodeView spec (mscvpdb.h), so a bytewise "printable ASCII only"
                # filter would truncate at the first continuation byte of a non-English
                # username or project name. Accept every non-zero byte >= 0x20 plus TAB;
                # UTF-8 continuation bytes (0x80..0xFF) are fine here, they decode below.
                $pEnd = $pStart
                $maxPath = [Math]::Min($bytes.Length, $pStart + 4096)
                while ($pEnd -lt $maxPath -and $bytes[$pEnd] -ne 0) {
                    $b = $bytes[$pEnd]
                    if ($b -lt 0x20 -and $b -ne 0x09) { break }
                    $pEnd++
                }
                $len = $pEnd - $pStart
                if ($len -ge 4) {
                    $s = [Text.Encoding]::UTF8.GetString($bytes, $pStart, $len)
                    # Must look like a Windows/UNIX path ending in .pdb (case-insensitive).
                    if ($s -match '(?i)\.pdb$' -and $s -match '[\\/]') {
                        if (-not $paths.Contains($s)) { [void]$paths.Add($s) }
                        # Stop scanning this PE - see the "outer PE only" rationale above.
                        # If we let the loop continue, an embedded resource that ships an
                        # inner PE would be reported against this outer file.
                        break
                    }
                }
                # Skip past the header so we do not re-match inside the same record.
                $i = $pStart + [Math]::Max(1, $len + 1)
                continue
            }
            $i++
        }
        if ($paths.Count -eq 0) { continue }

        foreach ($pdbPath in $paths) {
            $userProfile = ($pdbPath -match '(?i)^[A-Z]:\\Users\\[^\\]+\\')
            $isUnc       = ($pdbPath -match '^(\\\\|//)')
            $repoLike    = ($pdbPath -match '(?i)\\(src|repo|repos|code|projects|source)\\')
            if ($isUnc) {
                New-TcpkFinding -Module 'discovery' -RuleId 'pe.debug.pdb-path-unc' `
                    -Severity 'MEDIUM' -Confidence 'Confirmed' `
                    -Title "$($pe.Name) leaks a UNC PDB path: $pdbPath" `
                    -File $pe.FullName -Evidence "PdbPath=$pdbPath" `
                    -Cwe @('CWE-540','CWE-200') `
                    -Description ('The PE debug directory contains a CodeView RSDS record whose PdbPath is a UNC ' +
                        'path. The build server hostname (and often the share layout) is now discoverable by ' +
                        'anyone with the shipped binary.') `
                    -Fix 'Strip the PDB path from the release build (link /PDBALTPATH:%_PDB% or /PDB:%_PDB%.pdb followed by a Nuget bundle post-step), or move the .pdb into a build-agent-relative location.'
            } elseif ($userProfile) {
                $user = ''
                $m = [regex]::Match($pdbPath, '(?i)^[A-Z]:\\Users\\([^\\]+)\\')
                if ($m.Success) { $user = $m.Groups[1].Value }
                New-TcpkFinding -Module 'discovery' -RuleId 'pe.debug.pdb-path-userprofile' `
                    -Severity 'MEDIUM' -Confidence 'Confirmed' `
                    -Title "$($pe.Name) leaks a developer profile PDB path (user=$user)" `
                    -File $pe.FullName -Evidence "PdbPath=$pdbPath" `
                    -Cwe @('CWE-540','CWE-200') `
                    -Description ('The PDB path stamped in this binary lives under C:\Users\<name>, exposing the ' +
                        'Windows account name that produced the build. Combined with the source-tree layout ' +
                        'segments, this is a low-effort phishing / social-engineering signal about the vendor.') `
                    -Fix 'Set /PDBALTPATH:%_PDB% (MSVC) so the linker writes just the basename, or strip the debug directory in the release step.'
            } elseif ($repoLike) {
                New-TcpkFinding -Module 'discovery' -RuleId 'pe.debug.pdb-path-repo' `
                    -Severity 'LOW' -Confidence 'Confirmed' `
                    -Title "$($pe.Name) leaks a source-tree PDB path: $pdbPath" `
                    -File $pe.FullName -Evidence "PdbPath=$pdbPath" `
                    -Cwe @('CWE-540','CWE-200') `
                    -Description ("The PDB path reveals a repo / src / projects / code segment. It discloses " +
                        "the internal source-tree layout and often the product's internal codename.") `
                    -Fix 'Set /PDBALTPATH:%_PDB% or strip the debug directory in the release step.'
            } else {
                New-TcpkFinding -Module 'discovery' -RuleId 'pe.debug.pdb-path-leak' `
                    -Severity 'LOW' -Confidence 'Confirmed' `
                    -Title "$($pe.Name) ships a build-time PDB path: $(Split-Path -Leaf $pdbPath)" `
                    -File $pe.FullName -Evidence "PdbPath=$pdbPath" `
                    -Cwe @('CWE-540') `
                    -Description ('An unstripped CodeView RSDS record in the debug directory names the PDB ' +
                        'produced by the build. On its own the leak is small (a filename); paired with the ' +
                        'other pdb-path rules above it becomes a build-machine fingerprint.') `
                    -Fix 'Set /PDBALTPATH:%_PDB% (MSVC) or -Wl,--no-insert-timestamp equivalents for the toolchain to keep only the basename.'
            }
        }
    }
}
