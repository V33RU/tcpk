# Go / Rust dependency-tree recovery from statically-linked native binaries.
#
# WHY THIS EXISTS. .NET ships deps.json, Electron ships package.json, Java ships
# pom.properties inside the jar. Go and Rust ship ONE statically-linked executable
# with the whole dependency tree compiled in and no manifest beside it, so a Go or
# Rust thick client used to reach the CVE engine with an empty component list --
# which reads as "clean" instead of "never queried".
#
# Two very different recovery paths, and the difference is worth stating plainly:
#
#   Go   is STRUCTURED. The toolchain stamps runtime/debug.BuildInfo into the image
#        behind a fixed 14-byte magic, and the module list is plain tab/newline
#        delimited text. Recovery is complete for any binary the Go linker produced
#        (Go 1.18+ inlines the strings; older releases store pointers, and the text
#        block is still present either way).
#
#   Rust is NOT. rustc embeds no manifest of any kind. The only crate identities that
#        survive are the Cargo registry SOURCE PATHS baked into panic locations and
#        debug info: .../cargo/registry/src/<host>-<hash>/<crate>-<version>/src/lib.rs.
#        A stripped release build, or one built with --remap-path-prefix, has none of
#        them. Rust recovery here is therefore BEST-EFFORT AND INCOMPLETE BY
#        CONSTRUCTION, and every caller is required to say so.
#
# Both collectors return the SHARED component shape used by Get-TcpkCveMatches:
#     [pscustomobject] @{ Name; Version; File }
# plus Ecosystem / Source / Verified, which the OSV feeder ignores.

# "\xff Go buildinf:" -- the runtime/debug.BuildInfo header magic. Stable across every
# Go release that has had it (1.13+). The two bytes that follow are ptrSize and flags.
$script:TcpkGoBuildInfMagic = [byte[]]@(0xFF, 0x20, 0x47, 0x6F, 0x20, 0x62, 0x75, 0x69, 0x6C, 0x64, 0x69, 0x6E, 0x66, 0x3A)

# flags bit 1 (0x2): the module data is stored INLINE as length-delimited strings
# (Go 1.18+). When clear, the header holds pointers into the data section instead.
$script:TcpkGoFlagInlineStrings = 0x2

# Raw-byte chunk for the magic scan. The scan uses a Latin-1 decode (byte <-> char 1:1)
# so the search itself is a native String.IndexOf rather than a per-byte PowerShell loop,
# which on a 200 MB image is the difference between milliseconds and minutes.
$script:TcpkGoMagicChunk   = 4MB
$script:TcpkGoMagicOverlap = 64

# Locate the Go build-info header by RAW BYTES and read the two header fields after it.
# Returns a record even when nothing is found, so a caller can distinguish
# "scanned, absent" from "not scanned".
function Find-TcpkGoBuildInfoMagic {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [long]$MaxBytes = 0          # 0 = read the whole file
    )
    $res = [pscustomobject]@{
        Found = $false; Offset = -1; PtrSize = 0; Flags = 0
        InlineStrings = $false; BytesScanned = [int64]0; Truncated = $false; Error = ''
    }
    $fs = $null
    try {
        # FileShare.ReadWrite|Delete: a running target holds its own image open.
        $fs = [System.IO.FileStream]::new($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read,
              ([System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete))
    } catch {
        $res.Error = "$($_.Exception.Message)"
        return $res
    }
    try {
        $enc = $null
        try { $enc = [System.Text.Encoding]::GetEncoding(28591) } catch { $enc = $null }   # ISO-8859-1
        if (-not $enc) { $res.Error = 'Latin-1 (28591) encoding unavailable'; return $res }

        $needle = ''
        foreach ($b in $script:TcpkGoBuildInfMagic) { $needle += [char][int]$b }

        $chunk   = [int]$script:TcpkGoMagicChunk
        $overlap = [int]$script:TcpkGoMagicOverlap
        $buf     = New-Object byte[] ($chunk + $overlap)
        $carry   = 0
        $basePos = [int64]0
        while ($true) {
            $read  = $fs.Read($buf, $carry, $chunk)
            $total = $carry + $read
            if ($total -le 0) { break }
            $res.BytesScanned += $read

            $s = $enc.GetString($buf, 0, $total)
            $idx = $s.IndexOf($needle, [System.StringComparison]::Ordinal)
            if ($idx -ge 0) {
                $res.Found  = $true
                $res.Offset = $basePos + $idx
                # ptrSize and flags sit immediately after the 14-byte magic. They are only
                # readable when both bytes landed inside this buffer; a match in the final
                # 2 bytes of the file simply leaves them at 0.
                if (($idx + 15) -lt $total) {
                    $res.PtrSize = [int]$buf[$idx + 14]
                    $res.Flags   = [int]$buf[$idx + 15]
                    $res.InlineStrings = (($res.Flags -band $script:TcpkGoFlagInlineStrings) -ne 0)
                }
                break
            }

            if ($read -lt $chunk) { break }                       # end of file
            if ($MaxBytes -gt 0 -and $res.BytesScanned -ge $MaxBytes) { $res.Truncated = $true; break }

            # Carry the tail forward so a magic straddling the boundary is still found.
            $keep = [Math]::Min($overlap, $total)
            [System.Array]::Copy($buf, $total - $keep, $buf, 0, $keep)
            $basePos += ($total - $keep)
            $carry = $keep
        }
    } catch {
        $res.Error = "$($_.Exception.Message)"
    } finally {
        if ($fs) { $fs.Dispose() }
    }
    return $res
}

# ---- text-scan patterns -------------------------------------------------------
# The lookbehind is what stops "mydep\t" or "cargo/registry/src/.../godep\t" from being
# read as a 'dep' line. Anchoring on ^ instead would be wrong: the extracted printable
# runs do not preserve the binary's line structure at run boundaries.
$script:TcpkGoDepRx   = '(?<![A-Za-z0-9_./\-])(mod|dep|=>)\t([^\t\r\n]{1,400})\t([^\t\r\n]{1,120})'
$script:TcpkGoPathRx  = '(?<![A-Za-z0-9_./\-])path\t([^\t\r\n]{1,400})'
$script:TcpkGoVerRx   = '(?<![A-Za-z0-9_./\-])go\t(1\.\d{1,3}(?:\.\d{1,3})?)'
$script:TcpkGoBuildRx = '(?<![A-Za-z0-9_./\-])build\t(-[A-Za-z0-9_.\-]{1,40}=[^\t\r\n]{0,160})'

# Cargo registry source path. Both separators appear: a Windows cross-build keeps
# backslashes, a path recorded by rustc on the build host keeps forward slashes.
# No leading separator is required before 'cargo': CARGO_HOME is normally the DOTTED
# directory '.cargo', so anchoring on '/cargo/' would match nothing in practice. The
# lookbehind is what keeps a directory merely ENDING in "cargo" out of the match.
$script:TcpkCargoCrateRx = '(?i)(?<![A-Za-z0-9_\-])cargo[\\/]registry[\\/]src[\\/][^\\/]{1,120}[\\/]([A-Za-z0-9_][A-Za-z0-9_\-]{0,63}?)-(\d+\.\d+\.\d+[0-9A-Za-z.\-+]{0,40})[\\/]'
# Vendored trees (cargo vendor) have the same <crate>-<version> leaf without the registry hop.
$script:TcpkCargoVendorRx = '(?i)[\\/]vendor[\\/]([A-Za-z0-9_][A-Za-z0-9_\-]{0,63}?)-(\d+\.\d+\.\d+[0-9A-Za-z.\-+]{0,40})[\\/]src[\\/]'
$script:TcpkRustcHashRx  = '(?i)[\\/]rustc[\\/]([0-9a-f]{40})[\\/]'
$script:TcpkRustcVerRx   = 'rustc[ \-](1\.\d{1,3}(?:\.\d{1,3})?)'

# A Go module path is a domain-ish import path. Requiring a dot or a slash is what keeps
# a stray "dep\tfoo\tv1" out of the component list.
function Test-TcpkGoModulePath {
    param([string]$Name)
    if (-not $Name) { return $false }
    if ($Name.Length -gt 300) { return $false }
    if ($Name -notmatch '^[A-Za-z0-9][A-Za-z0-9._~/\-]*$') { return $false }
    return ($Name.Contains('/') -or $Name.Contains('.'))
}

# Scan ONE binary for both Go build info and Rust cargo paths in a single streamed pass.
#
# Streaming, not Get-Content -Raw: Invoke-TcpkOnFileText hands the file to the C#
# printable-run extractor above 16 MB, so a 200 MB image costs bounded memory and every
# byte is still read. -Utf8Only because Go and Rust both embed UTF-8; the UTF-16 views
# would be noise and double the work.
#
# Returns a record with everything the caller needs to write an honest finding, including
# the caps it hit.
function Get-TcpkGoRustBinaryInfo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [int]$MaxComponents = 5000
    )
    $info = [pscustomobject]@{
        Path = $Path; IsGo = $false; IsRust = $false
        MagicFound = $false; MagicOffset = -1; PtrSize = 0; Flags = 0; InlineStrings = $false
        GoToolchain = ''; GoMainPath = ''; GoMainVersion = ''
        GoModules = @(); GoModulesRaw = 0; GoUnusableVersions = 0; GoBuildSettings = @()
        RustCrates = @(); RustcHash = ''; RustcVersion = ''
        Capped = $false; Error = ''
    }

    $st = @{
        Stop = $false
        GoDeps = (New-Object 'System.Collections.Specialized.OrderedDictionary')
        GoBuild = (New-Object 'System.Collections.Generic.List[string]')
        Rust = (New-Object 'System.Collections.Specialized.OrderedDictionary')
        GoPath = ''; GoVer = ''; MainVer = ''
        RustcHash = ''; RustcVer = ''
        GoBuildId = $false; MagicText = $false
        RawGo = 0; BadVer = 0
        Cap = $MaxComponents; Capped = $false
    }

    try {
        Invoke-TcpkOnFileText -Path $Path -State $st -Utf8Only -OnText {
            param($Text, $Src, $S)
            if (-not $Text -or $S.Stop) { return }

            if (-not $S.GoBuildId -and $Text.IndexOf('Go build ID:', [System.StringComparison]::Ordinal) -ge 0) { $S.GoBuildId = $true }
            if (-not $S.MagicText -and $Text.IndexOf(' Go buildinf:', [System.StringComparison]::Ordinal) -ge 0) { $S.MagicText = $true }

            # ---- Go: mod / dep / => lines ----
            foreach ($m in [regex]::Matches($Text, $script:TcpkGoDepRx)) {
                $kind = $m.Groups[1].Value
                $name = $m.Groups[2].Value.Trim()
                $ver  = $m.Groups[3].Value.Trim()
                if (-not (Test-TcpkGoModulePath $name)) { continue }
                $S.RawGo++
                if ($kind -eq 'mod' -and -not $S.MainVer) { $S.GoPath = $name; $S.MainVer = $ver }
                # Normalize to the shape the CVE pipeline already uses: 'v' stripped, must
                # start with a digit. '(devel)' / '(untracked)' are real build states, not
                # versions -- counted, never invented into something queryable.
                $nv = $ver -replace '^v', ''
                if ($nv -notmatch '^\d') { $S.BadVer++; continue }
                $k = "$($name.ToLowerInvariant())|$nv"
                if (-not $S.GoDeps.Contains($k)) {
                    if (($S.GoDeps.Count + $S.Rust.Count) -ge $S.Cap) { $S.Capped = $true; $S.Stop = $true; return }
                    $S.GoDeps[$k] = [pscustomobject]@{ Name = $name; Version = $nv; Kind = $kind }
                }
            }

            if (-not $S.GoPath) {
                $pm = [regex]::Match($Text, $script:TcpkGoPathRx)
                if ($pm.Success) {
                    $cand = $pm.Groups[1].Value.Trim()
                    if (Test-TcpkGoModulePath $cand) { $S.GoPath = $cand }
                }
            }
            if (-not $S.GoVer) {
                $vm = [regex]::Match($Text, $script:TcpkGoVerRx)
                if ($vm.Success) { $S.GoVer = $vm.Groups[1].Value }
            }
            if ($S.GoBuild.Count -lt 24) {
                foreach ($bm in [regex]::Matches($Text, $script:TcpkGoBuildRx)) {
                    if ($S.GoBuild.Count -ge 24) { break }
                    $bv = $bm.Groups[1].Value.Trim()
                    if (-not $S.GoBuild.Contains($bv)) { $S.GoBuild.Add($bv) }
                }
            }

            # ---- Rust: cargo registry / vendor source paths ----
            foreach ($rx in @($script:TcpkCargoCrateRx, $script:TcpkCargoVendorRx)) {
                foreach ($cm in [regex]::Matches($Text, $rx)) {
                    $cn = $cm.Groups[1].Value
                    $cv = $cm.Groups[2].Value
                    if ($cv -notmatch '^\d+\.\d+\.\d+') { continue }
                    $k = "$($cn.ToLowerInvariant())|$cv"
                    if ($S.Rust.Contains($k)) { continue }
                    if (($S.GoDeps.Count + $S.Rust.Count) -ge $S.Cap) { $S.Capped = $true; $S.Stop = $true; return }
                    $S.Rust[$k] = [pscustomobject]@{ Name = $cn; Version = $cv }
                }
            }
            if (-not $S.RustcHash) {
                $hm = [regex]::Match($Text, $script:TcpkRustcHashRx)
                if ($hm.Success) { $S.RustcHash = $hm.Groups[1].Value }
            }
            if (-not $S.RustcVer) {
                $rm = [regex]::Match($Text, $script:TcpkRustcVerRx)
                if ($rm.Success) { $S.RustcVer = $rm.Groups[1].Value }
            }
        }
    } catch {
        $info.Error = "$($_.Exception.Message)"
        return $info
    }

    $info.GoToolchain    = $st.GoVer
    $info.GoMainPath     = $st.GoPath
    $info.GoMainVersion  = $st.MainVer
    $info.GoModulesRaw   = $st.RawGo
    $info.GoUnusableVersions = $st.BadVer
    $info.GoBuildSettings = @($st.GoBuild.ToArray())
    $info.GoModules      = @(@($st.GoDeps.Values))
    $info.RustCrates     = @(@($st.Rust.Values))
    $info.RustcHash      = $st.RustcHash
    $info.RustcVersion   = $st.RustcVer
    $info.Capped         = [bool]$st.Capped

    # Go evidence, strongest first. The magic is the definitive proof the Go linker
    # produced this image; the text signals are what still work when the header is
    # stripped or the extractor did not surface it.
    $goTextSignal = ($info.GoModulesRaw -gt 0) -or $st.GoBuildId -or $st.MagicText -or ($info.GoToolchain -ne '')
    if ($goTextSignal) {
        $mg = Find-TcpkGoBuildInfoMagic -Path $Path
        $info.MagicFound    = $mg.Found
        $info.MagicOffset   = $mg.Offset
        $info.PtrSize       = $mg.PtrSize
        $info.Flags         = $mg.Flags
        $info.InlineStrings = $mg.InlineStrings
        if ($mg.Error -and -not $info.Error) { $info.Error = $mg.Error }
    }
    # A binary counts as Go on the magic, OR on dep/mod lines with real semver -- the
    # documented fallback for an image whose header was stripped.
    $info.IsGo   = ($info.MagicFound -or ($info.GoModules.Count -gt 0) -or ($st.GoBuildId -and $info.GoToolchain))
    $info.IsRust = (($info.RustCrates.Count -gt 0) -or ($info.RustcHash -ne '') -or ($info.RustcVersion -ne ''))
    return $info
}

# Collector for the online CVE engine. Same shape Get-TcpkCveMatches already feeds to
# OSV for every other ecosystem: @{ Name; Version; File }.
#
#   -Ecosystem Go        -> Go module paths recovered from embedded build info
#   -Ecosystem crates.io -> Rust crates recovered from cargo registry paths (BEST-EFFORT)
#   -Ecosystem Any       -> both, each tagged with its .Ecosystem
function Get-TcpkGoRustBinaryComponents {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Dir,
        [ValidateSet('Go', 'crates.io', 'Any')][string]$Ecosystem = 'Any',
        [long]$MaxFileBytes = 536870912,
        [int]$MaxComponents = 5000
    )
    $out = New-Object 'System.Collections.Generic.List[object]'
    $seen = @{}
    if (-not (Test-Path -LiteralPath $Dir)) { return @() }

    $files = @()
    try { $files = @(Get-TcpkPeFiles -Path $Dir) } catch { return @() }
    foreach ($f in $files) {
        if ($MaxFileBytes -gt 0 -and $f.Length -gt $MaxFileBytes) { continue }
        $info = $null
        try { $info = Get-TcpkGoRustBinaryInfo -Path $f.FullName -MaxComponents $MaxComponents } catch { continue }
        if (-not $info) { continue }
        if ($Ecosystem -ne 'crates.io') {
            foreach ($m in @($info.GoModules)) {
                $k = "go|$($m.Name.ToLowerInvariant())|$($m.Version)"
                if ($seen.ContainsKey($k)) { continue }
                $seen[$k] = $true
                $out.Add([pscustomobject]@{ Name = $m.Name; Version = $m.Version; File = $f.Name
                                            Ecosystem = 'Go'; Source = 'go-buildinfo'; Verified = $true })
            }
        }
        if ($Ecosystem -ne 'Go') {
            foreach ($c in @($info.RustCrates)) {
                $k = "rs|$($c.Name.ToLowerInvariant())|$($c.Version)"
                if ($seen.ContainsKey($k)) { continue }
                $seen[$k] = $true
                # Verified = $false: the path proves the crate was COMPILED IN on the build
                # host, not that this exact version's code survived into the shipped image.
                # The npm lockfile path already uses this flag to mark a lead vs a fact.
                $out.Add([pscustomobject]@{ Name = $c.Name; Version = $c.Version; File = $f.Name
                                            Ecosystem = 'crates.io'; Source = 'cargo-path'; Verified = $false })
            }
        }
    }
    return @($out.ToArray())
}
