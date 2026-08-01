# Extra-ecosystem component collectors for the online CVE engine: Java (Maven), Python (PyPI),
# Rust (crates.io), Go (Go modules) and Electron app.asar (npm). Each returns a plain list of
# @{ Name; Version; File } that Get-TcpkCveMatches feeds to OSV under the right ecosystem.
# All are best-effort + fully guarded: a malformed input yields nothing, never an error.

# ---- #4 Java: read Maven coordinates from shipped JARs (META-INF/maven/*/pom.properties) ----
function Get-TcpkJarMavenComponents {
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Dir)
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($jar in (Get-ChildItem -LiteralPath $Dir -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.Extension -in '.jar', '.war' })) {
        $zip = $null
        try {
            $zip = [System.IO.Compression.ZipFile]::OpenRead($jar.FullName)
            foreach ($e in $zip.Entries) {
                if ($e.FullName -notmatch '(?i)META-INF/maven/.+/pom\.properties$') { continue }
                $sr = $null
                try {
                    $sr = New-Object System.IO.StreamReader($e.Open())
                    $txt = $sr.ReadToEnd()
                    $g = if ($txt -match '(?im)^groupId=(.+)$')    { $matches[1].Trim() } else { '' }
                    $a = if ($txt -match '(?im)^artifactId=(.+)$') { $matches[1].Trim() } else { '' }
                    $v = if ($txt -match '(?im)^version=(.+)$')    { $matches[1].Trim() } else { '' }
                    if ($g -and $a -and $v -match '^\d') { $out.Add([pscustomobject]@{ Name = "$g`:$a"; Version = $v; File = $jar.Name }) }
                } catch { } finally { if ($sr) { $sr.Dispose() } }
            }
        } catch { } finally { if ($zip) { $zip.Dispose() } }
    }
    return @($out.ToArray())
}

# ---- #5 Python: dist-info/egg-info METADATA + requirements.txt -> PyPI ----
function Get-TcpkPythonComponents {
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Dir)
    $out = New-Object System.Collections.Generic.List[object]
    $seen = @{}
    function _add($n, $v, $f) {
        if (-not $n -or $v -notmatch '^\d') { return }
        $k = "$($n.ToLowerInvariant())|$v"; if ($seen.ContainsKey($k)) { return }; $seen[$k] = $true
        $out.Add([pscustomobject]@{ Name = $n; Version = $v; File = $f })
    }
    foreach ($m in (Get-ChildItem -LiteralPath $Dir -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq 'METADATA' -or $_.Name -eq 'PKG-INFO' })) {
        try {
            $t = Get-Content -LiteralPath $m.FullName -Raw
            $n = if ($t -match '(?im)^Name:\s*(.+)$')    { $matches[1].Trim() } else { '' }
            $v = if ($t -match '(?im)^Version:\s*(.+)$') { $matches[1].Trim() } else { '' }
            _add $n $v $m.Name
        } catch { }
    }
    foreach ($r in (Get-ChildItem -LiteralPath $Dir -Recurse -File -Filter 'requirements*.txt' -ErrorAction SilentlyContinue)) {
        try {
            foreach ($ln in (Get-Content -LiteralPath $r.FullName -ErrorAction SilentlyContinue)) {
                if ($ln -match '^\s*([A-Za-z0-9._-]+)\s*==\s*([0-9][^\s;#]*)') { _add $matches[1] $matches[2] $r.Name }
            }
        } catch { }
    }
    return @($out.ToArray())
}

# ---- #7 Rust: Cargo.lock -> crates.io ----
function Get-TcpkRustComponents {
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Dir)
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($lock in (Get-ChildItem -LiteralPath $Dir -Recurse -File -Filter 'Cargo.lock' -ErrorAction SilentlyContinue)) {
        try {
            $name = $null
            foreach ($ln in (Get-Content -LiteralPath $lock.FullName -ErrorAction SilentlyContinue)) {
                if ($ln -match '^\s*name\s*=\s*"([^"]+)"')    { $name = $matches[1]; continue }
                if ($ln -match '^\s*version\s*=\s*"([0-9][^"]*)"' -and $name) {
                    $out.Add([pscustomobject]@{ Name = $name; Version = $matches[1]; File = 'Cargo.lock' }); $name = $null
                }
                if ($ln -match '^\s*\[\[package\]\]') { $name = $null }
            }
        } catch { }
    }
    return @($out.ToArray())
}

# ---- #6 Go: read the embedded build-info module list from a Go binary -> Go ecosystem ----
# Go stamps runtime/debug.BuildInfo into the binary as tab/newline-delimited text:
#   "mod\t<path>\t<version>\t<hash>" and "dep\t<path>\t<version>\t<hash>".
function Get-TcpkGoComponents {
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Dir)
    $out = New-Object System.Collections.Generic.List[object]
    $seen = @{}
    foreach ($pe in (Get-ChildItem -LiteralPath $Dir -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.Extension -in '.exe', '.dll' })) {
        $t = $null; try { $t = Read-TcpkAllText -Path $pe.FullName } catch { }
        if (-not $t -or -not ($t.Contains('Go build ID:') -or ($t -match 'go1\.\d{1,2}'))) { continue }   # Go binaries only
        foreach ($mm in [regex]::Matches($t, "(?:dep|mod)\t([a-z0-9.\-]+\.[a-z]{2,}/[^\t\n]+)\t(v\d+\.\d+\.\d+[\w.\-+]*)")) {
            $n = $mm.Groups[1].Value; $v = ($mm.Groups[2].Value -replace '^v', '')
            $k = "$($n.ToLowerInvariant())|$v"; if ($seen.ContainsKey($k)) { continue }; $seen[$k] = $true
            $out.Add([pscustomobject]@{ Name = $n; Version = $v; File = $pe.Name })
        }
    }
    return @($out.ToArray())
}

# ---- #8 Electron: extract every package.json inside app.asar -> npm ----
# Minimal asar reader: [u32 @0=4][u32 @4=headerObjSize][u32 @8][u32 @12=jsonSize][json][data...].
# Data region begins at 8 + headerObjSize; a file's bytes are data[int(offset) .. +size].
function Get-TcpkAsarNpmComponents {
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Dir)
    $out = New-Object System.Collections.Generic.List[object]
    $seen = @{}
    foreach ($asar in (Get-ChildItem -LiteralPath $Dir -Recurse -File -Filter '*.asar' -ErrorAction SilentlyContinue)) {
        try {
            $bytes = [System.IO.File]::ReadAllBytes($asar.FullName)
            if ($bytes.Length -lt 16) { continue }
            $headerObjSize = [System.BitConverter]::ToUInt32($bytes, 4)
            $jsonSize      = [System.BitConverter]::ToUInt32($bytes, 12)
            if (($jsonSize + 16) -gt $bytes.Length) { continue }
            $json = [System.Text.Encoding]::UTF8.GetString($bytes, 16, $jsonSize)
            $tree = $json | ConvertFrom-Json
            $base = 8 + $headerObjSize
            # recursive walk: collect (offset,size) of every file named package.json
            $stack = New-Object System.Collections.Generic.Stack[object]
            $stack.Push($tree)
            while ($stack.Count) {
                $node = $stack.Pop()
                if (-not $node.files) { continue }
                foreach ($p in $node.files.PSObject.Properties) {
                    $child = $p.Value
                    if ($child.files) { $stack.Push($child) }
                    elseif ($p.Name -eq 'package.json' -and $null -ne $child.offset -and $child.size) {
                        try {
                            $off = $base + [int64]$child.offset
                            if (($off + $child.size) -le $bytes.Length) {
                                $pjTxt = [System.Text.Encoding]::UTF8.GetString($bytes, $off, [int]$child.size)
                                $pj = $pjTxt | ConvertFrom-Json
                                if ($pj.name -and "$($pj.version)" -match '^\d') {
                                    $k = "$("$($pj.name)".ToLowerInvariant())|$($pj.version)"
                                    if (-not $seen.ContainsKey($k)) { $seen[$k] = $true; $out.Add([pscustomobject]@{ Name = "$($pj.name)"; Version = "$($pj.version)"; File = $asar.Name; Source = 'asar'; Verified = $true }) }
                                }
                            }
                        } catch { }
                    }
                }
            }
        } catch { }
    }
    return @($out.ToArray())
}

# ---- Loose node_modules ON DISK (not inside the asar) -------------------------
# Get-TcpkAsarNpmComponents reads *.asar files only, so anything electron-builder
# left unpacked was invisible. That is not an edge case: native modules are ALWAYS
# unpacked (a .node cannot be loaded from inside an archive), so they land in
# app.asar.unpacked\node_modules, and some apps ship resources\node_modules whole.
# Those are exactly the stale dependencies worth finding.
#
# Walk shape: enumerate every directory named node_modules, then read only the
# IMMEDIATE package directories under each (plus one level for @scope/name).
# Nested node_modules appear in the same enumeration in their own right, so they are
# covered without a second recursive pass over an already-huge tree.
function Get-TcpkLooseNpmComponents {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Dir,
        [int]$MaxPackages = 4000
    )
    $out = New-Object System.Collections.Generic.List[object]
    $seen = @{}
    if (-not (Test-Path -LiteralPath $Dir)) { return @() }

    $addPkg = {
        param($pkgDir, $srcLabel)
        # Hitting the cap makes the returned count a FLOOR, not a total. Record it so the
        # report can say so; a truncated list presented as an exact count is the same class
        # of lie as an unqueried inventory presented as clean.
        if ($out.Count -ge $MaxPackages) { $script:TcpkNpmInventoryCapped = $true; return }
        $pjPath = Join-Path $pkgDir 'package.json'
        if (-not (Test-Path -LiteralPath $pjPath -PathType Leaf)) { return }
        try {
            $pj = Get-Content -LiteralPath $pjPath -Raw -ErrorAction Stop | ConvertFrom-Json
        } catch { return }
        if (-not $pj.name) { return }
        if ("$($pj.version)" -notmatch '^\d') { return }
        $k = "$("$($pj.name)".ToLowerInvariant())|$($pj.version)"
        if ($seen.ContainsKey($k)) { return }
        $seen[$k] = $true
        $out.Add([pscustomobject]@{
            Name = "$($pj.name)"; Version = "$($pj.version)"; File = $pkgDir; Source = $srcLabel; Verified = $true
        })
    }

    $roots = @()
    try { $roots = @(Get-ChildItem -LiteralPath $Dir -Recurse -Directory -Filter 'node_modules' -ErrorAction SilentlyContinue) } catch { }

    foreach ($nm in $roots) {
        if ($out.Count -ge $MaxPackages) { $script:TcpkNpmInventoryCapped = $true; break }
        # app.asar.unpacked is called out separately in the report because "the vendor
        # shipped an unpacked native module" is a different fact from "the vendor ships
        # a plain node_modules tree".
        $label = if ("$($nm.FullName)" -match '(?i)\.asar\.unpacked') { 'unpacked' } else { 'node_modules' }
        $children = @()
        try { $children = @(Get-ChildItem -LiteralPath $nm.FullName -Directory -ErrorAction SilentlyContinue) } catch { }
        foreach ($c in $children) {
            if ($out.Count -ge $MaxPackages) { $script:TcpkNpmInventoryCapped = $true; break }
            if ($c.Name -eq '.bin') { continue }
            if ($c.Name.StartsWith('@')) {
                $scoped = @()
                try { $scoped = @(Get-ChildItem -LiteralPath $c.FullName -Directory -ErrorAction SilentlyContinue) } catch { }
                foreach ($sc in $scoped) { & $addPkg $sc.FullName $label }
                continue
            }
            & $addPkg $c.FullName $label
        }
    }
    return @($out.ToArray())
}

# ---- Lockfiles ---------------------------------------------------------------
# Last resort when the dependency tree is not recoverable from disk. A lockfile is
# a DECLARATION, not proof of shipping: it lists devDependencies and packages the
# build may have pruned. Everything returned here is marked Verified = $false and the
# report labels it, so a CVE in a package that never shipped is not passed off as a
# confirmed finding.
function Get-TcpkLockfileNpmComponents {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Dir,
        [int]$MaxPackages = 4000
    )
    $out = New-Object System.Collections.Generic.List[object]
    $seen = @{}
    if (-not (Test-Path -LiteralPath $Dir)) { return @() }

    $add = {
        param($name, $version, $src)
        if ($out.Count -ge $MaxPackages) { $script:TcpkNpmInventoryCapped = $true; return }
        if (-not $name) { return }
        $v = "$version" -replace '^[v=\s]+', ''
        # npm alias: "version": "npm:real-package@1.2.3". The installed code is real-package,
        # so recording the alias name would query OSV for a package that does not exist.
        if ($v -match '^npm:(.+)@([^@]+)$') { $name = $matches[1]; $v = $matches[2] }
        # Berry's sentinel for the workspace root. Never a published package.
        if ($v -eq '0.0.0-use.local') { return }
        if ($v -notmatch '^\d') { return }
        $k = "$("$name".ToLowerInvariant())|$v"
        if ($seen.ContainsKey($k)) { return }
        $seen[$k] = $true
        $out.Add([pscustomobject]@{ Name = "$name"; Version = $v; File = $src; Source = 'lockfile'; Verified = $false })
    }

    $locks = @()
    try {
        $locks = @(Get-ChildItem -LiteralPath $Dir -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -in @('package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock') } |
            Select-Object -First 21)
    } catch { }
    # 21 requested, 20 used: if a 21st exists the enumeration was truncated.
    if ($locks.Count -gt 20) { $script:TcpkNpmInventoryCapped = $true; $locks = @($locks | Select-Object -First 20) }

    foreach ($lf in $locks) {
        if ($out.Count -ge $MaxPackages) { $script:TcpkNpmInventoryCapped = $true; break }
        $raw = ''
        try { $raw = Get-Content -LiteralPath $lf.FullName -Raw -ErrorAction Stop } catch { continue }
        if (-not $raw) { continue }

        if ($lf.Name -eq 'yarn.lock') {
            # yarn v1 is a custom text format ("foo@^1.0.0:" then '  version "1.2.3"');
            # yarn berry is YAML ('"foo@npm:^1.0.0":' then '  version: 1.2.3'). One pass
            # handles both: remember the last entry header, apply the next version line.
            $pending = ''
            foreach ($line in ($raw -split "`r?`n")) {
                if ($line -match '^\s*#') { continue }

                # Berry states the canonical identity on its own line:
                #   resolution: "strip-ansi@npm:6.0.1"
                # Prefer it over the descriptor. An alias ("foo@npm:bar@^1") or a patch
                # ("left-pad@patch:left-pad@1.3.0#~/p.patch") names one package in the header
                # and a DIFFERENT one in the resolution, so deriving from the header both
                # invents a package and loses the real one.
                if ($line -match '^\s+resolution:\s+"(.+)@npm:([^"]+)"\s*$') {
                    & $add $matches[1] $matches[2] $lf.Name
                    $pending = ''
                    continue
                }

                if ($line -match '^\S' -and $line -match ':\s*$') {
                    # Berry opens with a '__metadata:' block that also carries a 'version:'
                    # line. Without this it would be recorded as a package named __metadata.
                    if ($line -match '^__metadata\s*:') { $pending = ''; continue }
                    # Header can list several specifiers; the package name is the same in all.
                    $first = ($line.TrimEnd(':').Trim().Trim('"') -split ',')[0].Trim().Trim('"')
                    # workspace: is the project itself (version 0.0.0-use.local), link:/portal:
                    # are local paths. None of them is a shipped npm dependency.
                    if ($first -match '@(workspace|link|portal|file|exec):') { $pending = ''; continue }
                    if ($first -match '^(.+?)@(npm|patch|git\+ssh|git\+https|https?):') {
                        # Berry descriptor: everything before the FIRST protocol marker is the
                        # name. A patch entry repeats the name after it ("a@patch:a@npm%3A1.0.0"),
                        # so LastIndexOf would cut in the wrong place and invent 'a@patch:a'.
                        $pending = $matches[1]
                    } else {
                        # yarn v1 descriptor ("lodash@^4.17.15"): strip the range at the last '@'.
                        # Position 0 belongs to an @scope, so only an '@' after it counts.
                        $at = $first.LastIndexOf('@')
                        $pending = if ($at -gt 0) { $first.Substring(0, $at) } else { $first }
                    }
                    continue
                }
                if ($pending -and $line -match '^\s+version:?\s+"?([^"\s]+)"?\s*$') {
                    & $add $pending $matches[1] $lf.Name
                    $pending = ''
                }
            }
            continue
        }

        # PS 5.1 CANNOT PARSE A LOCKFILE v2/v3 AS WRITTEN. Every npm 7+ lockfile keys its
        # root project with the empty string ("packages": { "": {...} }), and ConvertFrom-Json
        # builds a PSCustomObject whose PSNoteProperty constructor rejects an empty name --
        # so the whole file throws and is silently dropped. -AsHashtable would avoid it but
        # is PowerShell 6+. Rename the key before parsing instead. The (?m)^\s* anchor keeps
        # this to a key at the start of a line, which is how npm writes it, so an empty string
        # appearing as a VALUE is untouched.
        $rawJson = $raw -replace '(?m)^\s*""\s*:', '"__tcpk_root__":'
        $json = $null
        try { $json = $rawJson | ConvertFrom-Json -ErrorAction Stop } catch { continue }
        if (-not $json) { continue }

        # lockfileVersion 2/3: flat "packages" keyed by install path.
        if ($json.PSObject.Properties.Name -contains 'packages' -and $json.packages) {
            foreach ($p in $json.packages.PSObject.Properties) {
                if ($out.Count -ge $MaxPackages) { $script:TcpkNpmInventoryCapped = $true; break }
                $key = "$($p.Name)"
                # The root project is the app, not a dependency, under either spelling.
                if (-not $key -or $key -eq '__tcpk_root__') { continue }
                $ent = $p.Value
                # Path form is node_modules/foo or node_modules/@scope/foo, possibly nested.
                $idx = $key.LastIndexOf('node_modules/')
                $nm = if ($idx -ge 0) { $key.Substring($idx + 13) } else { $key }
                if ($ent.PSObject.Properties.Name -contains 'name' -and $ent.name) { $nm = "$($ent.name)" }
                & $add $nm $ent.version $lf.Name
            }
        }

        # lockfileVersion 1: nested "dependencies".
        if ($json.PSObject.Properties.Name -contains 'dependencies' -and $json.dependencies) {
            $stack = New-Object System.Collections.Generic.Stack[object]
            $stack.Push($json.dependencies)
            $guard = 0
            while ($stack.Count -and $out.Count -lt $MaxPackages) {
                $guard++; if ($guard -gt 20000) { break }
                $node = $stack.Pop()
                foreach ($d in $node.PSObject.Properties) {
                    $ent = $d.Value
                    if ($null -eq $ent) { continue }
                    # v1 top-level "dependencies" maps name -> {version, dependencies}. A
                    # plain string value is the v2 root-package form, which has no version.
                    if ($ent -is [string]) { continue }
                    & $add $d.Name $ent.version $lf.Name
                    if ($ent.PSObject.Properties.Name -contains 'dependencies' -and $ent.dependencies) { $stack.Push($ent.dependencies) }
                }
            }
        }
    }
    return @($out.ToArray())
}

# ---- Is the app webpack/esbuild-bundled? --------------------------------------
# Reads only the asar HEADER (file names + sizes), not the blobs, so this is cheap
# even on a 200 MB archive. A bundled app has few package.json entries and one or
# more very large .js files; an unbundled one has hundreds of package.json entries
# and no single dominant script. The largest script's opening bytes are then checked
# for a bundler runtime marker, which turns the inference into an observation.
function Get-TcpkAsarBundleShape {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Dir)
    $shape = [ordered]@{
        AsarCount = 0; AsarBytes = 0; PackageJsonCount = 0
        JsCount = 0; LargestJsBytes = 0; LargestJsName = ''; BundlerMarker = ''
    }
    if (-not (Test-Path -LiteralPath $Dir)) { return $shape }
    $asars = @()
    try { $asars = @(Get-ChildItem -LiteralPath $Dir -Recurse -File -Filter '*.asar' -ErrorAction SilentlyContinue) } catch { }
    $bestPath = ''; $bestOff = 0; $bestSize = 0

    foreach ($asar in $asars) {
        $shape.AsarCount++
        $shape.AsarBytes += [int64]$asar.Length
        try {
            $fs = [IO.File]::OpenRead($asar.FullName)
            try {
                $hdr = New-Object byte[] 16
                if ($fs.Read($hdr, 0, 16) -lt 16) { continue }
                $headerObjSize = [BitConverter]::ToUInt32($hdr, 4)
                $jsonSize      = [BitConverter]::ToUInt32($hdr, 12)
                if ($jsonSize -le 0 -or ($jsonSize + 16) -gt $fs.Length) { continue }
                # Cast to int: jsonSize is UInt32, and UInt32 arithmetic would not bind to
                # Stream.Read(byte[], int, int) cleanly.
                $want = [int]$jsonSize
                $jb = New-Object byte[] $want
                $read = 0
                while ($read -lt $want) {
                    $n = $fs.Read($jb, $read, ($want - $read))
                    if ($n -le 0) { break }
                    $read += $n
                }
                if ($read -lt $want) { continue }
                $tree = ([Text.Encoding]::UTF8.GetString($jb, 0, $want)) | ConvertFrom-Json
                $base = 8 + $headerObjSize

                $stack = New-Object System.Collections.Generic.Stack[object]
                $stack.Push($tree)
                while ($stack.Count) {
                    $node = $stack.Pop()
                    if (-not $node.files) { continue }
                    foreach ($p in $node.files.PSObject.Properties) {
                        $child = $p.Value
                        if ($child.files) { $stack.Push($child); continue }
                        if ($p.Name -eq 'package.json') { $shape.PackageJsonCount++; continue }
                        # An ESM or CommonJS bundle is still a bundle. Matching only '*.js'
                        # meant an .mjs/.cjs output produced bundled=false and no warning.
                        # A .jsc carries no readable marker, so size alone has to speak for it.
                        if ($p.Name -notmatch '(?i)\.(js|mjs|cjs|jsc)$') { continue }
                        $shape.JsCount++
                        $sz = 0; try { $sz = [int64]$child.size } catch { }
                        if ($sz -gt $shape.LargestJsBytes) {
                            $shape.LargestJsBytes = $sz
                            $shape.LargestJsName = "$($p.Name)"
                        }
                        # Only a PACKED entry is addressable in this archive. An unpacked one
                        # has no usable offset, and reading offset 0 would sniff whichever file
                        # happens to sit first in the data section instead.
                        if ($sz -gt $bestSize -and $null -ne $child.offset -and $child.unpacked -ne $true) {
                            $bestPath = $asar.FullName
                            $bestOff = $base + [int64]$child.offset
                            $bestSize = $sz
                        }
                    }
                }
            } finally { $fs.Dispose() }
        } catch { }
    }

    # Read at most 64 KB of the single largest script to look for a bundler runtime.
    if ($bestPath -and $bestSize -gt 0) {
        try {
            $fs = [IO.File]::OpenRead($bestPath)
            try {
                $take = [int][Math]::Min(65536, $bestSize)
                if (($bestOff + $take) -le $fs.Length) {
                    $fs.Position = $bestOff
                    $buf = New-Object byte[] $take
                    $got = $fs.Read($buf, 0, $take)
                    if ($got -gt 0) {
                        $head = [Text.Encoding]::UTF8.GetString($buf, 0, $got)
                        if     ($head -match '__webpack_require__|webpackChunk|webpackBootstrap') { $shape.BundlerMarker = 'webpack' }
                        elseif ($head -match '__esbuild|esbuild-|__toCommonJS\s*=')               { $shape.BundlerMarker = 'esbuild' }
                        elseif ($head -match 'parcelRequire')                                      { $shape.BundlerMarker = 'parcel' }
                        elseif ($head -match 'System\.register\(|rollup')                          { $shape.BundlerMarker = 'rollup' }
                    }
                }
            } finally { $fs.Dispose() }
        } catch { }
    }
    return $shape
}

# ---------------------------------------------------------------------------
# npm supply-chain audit for a bundled Electron app (the Asar-tab "npm audit").
# Reuses the SHARED OSV engine for CVEs (no new CVE logic) and ADDS the one thing
# npm audit / CVE feeds miss: registry-flagged DEPRECATED / unmaintained packages.
# Online: OSV (npm) + the npm registry. Read-only, discovery-safe.
# ---------------------------------------------------------------------------

# Return the deprecation message for one (name,version) from the npm registry, or $null.
# One lightweight GET of the version manifest; fails closed (offline / 404 -> $null).
function Get-TcpkNpmDeprecation {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$Version, [int]$TimeoutSec = 4)
    try {
        $enc = "$Name".Replace('/', '%2f')   # scoped names: @scope/name -> @scope%2fname
        $url = "https://registry.npmjs.org/$enc/$Version"
        $r = Invoke-RestMethod -Uri $url -TimeoutSec $TimeoutSec -ErrorAction Stop
        if ($r.PSObject.Properties['deprecated'] -and "$($r.deprecated)".Trim()) { return "$($r.deprecated)".Trim() }
    } catch { }
    return $null
}

# Audit the npm packages bundled in a target's app.asar: OSV CVEs + deprecated flags.
# $Path may be an app.asar file or the install directory (we scan the dir for *.asar).
function Get-TcpkAsarNpmAudit {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path, [int]$MaxDeprecatedChecks = 60, [switch]$SkipDeprecated)
    $dir = $Path
    # Split-Path -LiteralPath + -Parent is an ambiguous parameter set on PS 5.1; use the .NET call.
    if (Test-Path -LiteralPath $Path -PathType Leaf) { $dir = [System.IO.Path]::GetDirectoryName($Path) }
    if (-not (Test-Path -LiteralPath $dir)) { return [ordered]@{ error = "path not found: $Path" } }
    # Three independent sources. The asar alone is not the inventory: native modules are
    # always unpacked to disk, and a webpack/esbuild build leaves no package.json at all.
    $script:TcpkNpmInventoryCapped = $false
    $fromAsar = @(Get-TcpkAsarNpmComponents -Dir $dir)
    $fromDisk = @()
    try { $fromDisk = @(Get-TcpkLooseNpmComponents -Dir $dir) } catch { }
    $shape = $null
    try { $shape = Get-TcpkAsarBundleShape -Dir $dir } catch { }

    # Merge real-file sources first so a verified package always wins over a lockfile
    # entry for the same name+version.
    $pkgs = New-Object System.Collections.Generic.List[object]
    $mseen = @{}
    foreach ($p in (@($fromAsar) + @($fromDisk))) {
        if (-not $p) { continue }
        $k = "$("$($p.Name)".ToLowerInvariant())|$($p.Version)"
        if ($mseen.ContainsKey($k)) { continue }
        $mseen[$k] = $true; $pkgs.Add($p)
    }
    $verifiedCount = $pkgs.Count

    # Lockfile fallback: only when the real-file inventory is too thin to be the truth.
    # Pulling it in unconditionally would add devDependencies that never shipped.
    $fromLock = @()
    $lockUsed = $false
    if ($verifiedCount -lt 20) {
        try { $fromLock = @(Get-TcpkLockfileNpmComponents -Dir $dir) } catch { }
        foreach ($p in $fromLock) {
            if (-not $p) { continue }
            $k = "$("$($p.Name)".ToLowerInvariant())|$($p.Version)"
            if ($mseen.ContainsKey($k)) { continue }
            $mseen[$k] = $true; $pkgs.Add($p); $lockUsed = $true
        }
    }
    $pkgs = @($pkgs.ToArray())

    # Is this inventory believable? A multi-megabyte asar that yields a handful of
    # packages means the dependency tree was bundled away, not that the app has three
    # dependencies. Saying nothing here is what made a blind scan read as a clean one.
    $blind = ''
    if ($shape) {
        $bundled = ($shape.BundlerMarker -ne '') -or ($shape.LargestJsBytes -ge 512000)
        if ($verifiedCount -lt 20 -and $shape.AsarBytes -ge 2097152 -and $bundled) {
            $how = if ($shape.BundlerMarker) { "$($shape.BundlerMarker) bundle detected" } else { 'single large bundled script' }
            $blind = ("Dependency inventory is INCOMPLETE. Only $verifiedCount package(s) were recoverable from " +
                "an app.asar of $([math]::Round($shape.AsarBytes / 1MB, 1)) MB ($how" +
                "$(if ($shape.LargestJsName) { ", largest script $($shape.LargestJsName) at $([math]::Round($shape.LargestJsBytes / 1MB, 1)) MB" })). " +
                'A bundler inlines every dependency into its output, leaving no package.json to read, so most ' +
                'shipped packages carry no recoverable name or version. TREAT A ZERO-VULNERABILITY RESULT AS ' +
                'UNKNOWN, NOT AS CLEAN: the packages were never queried.')
        }
    }

    if (-not $pkgs.Count) {
        # An asar that WAS parsed and simply held no package.json is a different fact from
        # "this is not an Electron app". Saying the latter about a measured multi-megabyte
        # archive is just wrong, and it is the reading that makes a blind result look benign.
        if ($shape -and $shape.AsarCount -gt 0) {
            $mb = [math]::Round($shape.AsarBytes / 1MB, 1)
            $mk = if ($shape.BundlerMarker) { ", bundler marker: $($shape.BundlerMarker)" } else { '' }
            $note = ("$($shape.AsarCount) asar archive(s) totalling $mb MB were parsed and contained no " +
                "package.json$mk. The dependency tree was inlined by the bundler, so no package name or " +
                'version is recoverable, and no node_modules or lockfile was found on disk. This result is ' +
                'UNKNOWN, NOT CLEAN: nothing was queried.')
            # Set blindspot too, so the GUI cannot take its "audit done" branch on this path.
            if (-not $blind) { $blind = $note }
        } else {
            $note = 'No npm packages found -- not an Electron app.asar, and no node_modules or lockfile on disk.'
            if ($blind) { $note = $blind }
        }
        return [ordered]@{ packages = 0; uniqueNames = 0; vulns = @(); deprecated = @(); deprecatedChecked = 0; deprecatedCapped = $false
            sources = @{}; unverified = 0; verifiedPackages = 0; inventoryCapped = [bool]$script:TcpkNpmInventoryCapped
            blindspot = $blind; shape = $shape; note = $note }
    }
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch { }
    $vulns = @()
    try { $vulns = @(Get-TcpkOsvMatches -Components $pkgs -Ecosystem 'npm') } catch { }

    # Tag each match with whether its package was read off a shipped file or only declared in
    # a lockfile. Without this the two render identically, and a CVE in a devDependency that
    # never shipped reads as a confirmed exposure. The OSV match carries Package and
    # ShippedVersion, which is exactly the dedup key used above.
    $verifiedKey = @{}
    foreach ($p in $pkgs) {
        $isVerified = $true
        if ($p.PSObject.Properties.Name -contains 'Verified') { $isVerified = [bool]$p.Verified }
        $verifiedKey["$("$($p.Name)".ToLowerInvariant())|$($p.Version)"] = $isVerified
    }
    foreach ($v in $vulns) {
        $vk = "$("$($v.Package)".ToLowerInvariant())|$($v.ShippedVersion)"
        $vv = $true
        if ($verifiedKey.ContainsKey($vk)) { $vv = $verifiedKey[$vk] }
        if ($v.PSObject.Properties.Name -contains 'Verified') { $v.Verified = $vv }
        else { $v | Add-Member -NotePropertyName 'Verified' -NotePropertyValue $vv -Force }
    }
    $deprecated = New-Object System.Collections.Generic.List[object]
    $checked = 0; $capped = $false
    if (-not $SkipDeprecated) {
        # Check the vulnerable packages first, then the rest, deduped by name, up to the cap.
        $vulnNames = @{}; foreach ($v in $vulns) { $vulnNames["$($v.Package)"] = $true }
        $ordered = @($pkgs | Sort-Object @{ E = { if ($vulnNames.ContainsKey("$($_.Name)")) { 0 } else { 1 } } }, @{ E = { "$($_.Name)" } })
        $seenName = @{}
        foreach ($p in $ordered) {
            $nm = "$($p.Name)"; if ($seenName.ContainsKey($nm)) { continue }; $seenName[$nm] = $true
            if ($checked -ge $MaxDeprecatedChecks) { $capped = $true; break }
            $checked++
            $msg = Get-TcpkNpmDeprecation -Name $nm -Version "$($p.Version)"
            if ($msg) { $deprecated.Add([pscustomobject]@{ Name = $nm; Version = "$($p.Version)"; Message = $msg }) }
        }
    }
    # Per-source counts, so the report can say WHERE the inventory came from rather than
    # presenting a lockfile-derived list as if it were read off the shipped files.
    $srcCounts = [ordered]@{}
    foreach ($p in $pkgs) {
        $s = "$($p.Source)"; if (-not $s) { $s = 'asar' }
        if (-not $srcCounts.Contains($s)) { $srcCounts[$s] = 0 }
        $srcCounts[$s]++
    }

    return [ordered]@{
        packages          = $pkgs.Count
        uniqueNames       = @($pkgs | Select-Object -ExpandProperty Name -Unique).Count
        vulns             = @($vulns)
        deprecated        = @($deprecated.ToArray())
        deprecatedChecked = $checked
        deprecatedCapped  = [bool]$capped
        sources           = $srcCounts
        unverified        = @($pkgs | Where-Object { $_.PSObject.Properties.Name -contains 'Verified' -and -not $_.Verified }).Count
        # Count read off shipped FILES, before any lockfile entries were merged in. The GUI
        # needs this: saying "only N recoverable" while N includes lockfile declarations
        # contradicts the report body and overstates what was actually observed.
        verifiedPackages  = $verifiedCount
        inventoryCapped   = [bool]$script:TcpkNpmInventoryCapped
        lockfileUsed      = [bool]$lockUsed
        blindspot         = $blind
        shape             = $shape
    }
}

# Render a Get-TcpkAsarNpmAudit result as an npm-audit-style text report. Pure/offline
# (no network) so it is unit-testable; the orchestrator above does the I/O.
function Format-TcpkNpmAuditReport {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Result, [string]$TargetName = '')
    $sb = New-Object System.Text.StringBuilder
    # External strings (OSV titles, registry deprecation notes) can carry emoji / non-ASCII;
    # the report is contractually ASCII-only, so fold anything outside printable ASCII to space.
    $asc = { param($s) ((("$s") -replace '[^\x20-\x7E]', ' ') -replace '\s{2,}', ' ').Trim() }
    [void]$sb.AppendLine('npm supply-chain audit -- bundled Electron dependencies')
    if ($TargetName) { [void]$sb.AppendLine("target: $TargetName") }
    [void]$sb.AppendLine('=' * 62)
    if ($Result.error) { [void]$sb.AppendLine("error: $($Result.error)"); return $sb.ToString() }
    # Wrap the blind-spot warning to the report width instead of emitting one long line.
    $wrap = {
        param($text, $width)
        $lines = New-Object System.Collections.Generic.List[string]
        $cur = ''
        foreach ($w in (("$text" -replace '\s+', ' ').Trim() -split ' ')) {
            if (-not $w) { continue }
            if ($cur -and ($cur.Length + 1 + $w.Length) -gt $width) { $lines.Add($cur); $cur = $w }
            else { $cur = if ($cur) { "$cur $w" } else { $w } }
        }
        if ($cur) { $lines.Add($cur) }
        return $lines
    }

    if (-not $Result.packages) { [void]$sb.AppendLine("$($Result.note)"); return $sb.ToString() }

    # The warning goes ABOVE the counts. Printed underneath, it reads as a footnote to a
    # clean result; printed first, it frames every number that follows.
    if ("$($Result.blindspot)") {
        [void]$sb.AppendLine('!! INCOMPLETE INVENTORY -- RESULTS BELOW ARE NOT A CLEAN BILL OF HEALTH !!')
        foreach ($l in (& $wrap $Result.blindspot 78)) { [void]$sb.AppendLine("   $l") }
        [void]$sb.AppendLine('')
    }

    if ($Result.inventoryCapped) {
        [void]$sb.AppendLine("bundled npm packages: AT LEAST $($Result.packages)  ($($Result.uniqueNames) unique names)")
        [void]$sb.AppendLine('  (enumeration hit its cap -- more packages exist; the counts below are a floor, not a total)')
    } else {
        [void]$sb.AppendLine("bundled npm packages: $($Result.packages)  ($($Result.uniqueNames) unique names)")
    }
    # $Result may be an ordered dictionary (the orchestrator) or a pscustomobject (a caller
    # that round-tripped it through JSON), so probe the value rather than call .Contains().
    $srcMap = $null
    try { $srcMap = $Result.sources } catch { }
    if ($srcMap -and @($srcMap.Keys).Count) {
        $lbl = @{ asar = 'inside app.asar'; unpacked = 'app.asar.unpacked'; node_modules = 'loose node_modules'; lockfile = 'lockfile (declared, presence not verified)' }
        $parts = @()
        foreach ($k in @($srcMap.Keys)) {
            $name = if ($lbl.ContainsKey("$k")) { $lbl["$k"] } else { "$k" }
            $parts += "$($srcMap[$k]) $name"
        }
        [void]$sb.AppendLine("  sources: " + ($parts -join '; '))
    }
    if ([int]$Result.unverified -gt 0) {
        [void]$sb.AppendLine("  NOTE: $($Result.unverified) package(s) come from a lockfile. A lockfile lists what was")
        [void]$sb.AppendLine("        declared at build time, including devDependencies, so a vulnerability in one")
        [void]$sb.AppendLine("        of these is a lead to confirm, not a confirmed shipped exposure.")
    }
    [void]$sb.AppendLine('')
    $order = @('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')
    $vulns = @($Result.vulns)
    if ($vulns.Count) {
        $counts = [ordered]@{}; foreach ($s in $order) { $counts[$s] = 0 }; $counts['OTHER'] = 0
        foreach ($v in $vulns) { $s = "$($v.Severity)".ToUpper(); if ($counts.Contains($s)) { $counts[$s]++ } else { $counts['OTHER']++ } }
        [void]$sb.AppendLine("VULNERABILITIES ($($vulns.Count))")
        $sorted = @($vulns | Sort-Object @{ E = { $i = [array]::IndexOf($order, "$($_.Severity)".ToUpper()); if ($i -lt 0) { 9 } else { $i } } })
        $lockVulns = 0
        foreach ($v in $sorted) {
            $fx = if ("$($v.FixedVersion)") { " -> fixed in $($v.FixedVersion)" } else { '' }
            # A match on a lockfile-declared package is a lead, not a shipped exposure. Mark
            # it on the line itself: a reader scanning the list will not cross-reference a
            # footnote before filing.
            $mk = ''
            if ($v.PSObject.Properties.Name -contains 'Verified' -and -not $v.Verified) {
                $mk = '  [LOCKFILE-DECLARED, PRESENCE NOT VERIFIED]'
                $lockVulns++
            }
            [void]$sb.AppendLine(("  [{0,-8}] {1} {2}  {3}  {4}{5}{6}" -f "$($v.Severity)".ToUpper(), $v.Package, $v.ShippedVersion, $v.Cve, (& $asc $v.Title), $fx, $mk))
        }
        $parts = @(); foreach ($s in $order) { if ($counts[$s]) { $parts += "$($counts[$s]) $($s.ToLower())" } }
        if ($counts['OTHER']) { $parts += "$($counts['OTHER']) other" }
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine("  $($vulns.Count) vulnerabilities: " + ($parts -join ', '))
        if ($lockVulns -gt 0) {
            [void]$sb.AppendLine("  of these, $($vulns.Count - $lockVulns) are in packages read off shipped files and $lockVulns are lockfile declarations.")
        }
    } else {
        [void]$sb.AppendLine('VULNERABILITIES: none found (matched live against OSV / GHSA).')
    }
    [void]$sb.AppendLine('')
    $dep = @($Result.deprecated)
    if ($dep.Count) {
        [void]$sb.AppendLine("DEPRECATED / UNMAINTAINED ($($dep.Count))")
        foreach ($d in $dep) {
            $m = (& $asc $d.Message); if ($m.Length -gt 96) { $m = $m.Substring(0, 96) + '...' }
            [void]$sb.AppendLine(("  {0} {1}  -- {2}" -f $d.Name, $d.Version, $m))
        }
    } else {
        [void]$sb.AppendLine('DEPRECATED: none among the packages checked.')
    }
    if ($Result.deprecatedCapped) {
        [void]$sb.AppendLine("  (deprecated status sampled for the first $($Result.deprecatedChecked) package names -- more packages exist)")
    } elseif ($Result.deprecatedChecked) {
        [void]$sb.AppendLine("  (deprecated status checked for $($Result.deprecatedChecked) package names)")
    }
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('CVEs matched live against OSV (npm / GHSA), for the packages listed above only.')
    [void]$sb.AppendLine('Inventory sources: package.json inside app.asar, app.asar.unpacked and loose')
    [void]$sb.AppendLine('node_modules on disk, and a lockfile when too little was recoverable from files.')
    [void]$sb.AppendLine('A full audit also covers native + .NET components and more sources.')
    return $sb.ToString()
}
