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
                                    if (-not $seen.ContainsKey($k)) { $seen[$k] = $true; $out.Add([pscustomobject]@{ Name = "$($pj.name)"; Version = "$($pj.version)"; File = $asar.Name }) }
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
    $pkgs = @(Get-TcpkAsarNpmComponents -Dir $dir)
    if (-not $pkgs.Count) {
        return [ordered]@{ packages = 0; uniqueNames = 0; vulns = @(); deprecated = @(); deprecatedChecked = 0; deprecatedCapped = $false
            note = 'No bundled npm packages found -- not an Electron app.asar, or its node_modules were not packed into the asar.' }
    }
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch { }
    $vulns = @()
    try { $vulns = @(Get-TcpkOsvMatches -Components $pkgs -Ecosystem 'npm') } catch { }
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
    return [ordered]@{
        packages          = $pkgs.Count
        uniqueNames       = @($pkgs | Select-Object -ExpandProperty Name -Unique).Count
        vulns             = @($vulns)
        deprecated        = @($deprecated.ToArray())
        deprecatedChecked = $checked
        deprecatedCapped  = [bool]$capped
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
    if (-not $Result.packages) { [void]$sb.AppendLine("$($Result.note)"); return $sb.ToString() }
    [void]$sb.AppendLine("bundled npm packages: $($Result.packages)  ($($Result.uniqueNames) unique names)")
    [void]$sb.AppendLine('')
    $order = @('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')
    $vulns = @($Result.vulns)
    if ($vulns.Count) {
        $counts = [ordered]@{}; foreach ($s in $order) { $counts[$s] = 0 }; $counts['OTHER'] = 0
        foreach ($v in $vulns) { $s = "$($v.Severity)".ToUpper(); if ($counts.Contains($s)) { $counts[$s]++ } else { $counts['OTHER']++ } }
        [void]$sb.AppendLine("VULNERABILITIES ($($vulns.Count))")
        $sorted = @($vulns | Sort-Object @{ E = { $i = [array]::IndexOf($order, "$($_.Severity)".ToUpper()); if ($i -lt 0) { 9 } else { $i } } })
        foreach ($v in $sorted) {
            $fx = if ("$($v.FixedVersion)") { " -> fixed in $($v.FixedVersion)" } else { '' }
            [void]$sb.AppendLine(("  [{0,-8}] {1} {2}  {3}  {4}{5}" -f "$($v.Severity)".ToUpper(), $v.Package, $v.ShippedVersion, $v.Cve, (& $asc $v.Title), $fx))
        }
        $parts = @(); foreach ($s in $order) { if ($counts[$s]) { $parts += "$($counts[$s]) $($s.ToLower())" } }
        if ($counts['OTHER']) { $parts += "$($counts['OTHER']) other" }
        [void]$sb.AppendLine('')
        [void]$sb.AppendLine("  $($vulns.Count) vulnerabilities: " + ($parts -join ', '))
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
    [void]$sb.AppendLine('CVEs matched live against OSV (npm / GHSA). This is a focused view of the bundled')
    [void]$sb.AppendLine('node_modules; a full audit also covers native + .NET components + more sources.')
    return $sb.ToString()
}
