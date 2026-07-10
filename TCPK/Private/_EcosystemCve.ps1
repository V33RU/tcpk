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
