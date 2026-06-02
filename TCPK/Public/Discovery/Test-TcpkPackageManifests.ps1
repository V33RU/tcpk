function Test-TcpkPackageManifests {
<#
.SYNOPSIS
    A34. Parse non-.deps.json package manifests (packages.config / pom.xml /
    package.json / *-lock) and flag bundled dependencies with known CVEs.

.DESCRIPTION
    Complements Test-TcpkDependencyCves (which reads .NET *.deps.json). This walks
    the shipped source/package manifests an app may carry:

      - packages.config            (legacy NuGet)   <package id="X" version="Y"/>
      - *.csproj / *.vbproj        (SDK PackageReference)  <PackageReference Include="X" Version="Y"/>
      - pom.xml                    (Maven)          <dependency><artifactId>..<version>..
      - package.json               (npm)            "dependencies": { "X": "^Y" }
      - package-lock.json          (npm lockfile)   resolved versions

    Each name@version is matched against the offline CVE list in
    Data\secrets.json (cve_packages). A match is Confidence='Confirmed' (the
    manifest states the exact version); the catalog is .NET-centric, so npm/Maven
    coverage grows as the catalog does.

.PARAMETER Path
    Folder (recursive) preferred.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $cves = (Get-TcpkData).cve_packages

    $isDir = (Get-Item -LiteralPath $Path).PSIsContainer
    $files = if ($isDir) {
        Get-ChildItem -LiteralPath $Path -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object {
                $_.Name -ieq 'packages.config' -or
                $_.Name -ieq 'pom.xml' -or
                $_.Name -ieq 'package.json' -or
                $_.Name -ieq 'package-lock.json' -or
                $_.Extension -ieq '.csproj' -or $_.Extension -ieq '.vbproj'
            }
    } else { @(Get-Item -LiteralPath $Path) }

    # Normalize an npm/Maven range to a plain version (strip ^ ~ >= v etc.)
    function _CleanVer([string]$v) { if (-not $v) { return $v }; ($v -replace '^[^\d]*','').Trim() }

    $deps = New-Object 'System.Collections.Generic.List[object]'
    foreach ($f in $files) {
        $eco = 'unknown'
        try {
            $name = $f.Name.ToLowerInvariant()
            if ($name -eq 'packages.config' -or $f.Extension -ieq '.csproj' -or $f.Extension -ieq '.vbproj') {
                $eco = 'nuget'
                [xml]$x = Get-Content -LiteralPath $f.FullName -Raw -ErrorAction Stop
                foreach ($p in $x.SelectNodes('//*[local-name()="package"]'))         { if ($p.id)      { $deps.Add([pscustomobject]@{ Name=$p.id;      Ver=$p.version; Eco=$eco; File=$f.FullName }) } }
                foreach ($p in $x.SelectNodes('//*[local-name()="PackageReference"]')) { if ($p.Include) { $deps.Add([pscustomobject]@{ Name=$p.Include; Ver=$p.Version; Eco=$eco; File=$f.FullName }) } }
            }
            elseif ($name -eq 'pom.xml') {
                $eco = 'maven'
                [xml]$x = Get-Content -LiteralPath $f.FullName -Raw -ErrorAction Stop
                foreach ($d in $x.SelectNodes('//*[local-name()="dependency"]')) {
                    $aid = ($d.ChildNodes | Where-Object { $_.LocalName -eq 'artifactId' }).InnerText
                    $ver = ($d.ChildNodes | Where-Object { $_.LocalName -eq 'version' }).InnerText
                    if ($aid) { $deps.Add([pscustomobject]@{ Name=$aid; Ver=$ver; Eco=$eco; File=$f.FullName }) }
                }
            }
            elseif ($name -eq 'package.json' -or $name -eq 'package-lock.json') {
                $eco = 'npm'
                $j = Get-Content -LiteralPath $f.FullName -Raw -ErrorAction Stop | ConvertFrom-Json
                foreach ($sec in 'dependencies','devDependencies','optionalDependencies') {
                    if ($j.$sec) {
                        foreach ($pn in $j.$sec.PSObject.Properties) {
                            $v = if ($pn.Value -is [string]) { $pn.Value } elseif ($pn.Value.version) { $pn.Value.version } else { '' }
                            $deps.Add([pscustomobject]@{ Name=$pn.Name; Ver=$v; Eco=$eco; File=$f.FullName })
                        }
                    }
                }
                if ($j.packages) {   # package-lock v2/v3
                    foreach ($pn in $j.packages.PSObject.Properties) {
                        if (-not $pn.Name) { continue }
                        $leaf = ($pn.Name -split '/')[-1]
                        if ($leaf -and $pn.Value.version) { $deps.Add([pscustomobject]@{ Name=$leaf; Ver=$pn.Value.version; Eco=$eco; File=$f.FullName }) }
                    }
                }
            }
        } catch { continue }
    }

    $seen = @{}
    foreach ($d in $deps) {
        $ver = _CleanVer $d.Ver
        if (-not $d.Name -or -not $ver) { continue }
        $dedup = "$($d.Name.ToLowerInvariant())@$ver@$($d.File)"
        if ($seen.ContainsKey($dedup)) { continue }
        $seen[$dedup] = $true

        foreach ($c in $cves) {
            if ($c.name -eq $d.Name -and (Test-TcpkSemVerLt -A $ver -B $c.below)) {
                New-TcpkFinding -Module 'static' -RuleId "pkgmanifest.cve.$($d.Name)" `
                    -Severity $c.severity -Confidence 'Confirmed' `
                    -Title "$($d.Eco): $($d.Name) $ver - $($c.cve)" `
                    -File $d.File -Evidence "declared $($d.Name)@$ver ($($d.Eco)); <$($c.below) required" `
                    -Cwe @('CWE-937','CWE-1104') `
                    -Description $c.summary `
                    -Fix "Upgrade $($d.Name) to >= $($c.below)."
            }
        }
    }
}
