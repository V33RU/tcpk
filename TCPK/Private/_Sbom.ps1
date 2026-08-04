# Map each shipped runtime DLL basename -> its true NuGet package id + version, read
# from *.deps.json (the `targets` section lists each package's runtime files). This lets
# the SBOM emit accurate `pkg:nuget/<id>@<version>` purls (a DLL's FileVersion is NOT the
# package version), making sbom.cdx.json consumable by external SBOM-CVE scanners
# (Dependency-Track / Grype / OSV) and aligning it with TCPK's own CVE matcher.
function Get-TcpkDepsRuntimeMap {
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Dir)
    $map = @{}
    if (-not (Test-Path -LiteralPath $Dir)) { return $map }
    foreach ($f in (Get-ChildItem -LiteralPath $Dir -Recurse -File -Filter '*.deps.json' -ErrorAction SilentlyContinue)) {
        $d = $null; try { $d = Get-Content -LiteralPath $f.FullName -Raw | ConvertFrom-Json } catch { continue }
        if (-not $d.targets) { continue }
        foreach ($tfm in $d.targets.PSObject.Properties) {
            foreach ($lib in $tfm.Value.PSObject.Properties) {
                if ($lib.Name -notmatch '^(.+)/([^/]+)$') { continue }
                $pkg = $matches[1]; $ver = $matches[2]
                $rt = $lib.Value.runtime
                if (-not $rt) { continue }
                foreach ($rf in $rt.PSObject.Properties) {
                    $bn = ([IO.Path]::GetFileName($rf.Name)).ToLowerInvariant()
                    if ($bn -and -not $map.ContainsKey($bn)) { $map[$bn] = [pscustomobject]@{ Package = $pkg; Version = $ver } }
                }
            }
        }
    }
    return $map
}

function Get-TcpkSbomComponents {
<#
.SYNOPSIS
    Inventory every shipped PE (EXE/DLL) under -Path as SBOM component objects.

.DESCRIPTION
    Shared building block: walks the install tree, reads version info + SHA-256 +
    managed/native flag, and builds a purl per component. Used by Export-TcpkSbom
    (to emit CycloneDX JSON) AND by the HTML/Excel report exporters (to render the
    SBOM section/sheet) so the expensive hashing runs once.

.PARAMETER Path
    Install directory (or single file).

.OUTPUTS
    [pscustomobject] per component: Name, Version, Publisher, Sha256, Managed,
    Purl, Type, BomRef, Path (full file path on disk).

.NOTES
    Only actual EXECUTABLE / LIBRARY code components belong in an SBOM. Images
    (.png/.ico), fonts, text, json, xml, etc. are NOT software components and are
    excluded. Every candidate is validated as a real PE binary (via Read-TcpkPe),
    so a mislabeled file (e.g. a .png renamed to .dll) is dropped too.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path
    )

    # Code / library PE file types worth inventorying (all are PE-format binaries).
    $codeExt = @('.exe', '.dll', '.sys', '.winmd', '.node', '.pyd', '.ocx', '.cpl', '.drv')

    $item = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
    # Get-TcpkChildItemSafe, not a raw -Recurse: this walk gets the same depth cap, reparse
    # guard and unreadable-directory accounting every other TCPK walk gets, so a truncated
    # inventory is reported instead of silently shipping a short SBOM.
    #
    # The extension list stays local rather than delegating to Get-TcpkPeFiles, which filters
    # to 5 extensions. The SBOM inventories 9, and .winmd/.ocx/.cpl/.drv are real shipped
    # components that would silently vanish from the CycloneDX output.
    $candidates = if ($item -and -not $item.PSIsContainer) {
        @($item)
    } else {
        @(Get-TcpkChildItemSafe -Path $Path -File |
            Where-Object { $_.Extension.ToLowerInvariant() -in $codeExt })
    }

    # deps.json runtime map (managed components get a precise pkg:nuget/<id>@<version> purl)
    $invDir = if ($item -and $item.PSIsContainer) { $Path } elseif ($item) { Split-Path -Parent $item.FullName } else { $null }
    $depsMap = if ($invDir) { Get-TcpkDepsRuntimeMap -Dir $invDir } else { @{} }

    $out = New-Object System.Collections.Generic.List[object]
    # A full PE parse plus a SHA-256 over every shipped binary is one of the most expensive
    # loops in the tool, and it runs AFTER the check loop, where nothing used to bound it.
    # Invoke-TcpkAudit now arms the budget around this stage via _RunStage, so poll it here
    # and emit a heartbeat: an SBOM build over a large install tree used to be both unbounded
    # and completely silent.
    $sbIdx = 0
    $sbStopped = $false
    foreach ($f in $candidates) {
        if (Test-TcpkCheckBudgetExpired) { $sbStopped = $true; break }
        $sbIdx++
        Write-TcpkHeartbeat -Component 'sbom' -Index $sbIdx -Total $candidates.Count -Current $f.Name -CurrentBytes $f.Length
        # Validate it is a REAL PE binary. Read-TcpkPe returns $null for anything
        # that is not a well-formed PE -- so renamed images/resources are dropped,
        # and we reuse the parse result for the managed/native classification.
        $pe = Read-TcpkPe -Path $f.FullName
        if (-not $pe) { continue }

        $vi = $null
        try { $vi = $f.VersionInfo } catch { }
        if (-not $vi) { try { $vi = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($f.FullName) } catch { } }

        $name = [IO.Path]::GetFileNameWithoutExtension($f.Name)
        $ver  = if ($vi -and $vi.FileVersion) { "$($vi.FileVersion)".Trim() } else { '0.0.0' }
        $pub  = if ($vi -and $vi.CompanyName) { "$($vi.CompanyName)".Trim() } else { '' }

        $sha = ''
        try { $sha = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256 -ErrorAction Stop).Hash.ToLower() } catch { }

        # managed (.NET) assemblies import mscoree.dll -> classify with a nuget purl
        $managed = (@($pe.Imports) -contains 'mscoree.dll')
        $purlType = if ($managed) { 'nuget' } else { 'generic' }
        $verClean = $ver
        $mv = [regex]::Match($ver, '^[\d]+(\.[\d]+){0,3}')
        if ($mv.Success) { $verClean = $mv.Value }

        # Prefer the TRUE NuGet package id + version from deps.json (the DLL FileVersion
        # is not the package version). Falls back to filename + FileVersion when the DLL
        # is not declared in any deps.json (e.g. the app's own binaries / native libs).
        $dep = if ($managed) { $depsMap[$f.Name.ToLowerInvariant()] } else { $null }
        if ($dep) {
            $name     = $dep.Package
            $ver      = $dep.Version
            $verClean = $dep.Version
            $purl     = "pkg:nuget/$([uri]::EscapeDataString($dep.Package))@$([uri]::EscapeDataString($dep.Version))"
        } else {
            $purl = "pkg:$purlType/$([uri]::EscapeDataString($name))@$verClean"
        }

        $out.Add([pscustomobject]@{
            Name      = $name
            Version   = $ver
            Publisher = $pub
            Sha256    = $sha
            Managed   = $managed
            Purl      = $purl
            Type      = 'library'
            BomRef    = "$name@$ver"
            Path      = $f.FullName
        })
    }
    # A short SBOM and a complete one look identical downstream, and a missing component reads
    # as "this product does not ship that library". Record the shortfall so coverage says so.
    if ($sbStopped) {
        Add-TcpkScanSkip -Kind 'BudgetStopped' -ItemPath ("SBOM inventory (after $sbIdx of $($candidates.Count) binaries)")
    }
    $out | Sort-Object Name, Version
}
