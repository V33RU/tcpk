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
    $candidates = if ($item -and -not $item.PSIsContainer) {
        @($item)
    } else {
        Get-ChildItem -LiteralPath $Path -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension.ToLowerInvariant() -in $codeExt }
    }

    $out = New-Object System.Collections.Generic.List[object]
    foreach ($f in $candidates) {
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
        $purl = "pkg:$purlType/$([uri]::EscapeDataString($name))@$verClean"

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
    $out | Sort-Object Name, Version
}
