function Export-TcpkSbom {
<#
.SYNOPSIS
    Export a CycloneDX 1.5 SBOM (software bill of materials) of bundled components.

.DESCRIPTION
    Inventories every PE (EXE/DLL) shipped under -Path and emits a CycloneDX JSON
    SBOM: name, version, publisher, SHA-256 hash, and a purl per component. This
    is a standard deliverable for compliance and feeds CVE/dependency tracking.

.PARAMETER Path
    Install directory (or single file).

.PARAMETER OutFile
    Path to write the .cdx.json SBOM.

.PARAMETER Profile
    Optional Get-TcpkTargetProfile object (drives metadata.component = the app).

.OUTPUTS
    [string] the OutFile path.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$OutFile,
        [object]$Profile = $null
    )

    $components = New-Object System.Collections.Generic.List[object]
    foreach ($pe in Get-TcpkPeFiles -Path $Path) {
        $vi = $null
        try { $vi = $pe.VersionInfo } catch { $vi = $null }
        if (-not $vi) { try { $vi = (Get-Item -LiteralPath $pe.FullName).VersionInfo } catch { } }

        $name = [IO.Path]::GetFileNameWithoutExtension($pe.Name)
        $ver  = if ($vi -and $vi.FileVersion) { "$($vi.FileVersion)".Trim() } else { '0.0.0' }
        $pub  = if ($vi -and $vi.CompanyName) { "$($vi.CompanyName)".Trim() } else { '' }

        $sha = ''
        try { $sha = (Get-FileHash -LiteralPath $pe.FullName -Algorithm SHA256 -ErrorAction Stop).Hash.ToLower() } catch { }

        $managed = $false
        try { $info = Read-TcpkPe -Path $pe.FullName; if ($info -and $info.PSObject.Properties['IsManaged']) { $managed = [bool]$info.IsManaged } } catch { }
        $purlType = if ($managed) { 'nuget' } else { 'generic' }
        $verClean = $ver
        $mv = [regex]::Match($ver, '^[\d]+(\.[\d]+){0,3}')
        if ($mv.Success) { $verClean = $mv.Value }
        $purl = "pkg:$purlType/$([uri]::EscapeDataString($name))@$verClean"

        $comp = [ordered]@{
            type        = 'library'
            'bom-ref'   = "$name@$ver"
            name        = $name
            version     = $ver
            purl        = $purl
        }
        if ($pub) { $comp.publisher = $pub; $comp.author = $pub }
        if ($sha) { $comp.hashes = @([ordered]@{ alg = 'SHA-256'; content = $sha }) }
        $comp.properties = @(
            [ordered]@{ name = 'tcpk:file';     value = $pe.FullName }
            [ordered]@{ name = 'tcpk:managed';  value = "$managed" }
        )
        $components.Add([pscustomobject]$comp)
    }

    # metadata.component = the application itself
    $appComp = $null
    if ($Profile) {
        $appComp = [ordered]@{
            type      = 'application'
            'bom-ref' = "$($Profile.Name)@$($Profile.Version)"
            name      = "$($Profile.Name)"
            version   = "$($Profile.Version)"
        }
        if ($Profile.Publisher) { $appComp.publisher = "$($Profile.Publisher)" }
    }

    $meta = [ordered]@{
        timestamp = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        tools     = @([ordered]@{ vendor = 'TCPK'; name = 'Thick Client Pentest Kit'; version = '0.0.1' })
    }
    if ($appComp) { $meta.component = $appComp }

    $bom = [ordered]@{
        bomFormat    = 'CycloneDX'
        specVersion  = '1.5'
        serialNumber = "urn:uuid:$([guid]::NewGuid().ToString())"
        version      = 1
        metadata     = $meta
    }
    # NOTE: assigning a List[object] via @(...) INSIDE the [ordered]@{} literal
    # throws "Argument types do not match" in PS 5.1 -- set it via the indexer instead.
    $bom['components'] = @($components.ToArray())

    $json = $bom | ConvertTo-Json -Depth 8
    $dir = Split-Path -Parent $OutFile
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    Set-Content -LiteralPath $OutFile -Value $json -Encoding UTF8
    Write-TcpkInfo "SBOM written: $OutFile ($($components.Count) components)"
    return $OutFile
}
