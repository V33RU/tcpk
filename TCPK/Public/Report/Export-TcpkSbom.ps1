function Export-TcpkSbom {
<#
.SYNOPSIS
    Export a CycloneDX 1.5 SBOM (software bill of materials) of bundled components.

.DESCRIPTION
    Inventories every PE (EXE/DLL) shipped under -Path and emits a CycloneDX JSON
    SBOM: name, version, publisher, SHA-256 hash, and a purl per component. This
    is a standard deliverable for compliance and feeds CVE/dependency tracking.

.PARAMETER Path
    Install directory (or single file). The PE inventory is built from this.

.PARAMETER Components
    Pre-built component inventory from Get-TcpkSbomComponents. Pass this when the
    caller has already inventoried the tree (e.g. to share it with the HTML/Excel
    reports) so the SHA-256 hashing isn't repeated.

.PARAMETER OutFile
    Path to write the .cdx.json SBOM.

.PARAMETER Profile
    Optional Get-TcpkTargetProfile object (drives metadata.component = the app).

.OUTPUTS
    [string] the OutFile path.
#>
    [CmdletBinding(DefaultParameterSetName = 'FromPath')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'FromPath')][string]$Path,
        [Parameter(Mandatory, ParameterSetName = 'FromComponents')][object[]]$Components,
        [Parameter(Mandatory)][string]$OutFile,
        [object]$Profile = $null
    )

    $inventory = if ($PSCmdlet.ParameterSetName -eq 'FromComponents') { @($Components) } else { @(Get-TcpkSbomComponents -Path $Path) }

    # NB: local name must differ from the [object[]]$Components parameter -- PS vars
    # are case-insensitive, so reusing $components would coerce this List into a
    # fixed-size array (the parameter's type) and .Add() would throw.
    $cdxComps = New-Object System.Collections.Generic.List[object]
    foreach ($pe in $inventory) {
        $comp = [ordered]@{
            type        = "$($pe.Type)"
            'bom-ref'   = "$($pe.BomRef)"
            name        = "$($pe.Name)"
            version     = "$($pe.Version)"
            purl        = "$($pe.Purl)"
        }
        if ($pe.Publisher) { $comp.publisher = "$($pe.Publisher)"; $comp.author = "$($pe.Publisher)" }
        if ($pe.Sha256)    { $comp.hashes = @([ordered]@{ alg = 'SHA-256'; content = "$($pe.Sha256)" }) }
        $comp.properties = @(
            [ordered]@{ name = 'tcpk:file';     value = "$($pe.Path)" }
            [ordered]@{ name = 'tcpk:managed';  value = "$($pe.Managed)" }
        )
        $cdxComps.Add([pscustomobject]$comp)
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
        tools     = @([ordered]@{ vendor = 'TCPK'; name = 'Thick Client Pentest Kit'; version = '0.1.0' })
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
    $bom['components'] = @($cdxComps.ToArray())

    $json = $bom | ConvertTo-Json -Depth 8
    $dir = Split-Path -Parent $OutFile
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    Set-Content -LiteralPath $OutFile -Value $json -Encoding UTF8
    Write-TcpkInfo "SBOM written: $OutFile ($($cdxComps.Count) components)"
    return $OutFile
}
