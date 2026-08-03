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
        [object]$Profile = $null,
        [object[]]$CveMatches = @()
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
        tools     = @([ordered]@{ vendor = 'TCPK'; name = 'Thick Client Pentest Kit'; version = '2.7.1' })
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

    # CVE-LOOKUP PROVENANCE. An SBOM is a machine-readable artifact another pipeline ingests
    # as truth, and in CycloneDX an absent or empty vulnerabilities[] reads as "checked,
    # none". It must therefore never be produced by a lookup that did not complete. Record
    # what actually happened as metadata.properties, which is the spec's own extension point,
    # so a consumer can tell "verified clean" from "never asked" without reading the HTML.
    $cveState = 'not-attempted'
    try {
        if (Test-TcpkOsvRunComplete) { $cveState = 'complete' }
        elseif ((Get-TcpkOsvSession).Attempted) { $cveState = 'incomplete' }
    } catch { $cveState = 'unknown' }
    $props = New-Object System.Collections.Generic.List[object]
    $props.Add([ordered]@{ name = 'tcpk:cve-lookup'; value = $cveState })
    if ($cveState -eq 'incomplete') {
        $sess = $null; try { $sess = Get-TcpkOsvSession } catch { }
        if ($sess) {
            $props.Add([ordered]@{ name = 'tcpk:cve-lookup-failures';   value = "$($sess.Failures)" })
            $props.Add([ordered]@{ name = 'tcpk:cve-lookup-unanswered'; value = "$($sess.Incomplete)" })
            $props.Add([ordered]@{ name = 'tcpk:cve-lookup-truncated';  value = "$([bool]$sess.Truncated)" })
        }
        $props.Add([ordered]@{ name = 'tcpk:cve-lookup-note'
                               value = 'An online CVE lookup was requested but did not complete for every component. An empty or short vulnerabilities[] in this document is UNKNOWN, not verified clean.' })
    }
    if (-not $bom.metadata.Contains('properties')) { $bom.metadata['properties'] = @() }
    $bom.metadata['properties'] = @($props.ToArray())

    # CycloneDX vulnerabilities array: TCPK's own CVE matches, linked to the affected
    # component's bom-ref so the SBOM is self-contained (findings + inventory agree).
    # Grouped by CVE id; a group with no confirmed-Vulnerable match (native Present /
    # PossiblyEmbedded) is marked analysis.state = in_triage (version unconfirmed).
    if ($CveMatches -and @($CveMatches).Count) {
        $sevMap = @{ CRITICAL = 'critical'; HIGH = 'high'; MEDIUM = 'medium'; LOW = 'low'; INFO = 'info' }
        $vulns = New-Object System.Collections.Generic.List[object]
        foreach ($grp in (@($CveMatches) | Group-Object Cve)) {
            $ms = @($grp.Group); $first = $ms[0]
            $seen = @{}; $refList = New-Object System.Collections.Generic.List[object]
            foreach ($m in $ms) {
                $hit = $inventory | Where-Object { $_.Name -eq $m.Package -and "$($_.Version)" -eq "$($m.ShippedVersion)" } | Select-Object -First 1
                if (-not $hit -and $m.File) { $hit = $inventory | Where-Object { (Split-Path $_.Path -Leaf) -eq $m.File } | Select-Object -First 1 }
                if (-not $hit) { $hit = $inventory | Where-Object { $_.Name -eq $m.Package } | Select-Object -First 1 }
                $r = if ($hit) { "$($hit.BomRef)" } else { "$($m.Package)@$($m.ShippedVersion)" }
                if (-not $seen.ContainsKey($r)) { $seen[$r] = $true; $refList.Add([ordered]@{ ref = $r }) }
            }
            $sev = if ($sevMap.ContainsKey("$($first.Severity)")) { $sevMap["$($first.Severity)"] } else { 'unknown' }
            $cwes = @(); foreach ($c in @($first.Cwe)) { if ("$c" -match '(\d+)') { $cwes += [int]$matches[1] } }
            $desc = "$($first.Title)"; if ($first.Summary) { $desc = "$desc -- $($first.Summary)" }
            $confirmed = @($ms | Where-Object { $_.Status -eq 'Vulnerable' }).Count -gt 0
            $v = [ordered]@{
                id      = "$($first.Cve)"
                source  = [ordered]@{ name = 'NVD'; url = "https://nvd.nist.gov/vuln/detail/$($first.Cve)" }
                ratings = @([ordered]@{ severity = $sev; method = 'other' })
            }
            if ($cwes.Count) { $v.cwes = @($cwes) }
            $v.description = $desc
            if (-not $confirmed) { $v.analysis = [ordered]@{ state = 'in_triage'; detail = 'Version unconfirmed (native / statically-linked); verify the embedding or native build.' } }
            $v.affects = @($refList.ToArray())
            $vulns.Add([pscustomobject]$v)
        }
        if ($vulns.Count) { $bom['vulnerabilities'] = @($vulns.ToArray()) }
    }

    $json = $bom | ConvertTo-Json -Depth 8
    $dir = Split-Path -Parent $OutFile
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    Set-Content -LiteralPath $OutFile -Value $json -Encoding UTF8
    Write-TcpkInfo "SBOM written: $OutFile ($($cdxComps.Count) components)"
    return $OutFile
}
