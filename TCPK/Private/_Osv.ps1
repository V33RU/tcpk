#requires -Version 5.1
# OSV (osv.dev) ONLINE CVE enrichment -- the ONLY networked CVE path in TCPK, and strictly
# opt-in (Get-TcpkCveMatches -OnlineCve / Invoke-TcpkAudit -OnlineCve). TCPK is offline by
# default; when enabled this sends ONLY public component identifiers (package name + version
# + ecosystem) to https://api.osv.dev -- never findings, secrets, file contents, or the target
# name. It fails CLOSED: any network/parse error returns nothing and the caller keeps the
# offline catalog result.

$script:TcpkOsvBatchUri = 'https://api.osv.dev/v1/querybatch'
$script:TcpkOsvVulnUri  = 'https://api.osv.dev/v1/vulns'

# PURE: map one OSV vulnerability record to a match object matching Get-TcpkCveMatches' shape.
# Kept side-effect-free so it can be unit-tested without the network.
function ConvertFrom-TcpkOsvVuln {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Vuln, [string]$Package, [string]$ShippedVersion)

    # Prefer a CVE alias as the displayed id; fall back to the native OSV id (e.g. GHSA-...).
    $id = "$($Vuln.id)"
    $cve = @($Vuln.aliases) | Where-Object { "$_" -match '^(?i)CVE-\d' } | Select-Object -First 1
    if ($cve) { $id = "$cve" }

    # First 'fixed' event across any affected range = the fixed version.
    $fixed = $null
    foreach ($aff in @($Vuln.affected)) {
        foreach ($rng in @($aff.ranges)) {
            foreach ($ev in @($rng.events)) { if ($ev.fixed) { $fixed = "$($ev.fixed)"; break } }
            if ($fixed) { break }
        }
        if ($fixed) { break }
    }

    # Severity band: GHSA records carry database_specific.severity (CRITICAL/HIGH/...). CVSS
    # vectors are present too but we do not recompute a v3 score here -> leave UNKNOWN if absent.
    $sev = 'UNKNOWN'
    if ($Vuln.database_specific -and $Vuln.database_specific.severity) {
        $sev = ("$($Vuln.database_specific.severity)").ToUpperInvariant()
    }
    if ($sev -notin 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW') { $sev = 'UNKNOWN' }

    $summary = "$($Vuln.summary)"; if (-not $summary) { $summary = "$($Vuln.details)" }
    if ($summary.Length -gt 300) { $summary = $summary.Substring(0, 297) + '...' }

    $refs = @(@($Vuln.references) | ForEach-Object { "$($_.url)" } | Where-Object { $_ } | Select-Object -First 4)
    if (-not $refs.Count) { $refs = @("https://osv.dev/vulnerability/$($Vuln.id)") }

    [pscustomobject]@{
        Cve = $id; Package = $Package; ShippedVersion = $ShippedVersion; FixedVersion = $fixed
        Status = 'Vulnerable'; Confidence = 'Confirmed (OSV)'; Severity = $sev
        Area = 'Dependency (OSV)'; Cwe = @(); Title = "$($Vuln.summary)"; Summary = $summary
        Kev = $false; References = $refs; Exploit = $null; File = '(deps.json / OSV)'; Source = 'osv.dev'
    }
}

# NETWORK (opt-in). Batch-query OSV for the given components, then fetch per-vuln detail and
# map. $Components = @( @{ Name=..; Version=..; File=.. } ). Returns mapped match objects, or
# nothing on any failure (fail-closed).
function Get-TcpkOsvMatches {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$Components,
        [string]$Ecosystem = 'NuGet',
        [int]$MaxDetail = 60,
        [int]$TimeoutSec = 20
    )
    $comp = @($Components | Where-Object { "$($_.Name)" -and "$($_.Version)" })
    if (-not $comp.Count) { return }

    $queries = @($comp | ForEach-Object { @{ package = @{ name = "$($_.Name)"; ecosystem = $Ecosystem }; version = "$($_.Version)" } })
    $body = @{ queries = $queries } | ConvertTo-Json -Depth 6
    $resp = $null
    try {
        $resp = Invoke-RestMethod -Uri $script:TcpkOsvBatchUri -Method Post -Body $body `
            -ContentType 'application/json' -TimeoutSec $TimeoutSec -ErrorAction Stop
    } catch {
        Write-Warning "OSV online query failed ($($_.Exception.Message)); keeping the offline catalog result only."
        return
    }

    # results[] aligns by index to queries[]; collect unique vuln id -> first matching component.
    $results = @($resp.results)
    $idToComp = @{}
    for ($i = 0; $i -lt $results.Count -and $i -lt $comp.Count; $i++) {
        foreach ($v in @($results[$i].vulns)) {
            $vid = "$($v.id)"; if (-not $vid) { continue }
            if (-not $idToComp.ContainsKey($vid)) { $idToComp[$vid] = $comp[$i] }
        }
    }
    if (-not $idToComp.Count) { return }

    $out = New-Object 'System.Collections.Generic.List[object]'
    $n = 0
    foreach ($vid in @($idToComp.Keys)) {
        if ($n -ge $MaxDetail) {
            Write-Warning "OSV: reached the $MaxDetail detail-lookup cap; remaining vulns not enriched this run."
            break
        }
        $n++
        $detail = $null
        try { $detail = Invoke-RestMethod -Uri "$script:TcpkOsvVulnUri/$vid" -TimeoutSec $TimeoutSec -ErrorAction Stop } catch { continue }
        if (-not $detail) { continue }
        $cmp = $idToComp[$vid]
        $out.Add( (ConvertFrom-TcpkOsvVuln -Vuln $detail -Package "$($cmp.Name)" -ShippedVersion "$($cmp.Version)") )
    }
    $out
}
