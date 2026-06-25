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
# nothing on any failure (fail-closed). This is the raw network core; callers normally use the
# cached front Get-TcpkOsvMatches below.
function Get-TcpkOsvQueryNet {
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

# ----- local cache (so repeat -OnlineCve runs are fast and work offline once warmed) -----
# Stored at %LOCALAPPDATA%\TCPK\cve-cache.json, keyed by ecosystem|name|version. Entries carry
# a fetchedUtc timestamp; reads past the TTL are treated as a miss. Cache IO fails open (a
# broken/locked cache never blocks a query).
$script:TcpkOsvCacheTtlDays = 7

function Get-TcpkOsvCachePath {
    $base = $env:LOCALAPPDATA
    if (-not $base) { $base = $env:TEMP }
    $dir = Join-Path $base 'TCPK'
    if (-not (Test-Path -LiteralPath $dir)) {
        try { New-Item -ItemType Directory -Path $dir -Force -ErrorAction Stop | Out-Null } catch { }
    }
    Join-Path $dir 'cve-cache.json'
}

function Get-TcpkOsvCache {
    $p = Get-TcpkOsvCachePath
    $h = @{}
    if (Test-Path -LiteralPath $p) {
        try {
            $j = Get-Content -LiteralPath $p -Raw -ErrorAction Stop | ConvertFrom-Json
            foreach ($prop in $j.PSObject.Properties) { $h[$prop.Name] = $prop.Value }
        } catch { $h = @{} }
    }
    $h
}

function Save-TcpkOsvCache {
    [CmdletBinding()] param([Parameter(Mandatory)]$Cache)
    $p = Get-TcpkOsvCachePath
    try { ([pscustomobject]$Cache) | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $p -Encoding UTF8 -ErrorAction Stop } catch { }
}

function Get-TcpkOsvCacheKey { param([string]$Ecosystem, [string]$Name, [string]$Version)
    "$Ecosystem|$("$Name".ToLowerInvariant())|$Version"
}

# CACHED front (the normal entry point). Serves fresh-enough components from the local cache and
# only hits the network (Get-TcpkOsvQueryNet) for the misses, then writes the misses back.
# -NoCache forces a live query (still updates the cache).
function Get-TcpkOsvMatches {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$Components,
        [string]$Ecosystem = 'NuGet',
        [int]$MaxDetail = 60,
        [int]$TimeoutSec = 20,
        [switch]$NoCache
    )
    $comp = @($Components | Where-Object { "$($_.Name)" -and "$($_.Version)" })
    if (-not $comp.Count) { return }

    $cache = @{}
    if (-not $NoCache) { try { $cache = Get-TcpkOsvCache } catch { $cache = @{} } }

    $cachedOut = New-Object 'System.Collections.Generic.List[object]'
    $toQuery   = New-Object 'System.Collections.Generic.List[object]'
    foreach ($c in $comp) {
        $key = Get-TcpkOsvCacheKey -Ecosystem $Ecosystem -Name "$($c.Name)" -Version "$($c.Version)"
        $entry = $null
        if (-not $NoCache -and $cache.ContainsKey($key)) { $entry = $cache[$key] }
        $fresh = $false
        if ($entry -and $entry.fetchedUtc) {
            try { $fresh = (([DateTimeOffset]::UtcNow - [DateTimeOffset]::Parse("$($entry.fetchedUtc)")).TotalDays -lt $script:TcpkOsvCacheTtlDays) } catch { $fresh = $false }
        }
        if ($fresh) {
            foreach ($m in @($entry.matches)) { if ($m) { $cachedOut.Add($m) } }
        } else {
            $toQuery.Add($c)
        }
    }

    $freshOut = @()
    if ($toQuery.Count) {
        $freshOut = @(Get-TcpkOsvQueryNet -Components @($toQuery.ToArray()) -Ecosystem $Ecosystem -MaxDetail $MaxDetail -TimeoutSec $TimeoutSec)
        # write each queried component's matches back (empty array = "checked, none" = still cached)
        $stamp = [DateTimeOffset]::UtcNow.ToString('o')
        foreach ($c in $toQuery) {
            $key = Get-TcpkOsvCacheKey -Ecosystem $Ecosystem -Name "$($c.Name)" -Version "$($c.Version)"
            $cm = @($freshOut | Where-Object { "$($_.Package)".ToLowerInvariant() -eq "$($c.Name)".ToLowerInvariant() -and "$($_.ShippedVersion)" -eq "$($c.Version)" })
            $cache[$key] = [pscustomobject]@{ fetchedUtc = $stamp; matches = $cm }
        }
        if (-not $NoCache) { Save-TcpkOsvCache -Cache $cache }
    }

    # .ToArray() not @($list) -- @() on a generic List throws "Argument types do not match" (PS 5.1).
    $cachedOut.ToArray() + @($freshOut)
}

# Rewrite the electron.outdated-runtime finding text to reflect what the OSV check ACTUALLY did,
# instead of always showing the static "Run with -OnlineCve to enumerate..." hint. Three states:
#   (a) OnlineCve ran + OSV returned electron advisories -> list the concrete CVE/GHSA IDs
#   (b) OnlineCve ran + OSV returned nothing for this version -> say "queried, none" (do NOT tell
#       the user to run a flag they already ran -- this was the mis-report)
#   (c) offline (no OnlineCve) -> leave the hint; it is the correct next step.
# Pure logic (no network); mutates and returns the finding so it is unit-testable. The hint is the
# trailing sentence, so the regex runs to end-of-line (the old [^.]*\. wrongly stopped at the dot
# inside "electron@41.2.0").
function Update-TcpkRuntimeCveText {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Finding,
        $CveMatches = @(),
        [bool]$OnlineCve = $false
    )
    if (-not $Finding) { return $Finding }
    $hintRx = 'Run with -OnlineCve.*'
    $eCves = @($CveMatches | Where-Object { "$($_.Package)".ToLowerInvariant() -eq 'electron' -and "$($_.Cve)" -match '^(?i)(CVE|GHSA)' })
    if ($eCves.Count) {
        $ids = @($eCves | ForEach-Object { "$($_.Cve)" } | Select-Object -Unique)
        $idList = ($ids -join ', ')
        try { $Finding.Evidence = "$($Finding.Evidence) | OSV advisories ($($ids.Count)): $idList" } catch { }
        try { $Finding.Description = [regex]::Replace("$($Finding.Description)", $hintRx, "Matching OSV advisories ($($ids.Count)): $idList.") } catch { }
    }
    elseif ($OnlineCve) {
        try { $Finding.Evidence = "$($Finding.Evidence) | OSV: queried, no advisories returned for this version" } catch { }
        try { $Finding.Description = [regex]::Replace("$($Finding.Description)", $hintRx, "OSV was queried for this runtime version and returned no advisories (the bundled version may be newer than OSV's data); the version-gap finding stands on its own -- verify against electronjs.org/releases.") } catch { }
    }
    # else: offline -- keep the "Run with -OnlineCve" hint as-is.
    $Finding
}
