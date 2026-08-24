#requires -Version 5.1
# OSV (osv.dev) ONLINE CVE enrichment -- the ONLY networked CVE path in TCPK, and strictly
# opt-in (Get-TcpkCveMatches -OnlineCve / Invoke-TcpkAudit -OnlineCve). TCPK is offline by
# default; when enabled this sends ONLY public component identifiers (package name + version
# + ecosystem) to https://api.osv.dev -- never findings, secrets, file contents, or the target
# name. It fails CLOSED: any network or parse error returns nothing and caches nothing, so the
# next run retries rather than reading back a fabricated clean entry. Failing closed is correct,
# but it is not silent by itself: TCPK ships NO offline CVE data, so a failed query means the
# component was never checked against any source, and zero CVE findings then looks exactly like
# an app with no vulnerable dependencies. The gap is registered via
# Add-TcpkScanSkip 'CveLookupFailed' so Test-TcpkScanCoverage states it in the report.

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

# QUERY STATUS. A component may only be cached as "checked, none" when OSV actually
# ANSWERED for it. Without this, any failure wrote every queried component back as clean
# with a fresh timestamp, and for the next 7 days the freshness test skipped the network
# entirely -- not even printing the warning again. The report then stated the components
# "were matched live against OSV", and Export-TcpkSbom wrote an empty vulnerabilities[]
# into the CycloneDX BOM. A silent, self-perpetuating false negative on the only CVE path
# in the tool, in a machine-readable artifact a client's pipeline ingests as truth.
#
# Two of the three ways to get there need no network failure at all: the MaxDetail cap and
# a single per-vuln detail fetch that 404s or times out both used to leave the affected
# component looking clean on a fully successful HTTP 200 run.
$script:TcpkOsvLastQuery = $null
$script:TcpkOsvSession   = $null

function Reset-TcpkOsvQueryStatus {
    [CmdletBinding()] param()
    $script:TcpkOsvLastQuery = [pscustomobject]@{
        Ok        = $false
        Reason    = ''
        Truncated = $false
        Queried   = 0
        # Cache keys OSV gave a complete answer for. ONLY these may be written back.
        Answered  = (New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase))
    }
}

function Get-TcpkOsvQueryStatus {
    [CmdletBinding()] param()
    if (-not $script:TcpkOsvLastQuery) { Reset-TcpkOsvQueryStatus }
    $script:TcpkOsvLastQuery
}

# Audit-wide roll-up across every ecosystem queried in one run. Invoke-TcpkAudit reads this
# to decide whether the report may claim the components were matched live.
function Reset-TcpkOsvSession {
    [CmdletBinding()] param()
    $script:TcpkOsvSession = [pscustomobject]@{
        Attempted  = $false
        Failures   = 0
        Truncated  = $false
        Incomplete = 0        # components queried but not definitively answered
        Reasons    = (New-Object 'System.Collections.Generic.List[string]')
    }
}

function Get-TcpkOsvSession {
    [CmdletBinding()] param()
    if (-not $script:TcpkOsvSession) { Reset-TcpkOsvSession }
    $script:TcpkOsvSession
}

# $true only when every OSV query this run completed and answered for every component.
# The report's "matched live against OSV" wording is gated on this, not on the -OnlineCve
# switch, which only says the user ASKED for a lookup.
function Test-TcpkOsvRunComplete {
    [CmdletBinding()] param()
    $s = Get-TcpkOsvSession
    return ([bool]$s.Attempted -and $s.Failures -eq 0 -and -not $s.Truncated -and $s.Incomplete -eq 0)
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
    Reset-TcpkOsvQueryStatus
    $st = Get-TcpkOsvQueryStatus

    $comp = @($Components | Where-Object { "$($_.Name)" -and "$($_.Version)" })
    if (-not $comp.Count) { $st.Ok = $true; return }
    $st.Queried = $comp.Count

    $queries = @($comp | ForEach-Object { @{ package = @{ name = "$($_.Name)"; ecosystem = $Ecosystem }; version = "$($_.Version)" } })
    $body = @{ queries = $queries } | ConvertTo-Json -Depth 6
    $resp = $null
    try {
        $resp = Invoke-RestMethod -Uri $script:TcpkOsvBatchUri -Method Post -Body $body `
            -ContentType 'application/json' -TimeoutSec $TimeoutSec -ErrorAction Stop
    } catch {
        # Ok stays $false, Answered stays empty -> the caller caches NOTHING and the next
        # run retries instead of reading a fabricated clean entry.
        $st.Reason = "$($_.Exception.Message)"
        # A warning on the console is not enough. It does not reach the HTML/Excel report,
        # and the report is where someone decides the dependencies are fine. With no CVE
        # findings emitted, that report is identical to one for an app with no vulnerable
        # packages. Register the gap so Test-TcpkScanCoverage states it as a coverage fact.
        try { Add-TcpkScanSkip -Kind 'CveLookupFailed' -ItemPath "OSV querybatch ($($queries.Count) component(s)): $($st.Reason)" } catch { }
        Write-Warning "OSV online query failed ($($st.Reason)); nothing will be cached, so the next run retries. The dependency surface is UNTESTED for this run, not clean."
        return
    }

    # results[] aligns by index to queries[]; collect unique vuln id -> first matching component,
    # and remember which vuln ids belong to which component so a component can be marked
    # answered only when every one of ITS vulns was successfully enriched.
    $results  = @($resp.results)
    $idToComp = @{}
    $compIds  = @{}
    for ($i = 0; $i -lt $comp.Count; $i++) {
        $compIds[$i] = New-Object 'System.Collections.Generic.List[string]'
        if ($i -ge $results.Count) { continue }   # short response -> this component was not answered
        foreach ($v in @($results[$i].vulns)) {
            $vid = "$($v.id)"; if (-not $vid) { continue }
            $compIds[$i].Add($vid)
            if (-not $idToComp.ContainsKey($vid)) { $idToComp[$vid] = $comp[$i] }
        }
    }

    # Enrich. A vuln that is skipped -- by the cap or by a failed detail fetch -- is recorded,
    # because its component can no longer be called clean.
    $failed = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $out = New-Object 'System.Collections.Generic.List[object]'
    $n = 0
    $warnedCap = $false
    foreach ($vid in @($idToComp.Keys)) {
        if ($n -ge $MaxDetail) {
            # continue, not break: every remaining id must still be marked unenriched so its
            # component is excluded from the cache. Costs no network.
            if (-not $warnedCap) {
                $warnedCap = $true
                $st.Truncated = $true
                Write-Warning "OSV: reached the $MaxDetail detail-lookup cap; the affected components will NOT be cached as clean."
            }
            [void]$failed.Add($vid)
            continue
        }
        $n++
        $detail = $null
        try { $detail = Invoke-RestMethod -Uri "$script:TcpkOsvVulnUri/$vid" -TimeoutSec $TimeoutSec -ErrorAction Stop }
        catch { [void]$failed.Add($vid); continue }
        if (-not $detail) { [void]$failed.Add($vid); continue }
        $cmp = $idToComp[$vid]
        $out.Add( (ConvertFrom-TcpkOsvVuln -Vuln $detail -Package "$($cmp.Name)" -ShippedVersion "$($cmp.Version)") )
    }

    # A component is ANSWERED when OSV returned a result slot for it and none of its vulns
    # was dropped. Zero vulns with a result slot is a genuine "checked, none" and caches.
    for ($i = 0; $i -lt $comp.Count; $i++) {
        if ($i -ge $results.Count) { continue }
        $anyFailed = $false
        foreach ($vid in $compIds[$i]) { if ($failed.Contains($vid)) { $anyFailed = $true; break } }
        if ($anyFailed) { continue }
        [void]$st.Answered.Add((Get-TcpkOsvCacheKey -Ecosystem $Ecosystem -Name "$($comp[$i].Name)" -Version "$($comp[$i].Version)"))
    }
    $st.Ok = $true
    $out
}

# ----- local cache (so repeat -OnlineCve runs are fast and work offline once warmed) -----
# Stored at %LOCALAPPDATA%\TCPK\cve-cache.json, keyed by ecosystem|name|version. Entries carry
# a fetchedUtc timestamp; reads past the TTL are treated as a miss. Cache IO fails open (a
# broken/locked cache never blocks a query).
$script:TcpkOsvCacheTtlDays = 7

function Get-TcpkOsvCachePath {
    $base = $env:LOCALAPPDATA
    if (-not $base) { $base = Get-TcpkWorkDir -Kind 'vulndb' }
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
    try { Save-TcpkJson -Value ([pscustomobject]$Cache) -Path $p -Depth 8 } catch { }
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
        $sess = Get-TcpkOsvSession
        $sess.Attempted = $true
        $freshOut = @(Get-TcpkOsvQueryNet -Components @($toQuery.ToArray()) -Ecosystem $Ecosystem -MaxDetail $MaxDetail -TimeoutSec $TimeoutSec)
        $st = Get-TcpkOsvQueryStatus

        if (-not $st.Ok) {
            $sess.Failures++
            if ($st.Reason) { $sess.Reasons.Add("$Ecosystem`: $($st.Reason)") }
        } else {
            if ($st.Truncated) { $sess.Truncated = $true }
            # Write back ONLY components OSV definitively answered for. An unanswered one is
            # left absent from the cache so the next run queries it again, instead of being
            # stamped clean and skipped for the whole TTL.
            $stamp = [DateTimeOffset]::UtcNow.ToString('o')
            $wrote = 0
            foreach ($c in $toQuery) {
                $key = Get-TcpkOsvCacheKey -Ecosystem $Ecosystem -Name "$($c.Name)" -Version "$($c.Version)"
                if (-not $st.Answered.Contains($key)) { $sess.Incomplete++; continue }
                $cm = @($freshOut | Where-Object { "$($_.Package)".ToLowerInvariant() -eq "$($c.Name)".ToLowerInvariant() -and "$($_.ShippedVersion)" -eq "$($c.Version)" })
                $cache[$key] = [pscustomobject]@{ fetchedUtc = $stamp; matches = $cm }
                $wrote++
            }
            if ($wrote -gt 0 -and -not $NoCache) { Save-TcpkOsvCache -Cache $cache }
        }
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
        # Only claim "queried, none" when the lookup actually COMPLETED. -OnlineCve means the
        # user asked for a query, not that one succeeded; saying "returned no advisories"
        # after a failed or truncated run is a positive claim about something that never ran.
        $complete = $true
        try { $complete = [bool](Test-TcpkOsvRunComplete) } catch { $complete = $true }
        if ($complete) {
            try { $Finding.Evidence = "$($Finding.Evidence) | OSV: queried, no advisories returned for this version" } catch { }
            try { $Finding.Description = [regex]::Replace("$($Finding.Description)", $hintRx, "OSV was queried for this runtime version and returned no advisories (the bundled version may be newer than OSV's data); the version-gap finding stands on its own -- verify against electronjs.org/releases.") } catch { }
        } else {
            try { $Finding.Evidence = "$($Finding.Evidence) | OSV: lookup did NOT complete -- advisory status unknown" } catch { }
            try { $Finding.Description = [regex]::Replace("$($Finding.Description)", $hintRx, "The OSV lookup did NOT complete this run (network failure, or the per-run detail cap was reached), so the advisory status of this runtime version is UNKNOWN rather than clean. Re-run with network access, or check electronjs.org/releases directly.") } catch { }
        }
    }
    # else: offline -- keep the "Run with -OnlineCve" hint as-is.
    $Finding
}
