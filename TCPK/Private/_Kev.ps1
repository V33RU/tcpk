# CISA Known Exploited Vulnerabilities (KEV) -- the authoritative "actively exploited in the
# wild" catalog, and the single strongest CVE prioritization signal. One cacheable pull per
# session; FAILS CLOSED (returns an empty set with no network) so it never blocks an audit or
# turns a real match into a false-clean. Consumed by Get-TcpkCveMatches (sets match.Kev), which
# the HTML report (KEV badge) and exploit plan already render.

$script:TcpkKevCache = $null

function Get-TcpkKevSet {
    [CmdletBinding()]
    param([switch]$Force)
    if ($script:TcpkKevCache -and -not $Force) { return , $script:TcpkKevCache }
    $set = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $url = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
    try {
        $old = $ProgressPreference
        $ProgressPreference = 'SilentlyContinue'
        try { $resp = Invoke-RestMethod -Uri $url -TimeoutSec 25 -ErrorAction Stop }
        finally { $ProgressPreference = $old }
        foreach ($v in @($resp.vulnerabilities)) { if ($v.cveID) { [void]$set.Add("$($v.cveID)".Trim()) } }
    } catch {
        Write-Verbose "TCPK KEV fetch failed (fails closed, no enrichment): $($_.Exception.Message)"
    }
    $script:TcpkKevCache = $set
    return , $set   # comma: prevent PS from unrolling the HashSet into an Object[] (drops the comparer)
}
