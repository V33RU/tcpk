function Get-TcpkRequestIdCandidates {
<#
.SYNOPSIS
    Parse an HTTP request and list its object-identifier locations (path / query / JSON body /
    header / cookie). Offline and ungated: it sends nothing, it only enumerates targets an
    IDOR probe could mutate. Feed a candidate to Invoke-TcpkIdorProbe -Location.

.DESCRIPTION
    The offline planning step for the replay/IDOR engine. Accepts a raw HTTP request (file or
    text), a (TLS-decrypted) pcap, or a hand-specified request, canonicalizes it, and reports
    every location whose key looks like an id (id/uid/user/order/...) or whose value is
    id-shaped (integer / GUID / ObjectId / long handle). Deterministic parse, no network.

.PARAMETER RequestFile / RequestText
    A raw HTTP request (Burp/proxy paste) as a file or a string.

.PARAMETER FromPcap / TsharkPath / KeylogFile / RsaKeyFile / RequestIndex
    Pull the request from a capture (uses tshark; TLS keys decrypt first). RequestIndex picks
    which HTTP request in the capture.

.PARAMETER Method / Url / Header / Body
    Hand-specify a request instead.

.OUTPUTS
    [TcpkFinding] -- replay.id-candidates.
#>
    [CmdletBinding()]
    param(
        [string]$RequestFile,
        [string]$RequestText,
        [string]$FromPcap,
        [string]$TsharkPath,
        [string]$KeylogFile,
        [string]$RsaKeyFile,
        [int]$RequestIndex = 0,
        [ValidateSet('http', 'https')][string]$Scheme,
        [string]$Method,
        [string]$Url,
        [string[]]$Header,
        [string]$Body
    )
    $spec = Resolve-TcpkRequestSpec -RequestFile $RequestFile -RequestText $RequestText -FromPcap $FromPcap `
        -Tshark $TsharkPath -Keylog $KeylogFile -RsaKey $RsaKeyFile -RequestIndex $RequestIndex -Scheme $Scheme `
        -Method $Method -Url $Url -Header $Header -Body $Body

    $locs = @(Get-TcpkIdLocations -Spec $spec)
    if ($locs.Count -eq 0) {
        return (New-TcpkFinding -Module 'discovery' -RuleId 'replay.no-id-candidates' -Severity 'INFO' `
                -Confidence 'Inferred' -Title 'No id-bearing locations found in the request' `
                -Evidence "$($spec.Method) $($spec.Path)" `
                -Description 'No path/query/body/header/cookie value looked like an object identifier. IDOR testing needs an id to mutate.')
    }
    $desc = $locs | ForEach-Object { "$($_.Kind):$($_.Key)=$($_.Value)" }
    New-TcpkFinding -Module 'discovery' -RuleId 'replay.id-candidates' -Severity 'INFO' `
        -Confidence 'Confirmed' -Cwe @('CWE-639') `
        -Title "$($locs.Count) id-bearing location(s) in $($spec.Method) $($spec.Path)" `
        -Evidence ($desc -join ' | ') `
        -Description 'Deterministic parse of the request. Each location is an object reference an IDOR probe can swap. Run Invoke-TcpkIdorProbe -Location <kind:key> -SwapId <other-id>.'
}
