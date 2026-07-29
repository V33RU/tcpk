# Request-replay + IDOR engine internals for Invoke-TcpkReplay / Invoke-TcpkIdorProbe
# and the live-probe side of Invoke-TcpkJwtAttack. The heart of the false-positive
# discipline is here: acceptance is decided by BODY comparison against known-good and
# known-bad baselines, never by HTTP status alone.
#
# System.Net.Http auto-loads in PS7 but not 5.1.
Add-Type -AssemblyName System.Net.Http -ErrorAction SilentlyContinue

# ---------------------------------------------------------- response snapshot ----

# sha256 hex of a NORMALIZED response body: UTF8, trimmed, CRLF->LF, and (only when the
# operator opts in) volatile fields blanked. Default is an exact normalized hash, so two
# responses match only when their meaningful content is identical.
function Get-TcpkNormalizedBodyHash {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Body, [string[]]$VolatileFieldRegex)
    if ($null -eq $Body -or $Body.Length -eq 0) { return 'sha256:empty' }
    $text = [Text.Encoding]::UTF8.GetString($Body)
    $text = $text.Trim()
    $text = $text.Replace("`r`n", "`n")
    if ($VolatileFieldRegex) {
        foreach ($rx in $VolatileFieldRegex) { try { $text = [regex]::Replace($text, $rx, '<v>') } catch {} }
    }
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $h = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($text))
        return 'sha256:' + [BitConverter]::ToString($h).Replace('-', '').ToLowerInvariant()
    } finally { $sha.Dispose() }
}

# Low-level sender shared by the JWT probe and the request replayer. Arbitrary method +
# headers + body. Never follows redirects (a 401 must not be masked by a login redirect).
# Returns the canonical snapshot: @{Status;Len;Hash;BodyHead;Redirect}. Status 0 on a
# transport error. Body preview and any headers are credential-redacted.
function New-TcpkHttpSnapshot {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Method,
        [Parameter(Mandatory)][string]$Url,
        [hashtable]$Headers,
        [byte[]]$Body,
        [string[]]$VolatileFieldRegex,
        [int]$TimeoutSec = 15
    )
    $handler = [System.Net.Http.HttpClientHandler]::new()
    $handler.AllowAutoRedirect = $false
    $client = [System.Net.Http.HttpClient]::new($handler)
    $client.Timeout = [TimeSpan]::FromSeconds($TimeoutSec)
    try {
        $req = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::new($Method), $Url)
        if ($null -ne $Body -and $Body.Length -gt 0) {
            $req.Content = [System.Net.Http.ByteArrayContent]::new($Body)
        }
        if ($Headers) {
            foreach ($k in $Headers.Keys) {
                $name = [string]$k; $val = [string]$Headers[$k]
                if ($name -ieq 'Content-Length') { continue }         # HttpClient computes it
                if ($name -ieq 'Host') { try { $req.Headers.Host = $val } catch {}; continue }
                if ($name -imatch '^Content-') {
                    if ($req.Content) { [void]$req.Content.Headers.TryAddWithoutValidation($name, $val) }
                } else {
                    [void]$req.Headers.TryAddWithoutValidation($name, $val)
                }
            }
        }
        $resp = $client.SendAsync($req).GetAwaiter().GetResult()
        $bytes = $resp.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult()
        $status = [int]$resp.StatusCode
        $preview = ''
        if ($bytes.Length -gt 0) {
            $s = [Text.Encoding]::UTF8.GetString($bytes)
            if ($s.Length -gt 4096) { $s = $s.Substring(0, 4096) }
            $s = Get-TcpkRedact -Text $s
            $preview = $s.Substring(0, [Math]::Min(256, $s.Length))
        }
        $redirect = $null
        if ($status -ge 300 -and $status -lt 400 -and $resp.Headers.Location) { $redirect = "$($resp.Headers.Location)" }
        return @{
            Status   = $status
            Len      = $bytes.Length
            Hash     = Get-TcpkNormalizedBodyHash -Body $bytes -VolatileFieldRegex $VolatileFieldRegex
            BodyHead = $preview
            Redirect = $redirect
        }
    } catch {
        return @{ Status = 0; Len = 0; Hash = 'sha256:error'; BodyHead = "<transport-error: $(("$($_.Exception.Message)" -split "`n")[0])>"; Redirect = $null }
    } finally { $client.Dispose() }
}

# ------------------------------------------------------- acceptance predicate ----

# THE single acceptance decision for every live auth-bypass check. A candidate response
# is "accepted" (the protected resource was actually served to a request that should not
# get it) ONLY when: status is 2xx/3xx, AND the body is NOT the reject/error page, AND the
# body matches the known-good accepted page. Status alone is never proof -- a 200 carrying
# a JSON error, a login page, or a WAF block is rejected because its body != accept body.
function Test-TcpkResponseAccepted {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Candidate,
        [Parameter(Mandatory)][hashtable]$AcceptRef,
        [Parameter(Mandatory)][hashtable]$RejectRef,
        [switch]$FuzzyBodyMatch
    )
    if ($Candidate.Status -eq 0) { return $false }
    if ($Candidate.Status -lt 200 -or $Candidate.Status -ge 400) { return $false }
    if ($Candidate.Hash -eq $RejectRef.Hash) { return $false }        # looks like the reject page
    if ($Candidate.Hash -eq $AcceptRef.Hash) { return $true }         # exact protected content (default)
    if ($FuzzyBodyMatch) {
        $den = [Math]::Max($AcceptRef.Len, 1)
        $lenDelta = [Math]::Abs($Candidate.Len - $AcceptRef.Len) / [double]$den
        if ($lenDelta -le 0.02 -and $Candidate.Hash -ne $RejectRef.Hash) { return $true }
    }
    return $false                                                     # 2xx but neither accept nor reject = inconclusive
}

# Structured comparison used by the replay/IDOR decision tables.
function Compare-TcpkHttpResponse {
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$A, [Parameter(Mandatory)][hashtable]$B, [hashtable]$SoftNotFound)
    $equiv = ($A.Hash -eq $B.Hash)
    $den = [Math]::Max($B.Len, 1)
    $material = (-not $equiv) -and (([Math]::Abs($A.Len - $B.Len) / [double]$den) -gt 0.02)
    $soft = $false
    if ($SoftNotFound) { $soft = ($A.Hash -eq $SoftNotFound.Hash) }
    return @{ Equivalent = $equiv; MaterialDiff = $material; IsSoftNotFound = $soft }
}
