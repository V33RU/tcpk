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
# Returns the canonical snapshot:
#   @{ Status; Len; Hash; BodyHead; Redirect; ServerDate; ElapsedMs }
# Status 0 on a transport error. Body preview and any headers are credential-redacted.
# ServerDate is the response Date header as UTC [datetime], or $null when absent; it is
# the only clock a vendor cannot dispute, so expiry checks compare against it and never
# against the local machine. ElapsedMs is wall-clock for the send, including the error
# path. Every key is present on BOTH the success and the transport-error return, so a
# caller never has to test for existence.
#
# This is the ONLY place a socket is opened. Anything a new check needs off the wire
# (headers, timing, full body) has to be added here, and additively: three call sites
# read the existing keys positionally by name and must keep working untouched.
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
    # Started before the try so the error path can still report how long we waited.
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
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

        # The SERVER's own clock, not ours. An expiry check that compares a token's exp
        # against the local clock proves nothing: the operator's machine may be skewed,
        # and the vendor's first response is always "your clock was wrong". Reading the
        # Date header off the same response that accepted the token removes that defence,
        # because the server is then the only clock in the argument. $null when the header
        # is absent (it is a SHOULD in RFC 9110, not a MUST), and callers must treat a
        # missing value as "cannot prove", never as "not expired".
        $serverDate = $null
        try {
            if ($resp.Headers.Date -and $resp.Headers.Date.HasValue) {
                $serverDate = $resp.Headers.Date.Value.UtcDateTime
            }
        } catch { $serverDate = $null }

        $sw.Stop()
        return @{
            Status     = $status
            Len        = $bytes.Length
            Hash       = Get-TcpkNormalizedBodyHash -Body $bytes -VolatileFieldRegex $VolatileFieldRegex
            BodyHead   = $preview
            Redirect   = $redirect
            ServerDate = $serverDate
            ElapsedMs  = [int]$sw.ElapsedMilliseconds
        }
    } catch {
        $sw.Stop()
        return @{ Status = 0; Len = 0; Hash = 'sha256:error'; BodyHead = "<transport-error: $(("$($_.Exception.Message)" -split "`n")[0])>"; Redirect = $null; ServerDate = $null; ElapsedMs = [int]$sw.ElapsedMilliseconds }
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

# ------------------------------------------------------------- request model ----

# A value looks like an object identifier: integer, GUID, Mongo ObjectId (24 hex), or a
# long hex / base64url handle. Deliberately excludes short words so 'edit'/'view' are not ids.
function Test-TcpkIsIdShaped {
    [CmdletBinding()] param([AllowEmptyString()][string]$Value)
    if ([string]::IsNullOrEmpty($Value)) { return $false }
    if ($Value -match '^\d+$') { return $true }
    if ($Value -match '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') { return $true }
    if ($Value -match '^[0-9a-fA-F]{24}$') { return $true }
    if ($Value -match '^[0-9a-fA-F]{16,}$') { return $true }
    if ($Value.Length -ge 16 -and $Value -match '^[A-Za-z0-9_\-]+$' -and $Value -match '\d') { return $true }
    return $false
}

$script:TcpkIdKeyRx = '(?i)(^|_)(id|uid|guid|user|account|acct|order|invoice|doc|file|record|obj|customer|profile)(_?id)?$'

# Ordered, case-insensitive header dictionary (HTTP header names are case-insensitive).
function New-TcpkHeaderDict {
    return New-Object System.Collections.Specialized.OrderedDictionary ([StringComparer]::OrdinalIgnoreCase)
}

# Rebuild the absolute URL from a spec's parts (after a path/query mutation).
function Get-TcpkSpecUrl {
    [CmdletBinding()] param([Parameter(Mandatory)][hashtable]$Spec)
    $auth = $Spec.Host
    $defaultPort = if ($Spec.Scheme -eq 'https') { 443 } else { 80 }
    if ($Spec.Port -and $Spec.Port -ne $defaultPort) { $auth = "$($Spec.Host):$($Spec.Port)" }
    $q = ''
    if ($Spec.Query -and $Spec.Query.Count -gt 0) {
        $pairs = foreach ($k in $Spec.Query.Keys) { "$k=" + [Uri]::EscapeDataString([string]$Spec.Query[$k]) }
        $q = '?' + ($pairs -join '&')
    }
    return "$($Spec.Scheme)://$auth$($Spec.Path)$q"
}

# Canonicalize any request source into the spec hashtable every replay helper consumes.
function New-TcpkRequestSpec {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Method,
        [Parameter(Mandatory)][string]$Url,
        [string[]]$Header,
        [string]$Body
    )
    $u = [Uri]$Url
    $headers = New-TcpkHeaderDict
    $cookies = New-TcpkHeaderDict
    if ($Header) {
        foreach ($h in $Header) {
            $i = $h.IndexOf(':')
            if ($i -lt 1) { continue }
            $name = $h.Substring(0, $i).Trim(); $val = $h.Substring($i + 1).Trim()
            $headers[$name] = $val
        }
    }
    if ($headers.Contains('Cookie')) {
        foreach ($c in ("$($headers['Cookie'])" -split ';')) {
            $kv = $c.Trim(); $e = $kv.IndexOf('=')
            if ($e -ge 1) { $cookies[$kv.Substring(0, $e).Trim()] = $kv.Substring($e + 1).Trim() }
        }
    }
    $query = New-Object System.Collections.Specialized.OrderedDictionary
    if ($u.Query.Length -gt 1) {
        foreach ($pair in ($u.Query.TrimStart('?') -split '&')) {
            if (-not $pair) { continue }
            $e = $pair.IndexOf('=')
            if ($e -ge 0) { $query[[Uri]::UnescapeDataString($pair.Substring(0, $e))] = [Uri]::UnescapeDataString($pair.Substring($e + 1)) }
            else { $query[[Uri]::UnescapeDataString($pair)] = '' }
        }
    }
    $bodyBytes = if ($null -ne $Body -and $Body.Length -gt 0) { [Text.Encoding]::UTF8.GetBytes($Body) } else { $null }
    return @{
        Method        = $Method.ToUpperInvariant()
        Url           = $Url
        Scheme        = $u.Scheme
        Host          = $u.Host
        Port          = $u.Port
        Path          = $u.AbsolutePath
        Query         = $query
        Headers       = $headers
        Cookies       = $cookies
        Body          = $bodyBytes
        ContentType   = if ($headers.Contains('Content-Type')) { "$($headers['Content-Type'])" } else { '' }
        HasAuthHeader = ($headers.Contains('Authorization') -and "$($headers['Authorization'])")
        HasCookie     = ($cookies.Count -gt 0)
        Origin        = "$($u.Scheme)://$($u.Authority)"
    }
}

# Parse a raw HTTP request (Burp/proxy paste) into a spec. Rejects an absolute request
# target whose host disagrees with the Host header (SSRF/misdirection guard).
function ConvertFrom-TcpkRawHttp {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Text, [string]$Scheme)
    $norm = $Text.Replace("`r`n", "`n")
    $sep = $norm.IndexOf("`n`n")
    $head = if ($sep -ge 0) { $norm.Substring(0, $sep) } else { $norm }
    $body = if ($sep -ge 0) { $norm.Substring($sep + 2) } else { '' }
    $lines = $head -split "`n"
    if ($lines.Count -lt 1) { throw "empty request" }
    $reqLine = $lines[0].Trim() -split '\s+'
    if ($reqLine.Count -lt 2) { throw "malformed request line: $($lines[0])" }
    $method = $reqLine[0]; $target = $reqLine[1]
    $hdrs = @()
    $hostHeader = $null
    for ($i = 1; $i -lt $lines.Count; $i++) {
        $ln = $lines[$i]
        if ([string]::IsNullOrWhiteSpace($ln)) { continue }
        $hdrs += $ln.Trim()
        if ($ln -imatch '^\s*Host\s*:\s*(.+?)\s*$') { $hostHeader = $Matches[1].Trim() }
    }
    if ($target -imatch '^https?://') {
        $tu = [Uri]$target
        if ($hostHeader -and $tu.Authority -and ($tu.Host -ne ($hostHeader -split ':')[0])) {
            throw "absolute request target host ($($tu.Host)) disagrees with Host header ($hostHeader); refusing"
        }
        $url = $target
    } else {
        if (-not $hostHeader) { throw "relative target with no Host header; cannot build URL" }
        $sch = if ($Scheme) { $Scheme } elseif ($hostHeader -match ':80$') { 'http' } else { 'https' }
        $url = "${sch}://${hostHeader}${target}"
    }
    return New-TcpkRequestSpec -Method $method -Url $url -Header $hdrs -Body $body
}

# Deep-ish clone so a mutation never touches the original spec.
function Copy-TcpkSpec {
    [CmdletBinding()] param([Parameter(Mandatory)][hashtable]$Spec)
    $h = New-TcpkHeaderDict; foreach ($k in $Spec.Headers.Keys) { $h[$k] = $Spec.Headers[$k] }
    $c = New-TcpkHeaderDict; foreach ($k in $Spec.Cookies.Keys) { $c[$k] = $Spec.Cookies[$k] }
    $q = New-Object System.Collections.Specialized.OrderedDictionary; foreach ($k in $Spec.Query.Keys) { $q[$k] = $Spec.Query[$k] }
    $b = if ($Spec.Body) { $Spec.Body.Clone() } else { $null }
    $new = @{}
    foreach ($k in $Spec.Keys) { $new[$k] = $Spec[$k] }
    $new.Headers = $h; $new.Cookies = $c; $new.Query = $q; $new.Body = $b
    return $new
}

# Enumerate id-bearing locations in a request (path / query / json-body / header / cookie).
function Get-TcpkIdLocations {
    [CmdletBinding()] param([Parameter(Mandatory)][hashtable]$Spec)
    $locs = New-Object System.Collections.Generic.List[object]
    # path segments
    $segs = $Spec.Path.Trim('/') -split '/'
    for ($i = 0; $i -lt $segs.Count; $i++) {
        if ($segs[$i] -and (Test-TcpkIsIdShaped $segs[$i])) {
            $locs.Add(@{ Kind = 'path'; Key = $i; Value = $segs[$i]; IdType = 'segment' })
        }
    }
    # query params
    foreach ($k in $Spec.Query.Keys) {
        $val = [string]$Spec.Query[$k]
        if ($k -match $script:TcpkIdKeyRx -or (Test-TcpkIsIdShaped $val)) {
            $locs.Add(@{ Kind = 'query'; Key = $k; Value = $val; IdType = 'query' })
        }
    }
    # json body leaves
    if ($Spec.Body -and ($Spec.ContentType -match 'json' -or -not $Spec.ContentType)) {
        try {
            $obj = [Text.Encoding]::UTF8.GetString($Spec.Body) | ConvertFrom-Json
            foreach ($leaf in (Get-TcpkJsonIdLeaves -Node $obj -PathPrefix '$')) { $locs.Add($leaf) }
        } catch {}
    }
    # id-ish headers
    foreach ($k in $Spec.Headers.Keys) {
        if ($k -imatch '^X-.*(-Id|-User|-Account)$' -or $k -imatch '^X-(User|Account|Customer)') {
            $locs.Add(@{ Kind = 'header'; Key = $k; Value = "$($Spec.Headers[$k])"; IdType = 'header' })
        }
    }
    # id-shaped cookies (excluding obvious session cookies)
    foreach ($k in $Spec.Cookies.Keys) {
        if ($k -imatch 'sess|sid|auth|token|jwt|csrf|xsrf') { continue }
        if (Test-TcpkIsIdShaped "$($Spec.Cookies[$k])") { $locs.Add(@{ Kind = 'cookie'; Key = $k; Value = "$($Spec.Cookies[$k])"; IdType = 'cookie' }) }
    }
    return $locs.ToArray()
}

function Get-TcpkJsonIdLeaves {
    [CmdletBinding()] param($Node, [string]$PathPrefix, [int]$Depth = 0)
    $out = New-Object System.Collections.Generic.List[object]
    if ($Depth -gt 6 -or $null -eq $Node) { return $out }
    if ($Node -is [psobject] -and $Node.PSObject.Properties.Count) {
        foreach ($p in $Node.PSObject.Properties) {
            $val = $p.Value
            if ($val -is [psobject] -and $val.PSObject.Properties.Count) {
                foreach ($x in (Get-TcpkJsonIdLeaves -Node $val -PathPrefix "$PathPrefix.$($p.Name)" -Depth ($Depth + 1))) { $out.Add($x) }
            } elseif ($p.Name -match $script:TcpkIdKeyRx -or (Test-TcpkIsIdShaped "$val")) {
                $out.Add(@{ Kind = 'json'; Key = "$PathPrefix.$($p.Name)"; Value = "$val"; IdType = 'json' })
            }
        }
    }
    return $out
}

# Clone the spec and replace exactly ONE id location, keeping URL/body consistent.
function Set-TcpkRequestId {
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Spec, [Parameter(Mandatory)][hashtable]$Location, [Parameter(Mandatory)][string]$NewValue)
    $s = Copy-TcpkSpec $Spec
    switch ($Location.Kind) {
        'path' {
            $segs = $s.Path.Trim('/') -split '/'
            if ([int]$Location.Key -lt $segs.Count) { $segs[[int]$Location.Key] = $NewValue }
            $lead = if ($s.Path.StartsWith('/')) { '/' } else { '' }
            $trail = if ($s.Path.EndsWith('/') -and $s.Path.Length -gt 1) { '/' } else { '' }
            $s.Path = $lead + ($segs -join '/') + $trail
            $s.Url = Get-TcpkSpecUrl $s
        }
        'query' { $s.Query[$Location.Key] = $NewValue; $s.Url = Get-TcpkSpecUrl $s }
        'header' { $s.Headers[$Location.Key] = $NewValue }
        'cookie' {
            $s.Cookies[$Location.Key] = $NewValue
            $s.Headers['Cookie'] = (($s.Cookies.Keys | ForEach-Object { "$_=$($s.Cookies[$_])" }) -join '; ')
        }
        'json' {
            try {
                $obj = [Text.Encoding]::UTF8.GetString($s.Body) | ConvertFrom-Json
                $parts = ($Location.Key -replace '^\$\.', '') -split '\.'
                $cur = $obj
                for ($i = 0; $i -lt $parts.Count - 1; $i++) { $cur = $cur.$($parts[$i]) }
                $cur.$($parts[-1]) = $NewValue
                $s.Body = [Text.Encoding]::UTF8.GetBytes(($obj | ConvertTo-Json -Compress -Depth 20))
            } catch {}
        }
    }
    return $s
}

# Clone the spec with the credential removed. -SessionCookieName removes named session
# cookie(s). Sets AuthActuallyRemoved = the clone genuinely lost a credential the original had.
function Remove-TcpkRequestAuth {
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Spec, [string[]]$SessionCookieName, [switch]$AllCookies)
    $s = Copy-TcpkSpec $Spec
    $had = [bool]$Spec.HasAuthHeader -or ($Spec.Cookies.Count -gt 0)
    if ($s.Headers.Contains('Authorization')) { $s.Headers.Remove('Authorization') }
    $removedCookie = $false
    if ($AllCookies) {
        $s.Cookies = New-TcpkHeaderDict; $removedCookie = ($Spec.Cookies.Count -gt 0)
        if ($s.Headers.Contains('Cookie')) { $s.Headers.Remove('Cookie') }
    } elseif ($SessionCookieName) {
        foreach ($n in $SessionCookieName) { if ($s.Cookies.Contains($n)) { $s.Cookies.Remove($n); $removedCookie = $true } }
        if ($s.Cookies.Count -gt 0) { $s.Headers['Cookie'] = (($s.Cookies.Keys | ForEach-Object { "$_=$($s.Cookies[$_])" }) -join '; ') }
        elseif ($s.Headers.Contains('Cookie')) { $s.Headers.Remove('Cookie') }
    }
    $s.HasAuthHeader = ($s.Headers.Contains('Authorization') -and "$($s.Headers['Authorization'])")
    $s.HasCookie = ($s.Cookies.Count -gt 0)
    # We "actually removed" a credential when the targeted one is gone: the Authorization
    # header that was present is now absent, OR a named session cookie was removed, OR every
    # cookie was cleared (-AllCookies). Untouched non-session cookies do not block this.
    $authWasPresent = [bool]$Spec.HasAuthHeader
    $authNowGone = -not [bool]$s.HasAuthHeader
    $s.AuthActuallyRemoved = (($authWasPresent -and $authNowGone) -or $removedCookie -or ($AllCookies -and $had))
    return $s
}

# Send a spec and return the shared snapshot.
function Invoke-TcpkHttpRequestFull {
    [CmdletBinding()] param([Parameter(Mandatory)][hashtable]$Spec, [string[]]$VolatileFieldRegex, [int]$TimeoutSec = 15)
    $h = @{}
    foreach ($k in $Spec.Headers.Keys) { $h[[string]$k] = [string]$Spec.Headers[$k] }
    return New-TcpkHttpSnapshot -Method $Spec.Method -Url $Spec.Url -Headers $h -Body $Spec.Body -VolatileFieldRegex $VolatileFieldRegex -TimeoutSec $TimeoutSec
}

# host:port of a spec must be in the operator-affirmed allow set. The spec's own Host
# (which may be pcap-derived / attacker-influenced) is NEVER auto-trusted.
function Assert-TcpkReplayHostAllowed {
    [CmdletBinding()] param([Parameter(Mandatory)][hashtable]$Spec, [string[]]$Allow)
    $defaultPort = if ($Spec.Scheme -eq 'https') { 443 } else { 80 }
    $hp = if ($Spec.Port -and $Spec.Port -ne $defaultPort) { "$($Spec.Host):$($Spec.Port)" } else { $Spec.Host }
    $norm = @($Allow | ForEach-Object { ($_ -replace '^https?://', '').TrimEnd('/') })
    if ($norm -contains $hp -or $norm -contains $Spec.Host) { return $true }
    throw "target host '$hp' is not in the affirmed allow-list (-AllowHost / -Target). Refusing to send. Authorized targets only."
}

# Idempotent-verb gate. Also treats side-effect-shaped GET paths as unsafe.
function Test-TcpkSafeMethod {
    [CmdletBinding()] param([Parameter(Mandatory)][hashtable]$Spec)
    if ($Spec.Method -notin 'GET', 'HEAD', 'OPTIONS') { return $false }
    if ($Spec.Path -imatch '/(delete|remove|destroy|logout|signout|drop|purge|reset)(/|$)') { return $false }
    foreach ($k in $Spec.Query.Keys) {
        if ($k -imatch '^action$' -and "$($Spec.Query[$k])" -imatch 'delete|remove|destroy|drop|reset') { return $false }
    }
    return $true
}

# Deterministically identify the session cookie: the cookie whose removal flips an accepted
# response to 401/403. Returns $null if none or several flip (ambiguous -> caller must refuse).
function Get-TcpkSessionCookieName {
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Spec, [string[]]$VolatileFieldRegex, [int]$TimeoutSec = 15)
    $flippers = @()
    foreach ($name in @($Spec.Cookies.Keys)) {
        $clone = Copy-TcpkSpec $Spec
        $clone.Cookies.Remove($name)
        if ($clone.Cookies.Count -gt 0) { $clone.Headers['Cookie'] = (($clone.Cookies.Keys | ForEach-Object { "$_=$($clone.Cookies[$_])" }) -join '; ') }
        elseif ($clone.Headers.Contains('Cookie')) { $clone.Headers.Remove('Cookie') }
        $snap = Invoke-TcpkHttpRequestFull -Spec $clone -VolatileFieldRegex $VolatileFieldRegex -TimeoutSec $TimeoutSec
        if ($snap.Status -in 401, 403) { $flippers += $name }
    }
    if ($flippers.Count -eq 1) { return $flippers[0] }
    return $null
}

# Build a request spec from any supported source, in precedence order:
# RequestFile > RequestText > FromPcap > manual (-Method/-Url/-Header/-Body).
function Resolve-TcpkRequestSpec {
    [CmdletBinding()]
    param(
        [string]$RequestFile, [string]$RequestText,
        [string]$FromPcap, [string]$Tshark, [string]$Keylog, [string]$RsaKey, [int]$RequestIndex = 0,
        [string]$Scheme,
        [string]$Method, [string]$Url, [string[]]$Header, [string]$Body
    )
    if ($RequestFile) {
        if (-not (Test-Path -LiteralPath $RequestFile)) { throw "request file not found: $RequestFile" }
        return ConvertFrom-TcpkRawHttp -Text (Get-Content -LiteralPath $RequestFile -Raw) -Scheme $Scheme
    }
    if ($RequestText) { return ConvertFrom-TcpkRawHttp -Text $RequestText -Scheme $Scheme }
    if ($FromPcap) {
        $tsh = if ($Tshark) { $Tshark } else { Get-TcpkTshark }
        return ConvertFrom-TcpkPcapRequest -Tshark $tsh -Pcap $FromPcap -KeylogFile $Keylog -RsaKeyFile $RsaKey -Index $RequestIndex
    }
    if ($Url) { return New-TcpkRequestSpec -Method ($(if ($Method) { $Method } else { 'GET' })) -Url $Url -Header $Header -Body $Body }
    throw "supply -RequestFile, -RequestText, -FromPcap, or -Url (with -Method/-Header/-Body)."
}
