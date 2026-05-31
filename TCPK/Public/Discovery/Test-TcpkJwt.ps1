function Test-TcpkJwt {
<#
.SYNOPSIS
    A14. Embedded JSON Web Token (JWT) discovery + weakness analysis.

.DESCRIPTION
    Finds JWTs embedded in shipped files (a hardcoded bearer token is a leaked
    credential), decodes the header + payload, and flags:
      * alg = none          -> signature not enforced (CRITICAL)
      * no exp claim        -> token never expires
      * exp in the past     -> expired token still shipped (leak)
      * sensitive claims    -> email / role / scope present in a shipped token

    A JWT in a binary/config is reported even if expired -- it reveals issuer,
    audience, and claim structure, and often a still-valid refresh path.

.PARAMETER Path
    File or directory.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $rxJwt = [regex]'eyJ[A-Za-z0-9_\-]{6,}\.eyJ[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{0,}'
    $skipExt = @('.png','.jpg','.jpeg','.ico','.ttf','.otf','.woff','.woff2','.gif','.bmp','.mp4','.mp3')

    $files = if ((Get-Item -LiteralPath $Path).PSIsContainer) {
        Get-ChildItem -LiteralPath $Path -Recurse -File -ErrorAction SilentlyContinue
    } else { Get-Item -LiteralPath $Path }

    $seen = @{}
    $cap = 25; $n = 0
    foreach ($f in $files) {
        if ($n -ge $cap) { break }
        if ($f.Extension.ToLowerInvariant() -in $skipExt) { continue }
        if ($f.Length -gt 16MB) { continue }
        $v = Read-TcpkStringViews -Path $f.FullName
        if (-not $v) { continue }

        foreach ($view in @($v.Utf8, $v.Utf16Le)) {
            foreach ($m in $rxJwt.Matches($view)) {
                if ($n -ge $cap) { break }
                $jwt = $m.Value
                $parts = $jwt.Split('.')
                if ($parts.Count -lt 2) { continue }

                $hdrBytes = Convert-TcpkFromB64Url -Text $parts[0]
                $payBytes = Convert-TcpkFromB64Url -Text $parts[1]
                if (-not $hdrBytes -or -not $payBytes) { continue }    # not real base64url -> false match

                $hdr = $null; $pay = $null
                try { $hdr = [Text.Encoding]::UTF8.GetString($hdrBytes) | ConvertFrom-Json } catch { continue }
                try { $pay = [Text.Encoding]::UTF8.GetString($payBytes) | ConvertFrom-Json } catch { continue }
                if (-not $hdr -or -not ($hdr.PSObject.Properties['alg'])) { continue }   # header must have alg => real JWT

                $alg = "$($hdr.alg)"
                $idKey = $parts[0].Substring(0,[Math]::Min(12,$parts[0].Length)) + $parts[1].Substring(0,[Math]::Min(12,$parts[1].Length))
                if ($seen.ContainsKey($idKey)) { continue }
                $seen[$idKey] = $true
                $n++

                # --- analyse ---
                $sev = 'MEDIUM'; $notes = @()
                if ($alg -match '^(none)$') { $sev = 'CRITICAL'; $notes += 'alg=none (signature NOT enforced)' }

                $expNote = 'no exp claim (never expires)'
                if ($pay.PSObject.Properties['exp']) {
                    $expVal = [int64]$pay.exp
                    $expDt = [DateTimeOffset]::FromUnixTimeSeconds($expVal).UtcDateTime
                    if ($expDt -lt (Get-Date).ToUniversalTime()) { $expNote = "expired $($expDt.ToString('u'))" }
                    else { $expNote = "valid until $($expDt.ToString('u'))"; if ($sev -eq 'MEDIUM') { $sev = 'HIGH' } }
                } else { if ($sev -eq 'MEDIUM') { $sev = 'HIGH' } }
                $notes += $expNote

                $claims = @()
                foreach ($cn in 'iss','aud','sub','email','role','roles','scope','scp','name','unique_name','upn') {
                    if ($pay.PSObject.Properties[$cn]) { $claims += "$cn=$($pay.$cn)" }
                }

                $red = if ($jwt.Length -gt 24) { $jwt.Substring(0,12) + '...' + $jwt.Substring($jwt.Length-6) } else { $jwt }
                New-TcpkFinding -Module 'static' -RuleId 'jwt.embedded-token' `
                    -Severity $sev -Confidence 'Confirmed' `
                    -Title "Embedded JWT (alg=$alg) in $($f.Name)" `
                    -File $f.FullName `
                    -Evidence ("$red | alg=$alg | " + ($notes -join '; ') + $(if ($claims) { ' | ' + ($claims -join ', ') } else { '' })) `
                    -Cwe @('CWE-798','CWE-522') `
                    -Description 'A JSON Web Token is hardcoded in a shipped file. Even if expired it leaks issuer/audience/claims and signals a credential was committed; if still valid it is a live bearer credential.' `
                    -Fix 'Never ship JWTs. Issue them server-side at runtime, keep lifetimes short, and reject alg=none server-side. Revoke/rotate any exposed token.'
            }
        }
    }
}
