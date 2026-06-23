function Test-TcpkSessionHandling {
<#
.SYNOPSIS
    A33. Session-handling hygiene (cookie flags, token lifecycle, weak token generation).

.DESCRIPTION
    Static, string/config-level audit of how the app manages sessions and session
    tokens. Complements the credential-storage checks (which cover token storage)
    and Test-TcpkJwt (which covers JWT structure) by looking at session LIFECYCLE
    hygiene that is statically visible:

      - cookies created without HttpOnly / Secure / a safe SameSite
      - ASP.NET cookieless sessions (session id in the URL)
      - session / access tokens passed in a URL query string
      - session tokens generated from Guid.NewGuid() or System.Random (not a CSPRNG)
      - non-expiring / very-long session timeouts and persistent ("remember me") cookies

    Highest signal comes from shipped config (web.config / appsettings.json / *.config),
    shipped scripts (Electron / WebView2 *.js), and URL string literals inside PEs. A
    string match proves the PATTERN is present, not that it governs a live session, so
    every finding is Confidence='Inferred' -- confirm the data flow in a decompiler
    (managed code) or by observing the app's real cookies/tokens with an intercepting
    proxy.

    The runtime parts of session security (real token entropy, server-side expiration,
    logout / idle invalidation, fixation) require the running app and are out of scope
    for this static check.

.PARAMETER Path
    Folder (recursive) preferred. Single file also works.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    # Each rule: a regex over file text + how to render it. All Inferred (a string
    # match proves the pattern is present, not that it governs a live session).
    $rules = @(
        @{ Id='cookie-not-httponly'
           Rx='(?i)(HttpOnly\s*=\s*false|httpOnlyCookies\s*=\s*"?false)'
           Sev='MEDIUM'; Cwe=@('CWE-1004')
           Title='Session cookie without HttpOnly'
           Desc='A cookie is created with HttpOnly disabled, so client-side script (e.g. via XSS, or a compromised WebView2 page) can read it and steal the session.'
           Fix='Set HttpOnly on all session/auth cookies (CookieOptions.HttpOnly = true; httpOnlyCookies enabled="true").' },

        @{ Id='cookie-not-secure'
           Rx='(?i)(requireSSL\s*=\s*"?false|CookieSecurePolicy\.None|CookieSecure\s*=\s*false)'
           Sev='MEDIUM'; Cwe=@('CWE-614')
           Title='Session cookie without the Secure flag'
           Desc='A session cookie can be sent over plaintext HTTP, so a network attacker can capture it.'
           Fix='Set Secure on session cookies (requireSSL="true" / CookieSecurePolicy.Always).' },

        @{ Id='cookie-samesite-none'
           Rx='(?i)(SameSite\s*=\s*SameSiteMode\.None|SameSite\s*=\s*"?None\b)'
           Sev='LOW'; Cwe=@('CWE-1275')
           Title='Session cookie SameSite=None'
           Desc='SameSite=None lets the cookie be sent on cross-site requests, widening the CSRF surface unless every cross-site use is intentional.'
           Fix='Use SameSite=Lax (or Strict) for session cookies; only use None when genuinely cross-site, and then also set Secure.' },

        @{ Id='cookieless-session'
           Rx='(?i)cookieless\s*=\s*"?(UseUri|true)\b'
           Sev='MEDIUM'; Cwe=@('CWE-598','CWE-384')
           Title='ASP.NET cookieless session (session id in the URL)'
           Desc='Cookieless sessions put the session id in the URL, where it leaks into logs, history, and referrers, and is exposed to session fixation.'
           Fix='Set cookieless="UseCookies" and rely on a HttpOnly+Secure cookie instead.' },

        @{ Id='token-in-url'
           Rx='(?i)[?&](jsessionid|sessionid|session_id|sessiontoken|sid|access_token|auth_token|id_token)='
           Sev='MEDIUM'; Cwe=@('CWE-598')
           Title='Session/access token passed in a URL'
           Desc='A session or access token is carried in a URL query string, where it leaks into server/proxy logs, browser history, and the Referer header.'
           Fix='Send tokens in the Authorization header or a secure cookie; never place them in the URL.' },

        @{ Id='weak-token-guid'
           Rx='(?i)(session|sessionid|token|authtoken|sid)\w*\s*=\s*Guid\.NewGuid\(\)'
           Sev='MEDIUM'; Cwe=@('CWE-330','CWE-338')
           Title='Session/auth token generated from Guid.NewGuid()'
           Desc='A session/auth token appears to be a GUID. GUIDs are not cryptographically random and are not a safe source of session secrets.'
           Fix='Generate session tokens from a CSPRNG (System.Security.Cryptography.RandomNumberGenerator) with at least 128 bits of entropy.' },

        @{ Id='weak-token-random'
           Rx='(?i)(session|token|sid)\w*\s*=\s*new\s+Random\b'
           Sev='MEDIUM'; Cwe=@('CWE-338')
           Title='Session/auth value derived from System.Random'
           Desc='A session/auth value is derived from System.Random, which is a predictable PRNG, not a cryptographic one.'
           Fix='Use System.Security.Cryptography.RandomNumberGenerator for any session/auth token.' },

        @{ Id='non-expiring-token'
           Rx='(?i)(Expires\s*=\s*DateTime\.MaxValue|MaxAge\s*=\s*(?:-1|TimeSpan\.MaxValue))'
           Sev='LOW'; Cwe=@('CWE-613')
           Title='Non-expiring session cookie/token'
           Desc='A session cookie/token is configured to never expire, so a stolen token stays valid indefinitely.'
           Fix='Set a reasonable absolute and idle expiration, and rotate tokens on privilege change.' },

        @{ Id='persistent-cookie'
           Rx='(?i)(isPersistent\s*=\s*true|createPersistentCookie\s*=\s*true|RememberMe\s*=\s*true)'
           Sev='LOW'; Cwe=@('CWE-539')
           Title='Persistent ("remember me") session cookie enabled'
           Desc='A persistent session cookie is issued, extending the window for token theft on shared machines.'
           Fix='Confirm the persistent cookie is required; keep it short-lived and bound to the device if so.' },

        @{ Id='high-timeout'
           Rx='(?i)(forms[^>]{0,200}?timeout\s*=\s*"?\d{4,}|sessionState[^>]{0,200}?timeout\s*=\s*"?\d{4,})'
           Sev='LOW'; Cwe=@('CWE-613')
           Title='Very long session timeout'
           Desc='A forms-auth / session timeout is set to 1000+ minutes, widening the session-hijack window.'
           Fix='Use a short idle session timeout (e.g. 15-30 minutes).' }
    )

    # Collect text-bearing targets: managed PEs (string-extracted) + shipped config /
    # script / source files (read as text). Cookie/token logic is most often visible in
    # config (web.config / appsettings.json) and shipped JS, not compiled IL.
    $peExt   = @('.exe','.dll','.sys','.winmd')
    $textExt = @('.config','.json','.xml','.ini','.js','.mjs','.cjs','.ts','.html','.htm','.cshtml','.aspx','.cs','.vue')

    $targets = New-Object 'System.Collections.Generic.List[object]'
    foreach ($pe in (Get-TcpkPeFiles -Path $Path)) {
        if (-not (Test-TcpkIsFrameworkFile $pe.Name)) { $targets.Add($pe) }
    }
    if ((Get-Item -LiteralPath $Path).PSIsContainer) {
        Get-ChildItem -LiteralPath $Path -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension.ToLowerInvariant() -in $textExt } |
            ForEach-Object { $targets.Add($_) }
    } elseif ((Get-Item -LiteralPath $Path).Extension.ToLowerInvariant() -in $textExt) {
        $targets.Add((Get-Item -LiteralPath $Path))
    }

    $seen = @{}
    foreach ($t in $targets) {
        $ext = $t.Extension.ToLowerInvariant()
        $text = if ($ext -in $peExt) {
            Read-TcpkAllText -Path $t.FullName
        } else {
            try { [IO.File]::ReadAllText($t.FullName) } catch { $null }
        }
        if (-not $text) { continue }
        # The bundled Chromium runtime binary contains cookie-attribute / token strings
        # (SameSite=None, etc.) that are Chromium's own, not the app's session logic; the
        # app's cookies are governed by the shipped JS/config, still scanned below.
        if (($ext -in $peExt) -and (Test-TcpkIsChromiumRuntime -Name $t.Name -Text $text)) { continue }

        foreach ($r in $rules) {
            $m = [regex]::Match($text, $r.Rx)
            if (-not $m.Success) { continue }
            $key = "$($r.Id)|$($t.FullName)"
            if ($seen.ContainsKey($key)) { continue }
            $seen[$key] = $true

            $ev = $m.Value
            if ($ev.Length -gt 120) { $ev = $ev.Substring(0,120) + ' ...' }

            New-TcpkFinding -Module 'static' -RuleId ('session.' + $r.Id) `
                -Severity $r.Sev -Confidence 'Inferred' `
                -Title $r.Title -File $t.FullName -Evidence $ev `
                -Cwe $r.Cwe -Description $r.Desc -Fix $r.Fix
        }
    }
}
