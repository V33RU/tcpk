#requires -Version 5.1
# Pester 5: Invoke-TcpkLogoutProbe against a real local HttpListener with real session state.
#
# The listener keeps an actual revoked-token set, so one route genuinely invalidates on
# logout and another genuinely does not. A suite that only exercised the broken route would
# pass against a cmdlet that flags every target.
#
# -RevocationGraceSec 0 throughout: the listener revokes synchronously, and the default 60s
# wait exists for asynchronous backends, not for this.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
    Enable-TcpkExploit -Acknowledge | Out-Null

    $l = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0); $l.Start()
    $script:port = ([System.Net.IPEndPoint]$l.LocalEndpoint).Port; $l.Stop()
    $script:base = "http://127.0.0.1:$($script:port)"
    $script:hostAllow = "127.0.0.1:$($script:port)"

    function script:New-TestJwt([string]$ExpPart) {
        $b64 = { param($s) [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($s)).TrimEnd('=').Replace('+','-').Replace('/','_') }
        $h = & $b64 '{"alg":"HS256","typ":"JWT"}'
        $p = & $b64 ('{"sub":"tester"' + $ExpPart + '}')
        return "$h.$p.sig"
    }
    $future = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() + 604800
    $script:jwtWithExp = script:New-TestJwt (',"exp":' + $future)
    $script:jwtNoExp   = script:New-TestJwt ''
    $script:opaque     = 'opaque-session-abc123'

    $script:job = Start-Job -ArgumentList $script:port -ScriptBlock {
        param($port)
        $ln = [System.Net.HttpListener]::new()
        $ln.Prefixes.Add("http://127.0.0.1:$port/")
        $ln.Start()
        $PROTECTED = 'PROTECTED-ACCOUNT-BODY-0123456789abcdef'
        $revoked = New-Object 'System.Collections.Generic.HashSet[string]'
        while ($ln.IsListening) {
            $ctx = $ln.GetContext(); $req = $ctx.Request; $res = $ctx.Response
            $tok = "$($req.Headers['Authorization'])" -replace '^\s*Bearer\s+', ''
            $path = $req.Url.AbsolutePath
            $code = 401; $body = 'unauthorized'
            if ($path -eq '/shutdown') {
                $res.StatusCode = 200
                $b = [Text.Encoding]::UTF8.GetBytes('bye')
                $res.OutputStream.Write($b, 0, $b.Length); $res.Close(); $ln.Stop(); return
            }
            # Both logout routes return 200. Only one actually records the revocation.
            elseif ($path -eq '/logout-real')  { [void]$revoked.Add($tok); $code = 200; $body = 'logged out' }
            elseif ($path -eq '/logout-fake')  { $code = 200; $body = 'logged out' }
            elseif ($path -eq '/logout-broken') { $code = 403; $body = 'csrf token missing' }
            # Honours the revoked set: the correct implementation.
            elseif ($path -eq '/account') {
                if ($tok -and -not $revoked.Contains($tok)) { $code = 200; $body = $PROTECTED }
            }
            # Ignores the revoked set entirely: the defect.
            elseif ($path -eq '/account-nocheck') {
                if ($tok) { $code = 200; $body = $PROTECTED }
            }
            elseif ($path -eq '/open') { $code = 200; $body = $PROTECTED }
            else { $code = 404; $body = 'nope' }
            $res.StatusCode = $code
            $b = [Text.Encoding]::UTF8.GetBytes($body)
            $res.OutputStream.Write($b, 0, $b.Length)
            $res.Close()
        }
    }

    $script:up = $false
    for ($i = 0; $i -lt 40; $i++) {
        try { $c = [System.Net.Sockets.TcpClient]::new(); $c.Connect('127.0.0.1', $script:port); $c.Close(); $script:up = $true; break }
        catch { Start-Sleep -Milliseconds 250 }
    }

    # Each case needs its own token, because a successful run really does revoke one.
    $script:n = 0
    function script:Tok { $script:n++; return "sess-$($script:n)-$([guid]::NewGuid().ToString('N').Substring(0,8))" }
}

AfterAll {
    try { Invoke-WebRequest -Uri "$($script:base)/shutdown" -TimeoutSec 3 -UseBasicParsing | Out-Null } catch { }
    if ($script:job) { Stop-Job $script:job -ErrorAction SilentlyContinue; Remove-Job $script:job -Force -ErrorAction SilentlyContinue }
    try { Disable-TcpkExploit | Out-Null } catch { }
}

# See AuthMatrix.Tests.ps1: -Skip: is evaluated at DISCOVERY, so a BeforeAll-assigned flag
# would silently skip the whole file. A listener that will not bind fails here instead.
Describe 'test server' {
    It 'listener came up' { $script:up | Should -BeTrue }
}

Describe 'Invoke-TcpkLogoutProbe: safety gates' {
    It 'refuses without -ConfirmActive' {
        { Invoke-TcpkLogoutProbe -Url "$($script:base)/account" -Header 'Authorization: Bearer t' `
            -LogoutUrl "$($script:base)/logout-real" -Target $script:hostAllow } |
            Should -Throw -ExpectedMessage '*ConfirmActive*'
    }

    It 'refuses to guess which endpoint signs a user out' {
        { Invoke-TcpkLogoutProbe -Url "$($script:base)/account" -Header 'Authorization: Bearer t' `
            -ConfirmActive -Target $script:hostAllow } |
            Should -Throw -ExpectedMessage '*will not guess*'
    }

    It 'checks the LOGOUT host against the allow-list, not just the protected host' {
        { Invoke-TcpkLogoutProbe -Url "$($script:base)/account" -Header 'Authorization: Bearer t' `
            -LogoutUrl 'http://not-authorized.invalid/logout' -ConfirmActive -Target $script:hostAllow } |
            Should -Throw -ExpectedMessage '*allow-list*'
    }
}

Describe 'Invoke-TcpkLogoutProbe: refusals that must not be silent' {
    It 'refuses when the two requests carry different credentials' {
        $f = @(Invoke-TcpkLogoutProbe -Url "$($script:base)/account" -Header 'Authorization: Bearer AAA' `
            -LogoutUrl "$($script:base)/logout-real" -LogoutMethod POST -LogoutHeader 'Authorization: Bearer BBB' `
            -ConfirmActive -Target $script:hostAllow -RevocationGraceSec 0)
        @($f | Where-Object { $_.RuleId -eq 'logout.credential-mismatch' }).Count | Should -Be 1
    }

    It 'refuses when the protected request carries no credential at all' {
        $f = @(Invoke-TcpkLogoutProbe -Url "$($script:base)/account" `
            -LogoutUrl "$($script:base)/logout-real" -LogoutMethod POST `
            -ConfirmActive -Target $script:hostAllow -RevocationGraceSec 0)
        @($f | Where-Object { $_.RuleId -eq 'logout.no-credential' }).Count | Should -Be 1
    }

    It 'stops when the logout request itself is rejected' {
        $t = script:Tok
        $f = @(Invoke-TcpkLogoutProbe -Url "$($script:base)/account" -Header "Authorization: Bearer $t" `
            -LogoutUrl "$($script:base)/logout-broken" -LogoutMethod POST -LogoutHeader "Authorization: Bearer $t" `
            -ConfirmActive -Target $script:hostAllow -RevocationGraceSec 0)
        $l = @($f | Where-Object { $_.RuleId -eq 'logout.logout-failed' })
        $l.Count | Should -Be 1
        @($f | Where-Object { $_.RuleId -like 'logout.*survives*' }).Count | Should -Be 0
    }

    It 'stops when the session was already dead before logout' {
        $t = script:Tok
        $f = @(Invoke-TcpkLogoutProbe -Url "$($script:base)/nonexistent" -Header "Authorization: Bearer $t" `
            -LogoutUrl "$($script:base)/logout-real" -LogoutMethod POST -LogoutHeader "Authorization: Bearer $t" `
            -ConfirmActive -Target $script:hostAllow -RevocationGraceSec 0)
        @($f | Where-Object { $_.RuleId -eq 'logout.baseline-not-accepted' }).Count | Should -Be 1
    }
}

Describe 'Invoke-TcpkLogoutProbe: a backend that really revokes' {
    It 'reports the clean result and raises no defect' {
        $t = script:Tok
        $f = @(Invoke-TcpkLogoutProbe -Url "$($script:base)/account" -Header "Authorization: Bearer $t" `
            -LogoutUrl "$($script:base)/logout-real" -LogoutMethod POST -LogoutHeader "Authorization: Bearer $t" `
            -ConfirmActive -Target $script:hostAllow -RevocationGraceSec 0 -SessionModel ServerSide)
        $r = @($f | Where-Object { $_.RuleId -eq 'logout.revoked' })
        $r.Count | Should -Be 1
        $r[0].Severity | Should -Be 'INFO'
        @($f | Where-Object { $_.RuleId -eq 'logout.session-not-invalidated' }).Count | Should -Be 0
    }
}

Describe 'Invoke-TcpkLogoutProbe: a backend that does not revoke' {
    It 'confirms the defect when the model is declared ServerSide' {
        $t = script:Tok
        $f = @(Invoke-TcpkLogoutProbe -Url "$($script:base)/account-nocheck" -Header "Authorization: Bearer $t" `
            -LogoutUrl "$($script:base)/logout-fake" -LogoutMethod POST -LogoutHeader "Authorization: Bearer $t" `
            -ConfirmActive -Target $script:hostAllow -RevocationGraceSec 0 -SessionModel ServerSide)
        $s = @($f | Where-Object { $_.RuleId -eq 'logout.session-not-invalidated' })
        $s.Count | Should -Be 1
        $s[0].Severity | Should -Be 'HIGH'
        $s[0].Confidence | Should -Be 'Confirmed (exploit)'
    }

    It 'downgrades to an observation, not a defect, when the model is undeclared' {
        $t = script:Tok
        $f = @(Invoke-TcpkLogoutProbe -Url "$($script:base)/account-nocheck" -Header "Authorization: Bearer $t" `
            -LogoutUrl "$($script:base)/logout-fake" -LogoutMethod POST -LogoutHeader "Authorization: Bearer $t" `
            -ConfirmActive -Target $script:hostAllow -RevocationGraceSec 0)
        $c = @($f | Where-Object { $_.RuleId -eq 'logout.credential-survives' })
        $c.Count | Should -Be 1
        $c[0].Severity | Should -Be 'MEDIUM'
        $c[0].Confidence | Should -Be 'Inferred'
        "$($c[0].Description)" | Should -Match '(?i)depends on the architecture'
        @($f | Where-Object { $_.RuleId -eq 'logout.session-not-invalidated' }).Count | Should -Be 0
    }

    It 'calls a declared-Stateless survival expected behaviour and states the window' {
        $f = @(Invoke-TcpkLogoutProbe -Url "$($script:base)/account-nocheck" `
            -Header "Authorization: Bearer $($script:jwtWithExp)" `
            -LogoutUrl "$($script:base)/logout-fake" -LogoutMethod POST `
            -LogoutHeader "Authorization: Bearer $($script:jwtWithExp)" `
            -ConfirmActive -Target $script:hostAllow -RevocationGraceSec 0 -SessionModel Stateless)
        $s = @($f | Where-Object { $_.RuleId -eq 'logout.stateless-not-revoked' })
        $s.Count | Should -Be 1
        $s[0].Severity | Should -Be 'INFO'
        "$($s[0].Description)" | Should -Match 'remains usable for roughly \d+ more seconds'
    }

    It 'flags a JWT with no exp as permanent, whatever the declared model' {
        $f = @(Invoke-TcpkLogoutProbe -Url "$($script:base)/account-nocheck" `
            -Header "Authorization: Bearer $($script:jwtNoExp)" `
            -LogoutUrl "$($script:base)/logout-fake" -LogoutMethod POST `
            -LogoutHeader "Authorization: Bearer $($script:jwtNoExp)" `
            -ConfirmActive -Target $script:hostAllow -RevocationGraceSec 0 -SessionModel Stateless)
        $n = @($f | Where-Object { $_.RuleId -eq 'logout.token-never-dies' })
        $n.Count | Should -Be 1
        $n[0].Severity | Should -Be 'HIGH'
        $n[0].Confidence | Should -Be 'Confirmed (exploit)'
        "$($n[0].Description)" | Should -Match '(?i)does not depend on -SessionModel'
        # It must NOT also emit the softer stateless observation for the same run.
        @($f | Where-Object { $_.RuleId -eq 'logout.stateless-not-revoked' }).Count | Should -Be 0
    }
}

Describe 'Invoke-TcpkLogoutProbe: an endpoint needing no credential' {
    It 'reports the missing authentication and makes NO revocation claim' {
        $t = script:Tok
        $f = @(Invoke-TcpkLogoutProbe -Url "$($script:base)/open" -Header "Authorization: Bearer $t" `
            -LogoutUrl "$($script:base)/logout-real" -LogoutMethod POST -LogoutHeader "Authorization: Bearer $t" `
            -ConfirmActive -Target $script:hostAllow -RevocationGraceSec 0 -SessionModel ServerSide)
        $o = @($f | Where-Object { $_.RuleId -eq 'logout.endpoint-open' })
        $o.Count | Should -Be 1
        $o[0].Severity | Should -Be 'CRITICAL'
        @($f | Where-Object { $_.RuleId -eq 'logout.session-not-invalidated' }).Count | Should -Be 0
    }
}

Describe 'Get-TcpkSpecCredentialFingerprint / Test-TcpkSpecHasJwt' {
    It 'fingerprints identical credentials the same and different ones differently' {
        InModuleScope TCPK {
            $a = New-TcpkRequestSpec -Method GET -Url 'https://x.invalid/a' -Header 'Authorization: Bearer AAA'
            $b = New-TcpkRequestSpec -Method POST -Url 'https://x.invalid/logout' -Header 'Authorization: Bearer AAA'
            $c = New-TcpkRequestSpec -Method GET -Url 'https://x.invalid/a' -Header 'Authorization: Bearer BBB'
            (Get-TcpkSpecCredentialFingerprint -Spec $a) | Should -Be (Get-TcpkSpecCredentialFingerprint -Spec $b)
            (Get-TcpkSpecCredentialFingerprint -Spec $a) | Should -Not -Be (Get-TcpkSpecCredentialFingerprint -Spec $c)
        }
    }

    It 'never returns the raw credential' {
        InModuleScope TCPK {
            $a = New-TcpkRequestSpec -Method GET -Url 'https://x.invalid/a' -Header 'Authorization: Bearer SUPERSECRET'
            (Get-TcpkSpecCredentialFingerprint -Spec $a) | Should -Not -Match 'SUPERSECRET'
            (Get-TcpkSpecCredentialFingerprint -Spec $a) | Should -Match '^[0-9a-f]{64}$'
        }
    }

    It 'returns empty when there is no credential' {
        InModuleScope TCPK {
            $a = New-TcpkRequestSpec -Method GET -Url 'https://x.invalid/a'
            (Get-TcpkSpecCredentialFingerprint -Spec $a) | Should -BeNullOrEmpty
        }
    }

    It 'tells a JWT without exp apart from an opaque token' {
        InModuleScope TCPK -Parameters @{ jwt = $script:jwtNoExp; opaque = $script:opaque } {
            param($jwt, $opaque)
            $a = New-TcpkRequestSpec -Method GET -Url 'https://x.invalid/a' -Header "Authorization: Bearer $jwt"
            $b = New-TcpkRequestSpec -Method GET -Url 'https://x.invalid/a' -Header "Authorization: Bearer $opaque"
            Test-TcpkSpecHasJwt -Spec $a | Should -BeTrue
            Test-TcpkSpecHasJwt -Spec $b | Should -BeFalse
            # The exp-seeking helper finds nothing in either: that is the pair of answers
            # the caller uses to identify a credential nothing can expire.
            Get-TcpkSpecJwtClaim -Spec $a | Should -BeNullOrEmpty
            Get-TcpkSpecJwtClaim -Spec $b | Should -BeNullOrEmpty
        }
    }
}
