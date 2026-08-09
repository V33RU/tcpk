#requires -Version 5.1
# Pester 5: Invoke-TcpkExpiryProbe against a real local HttpListener.
#
# The listener implements genuine exp enforcement on one route and none on another, so
# the check has to tell them apart. A suite that only asserted the broken route would
# pass against a cmdlet that flags everything.
#
# HttpListener sets a Date header on every response by itself, which is what the check
# reads as the server clock, so the ServerDate path is exercised for real here.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
    Enable-TcpkExploit -Acknowledge | Out-Null

    $l = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0); $l.Start()
    $script:port = ([System.Net.IPEndPoint]$l.LocalEndpoint).Port; $l.Stop()
    $script:base = "http://127.0.0.1:$($script:port)"
    $script:hostAllow = "127.0.0.1:$($script:port)"

    # Build real JWTs. Signature is never checked by this cmdlet (it replays, it does not
    # forge), so an unsigned third segment is fine; the exp claim is what matters.
    function script:New-TestJwt([long]$ExpUnix) {
        $b64 = {
            param($s)
            [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($s)).TrimEnd('=').Replace('+', '-').Replace('/', '_')
        }
        $h = & $b64 '{"alg":"HS256","typ":"JWT"}'
        $p = & $b64 ('{"sub":"tester","exp":' + $ExpUnix + '}')
        return "$h.$p.sig"
    }

    $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $script:expiredJwt = script:New-TestJwt ($now - 604800)   # 7 days past exp
    $script:freshJwt   = script:New-TestJwt ($now + 604800)   # 7 days of life left
    $script:soonJwt    = script:New-TestJwt ($now + 3600)     # still valid, defers

    $script:job = Start-Job -ArgumentList $script:port, $script:expiredJwt, $script:freshJwt -ScriptBlock {
        param($port, $expired, $fresh)
        $ln = [System.Net.HttpListener]::new()
        $ln.Prefixes.Add("http://127.0.0.1:$port/")
        $ln.Start()
        $PROTECTED = 'PROTECTED-ACCOUNT-BODY-0123456789abcdef'
        while ($ln.IsListening) {
            $ctx = $ln.GetContext(); $req = $ctx.Request; $res = $ctx.Response
            $auth = "$($req.Headers['Authorization'])" -replace '^\s*Bearer\s+', ''
            $known = ($auth -eq $expired -or $auth -eq $fresh)
            $code = 401; $body = 'unauthorized'
            switch -Regex ($req.Url.AbsolutePath) {
                '/shutdown' {
                    $res.StatusCode = 200
                    $b = [Text.Encoding]::UTF8.GetBytes('bye')
                    $res.OutputStream.Write($b, 0, $b.Length); $res.Close(); $ln.Stop(); return
                }
                # Honours ANY token it recognises, expired or not: the defect.
                '/no-expiry-check' { if ($known) { $code = 200; $body = $PROTECTED } }
                # Rejects the expired one specifically: correct enforcement.
                '/enforced' {
                    if ($auth -eq $fresh) { $code = 200; $body = $PROTECTED }
                    elseif ($auth -eq $expired) { $code = 401; $body = 'token expired' }
                }
                # No credential required at all.
                '/open' { $code = 200; $body = $PROTECTED }
                default { $code = 404; $body = 'nope' }
            }
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
}

AfterAll {
    try { Invoke-WebRequest -Uri "$($script:base)/shutdown" -TimeoutSec 3 -UseBasicParsing | Out-Null } catch { }
    if ($script:job) { Stop-Job $script:job -ErrorAction SilentlyContinue; Remove-Job $script:job -Force -ErrorAction SilentlyContinue }
    try { Disable-TcpkExploit | Out-Null } catch { }
}

# The listener is a hard requirement, not an optional capability, so a failure to bind is
# a FAILING test rather than a skip. Gating these on a -Skip: whose variable is assigned in
# BeforeAll would be worse than useless: Pester evaluates -Skip: during DISCOVERY, before
# BeforeAll has run, so the variable is still $null, -not $null is $true, and the entire
# file silently reports green having executed nothing. Repo suites that legitimately skip
# (Windows-only, tshark-only) set their flag in BeforeDiscovery for exactly this reason.
Describe 'test server' {
    It 'listener came up' { $script:up | Should -BeTrue }
}

Describe 'New-TcpkHttpSnapshot: the added ServerDate / ElapsedMs keys' {
    It 'returns the server Date header as UTC, and keeps the original five keys' {
        InModuleScope TCPK -Parameters @{ url = "$($script:base)/open" } {
            param($url)
            $s = New-TcpkHttpSnapshot -Method GET -Url $url
            $s.Status | Should -Be 200
            $s.Hash | Should -Match '^sha256:'
            $s.BodyHead | Should -Match 'PROTECTED'
            $s.ContainsKey('Redirect') | Should -BeTrue
            $s.ServerDate | Should -Not -BeNullOrEmpty
            $s.ServerDate.Kind | Should -Be 'Utc'
            $s.ElapsedMs | Should -BeGreaterOrEqual 0
        }
    }

    It 'still returns every key on a transport error, so callers never test for existence' {
        InModuleScope TCPK {
            $s = New-TcpkHttpSnapshot -Method GET -Url 'http://127.0.0.1:1/nope' -TimeoutSec 2
            $s.Status | Should -Be 0
            $s.Hash | Should -Be 'sha256:error'
            $s.ContainsKey('ServerDate') | Should -BeTrue
            $s.ServerDate | Should -BeNullOrEmpty
            $s.ContainsKey('ElapsedMs') | Should -BeTrue
        }
    }
}

Describe 'Invoke-TcpkExpiryProbe: safety gates' {
    It 'refuses without -ConfirmActive' {
        { Invoke-TcpkExpiryProbe -Url "$($script:base)/no-expiry-check" -Header "Authorization: Bearer $($script:expiredJwt)" -Target $script:hostAllow } |
            Should -Throw -ExpectedMessage '*ConfirmActive*'
    }

    It 'refuses a host outside the allow-list' {
        { Invoke-TcpkExpiryProbe -Url 'http://not-authorized.invalid/x' -Header "Authorization: Bearer $($script:expiredJwt)" `
            -ConfirmActive -Target $script:hostAllow } | Should -Throw -ExpectedMessage '*allow-list*'
    }
}

Describe 'Invoke-TcpkExpiryProbe: a route that ignores exp' {
    BeforeAll {
        $script:bad = @(Invoke-TcpkExpiryProbe -Url "$($script:base)/no-expiry-check" `
            -Header "Authorization: Bearer $($script:expiredJwt)" -ConfirmActive -Target $script:hostAllow)
    }

    It 'confirms the expired token was accepted' {
        $f = @($script:bad | Where-Object { $_.RuleId -eq 'expiry.expired-token-accepted' })
        $f.Count | Should -Be 1
        $f[0].Severity | Should -Be 'HIGH'
        $f[0].Confidence | Should -Be 'Confirmed (exploit)'
    }

    It 'cites BOTH clocks from the server, never the local machine' {
        $f = @($script:bad | Where-Object { $_.RuleId -eq 'expiry.expired-token-accepted' })
        "$($f[0].Evidence)" | Should -Match 'token exp='
        "$($f[0].Evidence)" | Should -Match 'server Date='
        "$($f[0].Evidence)" | Should -Match 'past exp'
    }

    It 'records that the no-credential control was rejected, ruling out an open route' {
        $f = @($script:bad | Where-Object { $_.RuleId -eq 'expiry.expired-token-accepted' })
        "$($f[0].Description)" | Should -Match '(?i)no-credential control was rejected'
    }

    It 'states the token was replayed unmodified, separating this from token forgery' {
        $f = @($script:bad | Where-Object { $_.RuleId -eq 'expiry.expired-token-accepted' })
        "$($f[0].Description)" | Should -Match '(?i)unmodified and unre-signed|byte-identical'
    }
}

Describe 'Invoke-TcpkExpiryProbe: a route that enforces exp' {
    BeforeAll {
        $script:good = @(Invoke-TcpkExpiryProbe -Url "$($script:base)/enforced" `
            -Header "Authorization: Bearer $($script:expiredJwt)" -ConfirmActive -Target $script:hostAllow)
    }

    It 'raises NO escalation finding' {
        @($script:good | Where-Object { $_.RuleId -eq 'expiry.expired-token-accepted' }).Count | Should -Be 0
    }

    It 'records the clean result, so it differs from a check that never ran' {
        $f = @($script:good | Where-Object { $_.RuleId -eq 'expiry.enforced' })
        $f.Count | Should -Be 1
        $f[0].Severity | Should -Be 'INFO'
    }
}

Describe 'Invoke-TcpkExpiryProbe: an endpoint needing no credential' {
    It 'reports the missing authentication and makes NO expiry claim' {
        $f = @(Invoke-TcpkExpiryProbe -Url "$($script:base)/open" `
            -Header "Authorization: Bearer $($script:expiredJwt)" -ConfirmActive -Target $script:hostAllow)
        $o = @($f | Where-Object { $_.RuleId -eq 'expiry.endpoint-open' })
        $o.Count | Should -Be 1
        $o[0].Severity | Should -Be 'CRITICAL'
        @($f | Where-Object { $_.RuleId -eq 'expiry.expired-token-accepted' }).Count | Should -Be 0
    }
}

Describe 'Invoke-TcpkExpiryProbe: refusals that must not be silent' {
    It 'defers, with the exact re-run time, when the token has not lapsed yet' {
        $f = @(Invoke-TcpkExpiryProbe -Url "$($script:base)/no-expiry-check" `
            -Header "Authorization: Bearer $($script:soonJwt)" -ConfirmActive -Target $script:hostAllow)
        $d = @($f | Where-Object { $_.RuleId -eq 'expiry.not-yet-lapsed' })
        $d.Count | Should -Be 1
        $d[0].Confidence | Should -Be 'Skipped'
        "$($d[0].Fix)" | Should -Match '\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z'
        @($f | Where-Object { $_.RuleId -eq 'expiry.expired-token-accepted' }).Count | Should -Be 0
    }

    It 'says so when the credential declares no deadline at all' {
        $f = @(Invoke-TcpkExpiryProbe -Url "$($script:base)/no-expiry-check" `
            -Header 'Authorization: Bearer opaque-session-token-not-a-jwt' -ConfirmActive -Target $script:hostAllow)
        $n = @($f | Where-Object { $_.RuleId -eq 'expiry.no-declared-deadline' })
        $n.Count | Should -Be 1
        $n[0].Confidence | Should -Be 'Skipped'
    }

    It 'refuses a non-idempotent verb by default' {
        $f = @(Invoke-TcpkExpiryProbe -Url "$($script:base)/no-expiry-check" -Method POST -Body 'x=1' `
            -Header "Authorization: Bearer $($script:expiredJwt)" -ConfirmActive -Target $script:hostAllow)
        @($f | Where-Object { $_.RuleId -eq 'expiry.unsafe-method-refused' }).Count | Should -Be 1
    }
}

Describe 'Get-TcpkSpecJwtClaim: deadline extraction' {
    It 'finds an exp carried in a cookie, not just the Authorization header' {
        InModuleScope TCPK -Parameters @{ jwt = $script:expiredJwt } {
            param($jwt)
            $spec = New-TcpkRequestSpec -Method GET -Url 'https://x.invalid/a'
            $spec.Cookies = New-TcpkHeaderDict
            $spec.Cookies['access_token'] = $jwt
            $r = Get-TcpkSpecJwtClaim -Spec $spec
            $r | Should -Not -BeNullOrEmpty
            $r.Where | Should -Match 'access_token'
        }
    }

    It 'returns nothing for an opaque token, rather than inventing a deadline' {
        InModuleScope TCPK {
            $spec = New-TcpkRequestSpec -Method GET -Url 'https://x.invalid/a'
            $spec.Headers['Authorization'] = 'Bearer not-a-jwt-at-all'
            Get-TcpkSpecJwtClaim -Spec $spec | Should -BeNullOrEmpty
        }
    }

    It 'skips a token whose exp is out of range instead of throwing' {
        InModuleScope TCPK {
            $b64 = { param($s) [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($s)).TrimEnd('=').Replace('+','-').Replace('/','_') }
            $bad = "$(& $b64 '{"alg":"none"}').$(& $b64 '{"exp":99999999999999999}').x"
            $spec = New-TcpkRequestSpec -Method GET -Url 'https://x.invalid/a'
            $spec.Headers['Authorization'] = "Bearer $bad"
            { Get-TcpkSpecJwtClaim -Spec $spec } | Should -Not -Throw
            Get-TcpkSpecJwtClaim -Spec $spec | Should -BeNullOrEmpty
        }
    }
}
