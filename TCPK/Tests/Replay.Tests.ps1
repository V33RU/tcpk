#requires -Version 5.1
# Pester 5: the replay/IDOR engine. Offline blocks unit-test the false-positive core
# (Test-TcpkResponseAccepted) and the request model. The live block drives one local
# HttpListener (readiness-polled, not a fixed sleep) that enforces a different policy per
# path, proving replay/IDOR detection with no false positives. Cross-platform.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
}

Describe 'Test-TcpkResponseAccepted (FP core)' {
    BeforeAll {
        $script:accept = @{ Status = 200; Len = 40; Hash = 'sha256:AAA'; BodyHead = 'ok'; Redirect = $null }
        $script:reject = @{ Status = 401; Len = 12; Hash = 'sha256:REJ'; BodyHead = 'no'; Redirect = $null }
    }
    It 'accepts a 200 whose body equals the accepted baseline' {
        InModuleScope TCPK -Parameters @{ a = $script:accept; r = $script:reject } {
            param($a, $r)
            $cand = @{ Status = 200; Len = 40; Hash = 'sha256:AAA' }
            (Test-TcpkResponseAccepted -Candidate $cand -AcceptRef $a -RejectRef $r) | Should -BeTrue
        }
    }
    It 'REJECTS a 200 whose body equals the reject page (status-lying backend)' {
        InModuleScope TCPK -Parameters @{ a = $script:accept; r = $script:reject } {
            param($a, $r)
            $cand = @{ Status = 200; Len = 12; Hash = 'sha256:REJ' }
            (Test-TcpkResponseAccepted -Candidate $cand -AcceptRef $a -RejectRef $r) | Should -BeFalse
        }
    }
    It 'REJECTS a 200 whose body matches neither baseline (inconclusive)' {
        InModuleScope TCPK -Parameters @{ a = $script:accept; r = $script:reject } {
            param($a, $r)
            $cand = @{ Status = 200; Len = 99; Hash = 'sha256:OTHER' }
            (Test-TcpkResponseAccepted -Candidate $cand -AcceptRef $a -RejectRef $r) | Should -BeFalse
        }
    }
    It 'REJECTS a transport error (status 0) and a 401' {
        InModuleScope TCPK -Parameters @{ a = $script:accept; r = $script:reject } {
            param($a, $r)
            (Test-TcpkResponseAccepted -Candidate @{ Status = 0; Hash = 'sha256:AAA' } -AcceptRef $a -RejectRef $r) | Should -BeFalse
            (Test-TcpkResponseAccepted -Candidate @{ Status = 401; Hash = 'sha256:AAA' } -AcceptRef $a -RejectRef $r) | Should -BeFalse
        }
    }
    It 'fuzzy matches within 2% length only when opted in and still differs from reject' {
        InModuleScope TCPK -Parameters @{ a = $script:accept; r = $script:reject } {
            param($a, $r)
            $cand = @{ Status = 200; Len = 40; Hash = 'sha256:CLOSE' }
            (Test-TcpkResponseAccepted -Candidate $cand -AcceptRef $a -RejectRef $r) | Should -BeFalse
            (Test-TcpkResponseAccepted -Candidate $cand -AcceptRef $a -RejectRef $r -FuzzyBodyMatch) | Should -BeTrue
        }
    }
}

Describe 'request model + parsers (offline)' {
    It 'ConvertFrom-TcpkRawHttp parses method/url/headers/body' {
        InModuleScope TCPK {
            $raw = "POST /api/orders/1001?ref=9 HTTP/1.1`r`nHost: shop.test`r`nAuthorization: Bearer abc`r`nContent-Type: application/json`r`n`r`n{`"note`":`"hi`"}"
            $s = ConvertFrom-TcpkRawHttp -Text $raw
            $s.Method | Should -Be 'POST'
            $s.Host   | Should -Be 'shop.test'
            $s.Path   | Should -Be '/api/orders/1001'
            $s.Query['ref'] | Should -Be '9'
            $s.HasAuthHeader | Should -BeTrue
            [Text.Encoding]::UTF8.GetString($s.Body) | Should -Match 'note'
        }
    }
    It 'rejects an absolute target whose host disagrees with the Host header' {
        InModuleScope TCPK {
            $raw = "GET http://evil.test/x HTTP/1.1`r`nHost: good.test`r`n`r`n"
            { ConvertFrom-TcpkRawHttp -Text $raw } | Should -Throw
        }
    }
    It 'Get-TcpkIdLocations finds the path id 1001' {
        InModuleScope TCPK {
            $s = New-TcpkRequestSpec -Method GET -Url 'https://shop.test/api/orders/1001' -Header @('Authorization: Bearer a')
            $locs = @(Get-TcpkIdLocations -Spec $s)
            ($locs | Where-Object { $_.Kind -eq 'path' -and $_.Value -eq '1001' }) | Should -Not -BeNullOrEmpty
        }
    }
    It 'Set-TcpkRequestId swaps a path id and rewrites the URL' {
        InModuleScope TCPK {
            $s = New-TcpkRequestSpec -Method GET -Url 'https://shop.test/api/orders/1001'
            $loc = @(Get-TcpkIdLocations -Spec $s)[0]
            $s2 = Set-TcpkRequestId -Spec $s -Location $loc -NewValue '1002'
            $s2.Url | Should -Be 'https://shop.test/api/orders/1002'
            $s.Url  | Should -Be 'https://shop.test/api/orders/1001'
        }
    }
    It 'Remove-TcpkRequestAuth strips the Authorization header and flags it removed' {
        InModuleScope TCPK {
            $s = New-TcpkRequestSpec -Method GET -Url 'https://shop.test/x' -Header @('Authorization: Bearer a')
            $anon = Remove-TcpkRequestAuth -Spec $s
            $anon.HasAuthHeader | Should -BeFalse
            $anon.AuthActuallyRemoved | Should -BeTrue
        }
    }
    It 'Remove-TcpkRequestAuth flags removal when stripping the bearer but keeping a cookie' {
        InModuleScope TCPK {
            $s = New-TcpkRequestSpec -Method GET -Url 'https://shop.test/x' -Header @('Authorization: Bearer a', 'Cookie: sid=x')
            $anon = Remove-TcpkRequestAuth -Spec $s
            $anon.AuthActuallyRemoved | Should -BeTrue
            $anon.Cookies.Contains('sid') | Should -BeTrue
        }
    }
    It 'Test-TcpkSafeMethod allows GET, blocks DELETE and side-effect GET paths' {
        InModuleScope TCPK {
            (Test-TcpkSafeMethod -Spec (New-TcpkRequestSpec -Method GET -Url 'https://s.test/x')) | Should -BeTrue
            (Test-TcpkSafeMethod -Spec (New-TcpkRequestSpec -Method DELETE -Url 'https://s.test/x')) | Should -BeFalse
            (Test-TcpkSafeMethod -Spec (New-TcpkRequestSpec -Method GET -Url 'https://s.test/user/logout')) | Should -BeFalse
        }
    }
    It 'Assert-TcpkReplayHostAllowed throws for a host not in the allow-list' {
        InModuleScope TCPK {
            $s = New-TcpkRequestSpec -Method GET -Url 'https://evil.test/x'
            { Assert-TcpkReplayHostAllowed -Spec $s -Allow @('good.test') } | Should -Throw
            (Assert-TcpkReplayHostAllowed -Spec $s -Allow @('evil.test')) | Should -BeTrue
        }
    }
    It 'Get-TcpkRequestIdCandidates emits replay.id-candidates (ungated)' {
        $f = @(Get-TcpkRequestIdCandidates -Method GET -Url 'https://shop.test/api/orders/1001?user_id=42')
        $cand = $f | Where-Object RuleId -eq 'replay.id-candidates'
        $cand | Should -Not -BeNullOrEmpty
        $cand.Evidence | Should -Match '1001'
    }
}

Describe 'Replay + IDOR + JWT probe (live, gated)' {
    BeforeAll {
        Enable-TcpkExploit -Acknowledge | Out-Null
        $l = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0); $l.Start()
        $script:port = ([System.Net.IPEndPoint]$l.LocalEndpoint).Port; $l.Stop()
        $script:base = "http://127.0.0.1:$($script:port)"
        $script:vhost = "127.0.0.1:$($script:port)"
        $script:job = Start-Job -ArgumentList $script:port -ScriptBlock {
            param($port)
            $obj = @{ '1001' = '{"order":1001,"owner":"alice","total":42}'; '1002' = '{"order":1002,"owner":"bob","total":99}' }
            $owns = @{ 'tokA' = '1001'; 'tokB' = '1002' }
            $ln = [System.Net.HttpListener]::new(); $ln.Prefixes.Add("http://127.0.0.1:$port/"); $ln.Start()
            try {
                while ($true) {
                    $c = $ln.GetContext(); $req = $c.Request; $path = $req.Url.AbsolutePath
                    $a = "$($req.Headers['Authorization'])"; $bearer = if ($a -match '^Bearer (.+)$') { $Matches[1] } else { '' }
                    $ck = "$($req.Headers['Cookie'])"; $hasSid = ($ck -match '(^|;\s*)sid=')
                    $status = 401; $body = 'DENIED'
                    switch -Regex ($path) {
                        '^/x$'                       { if ($a) { $status = 200; $body = 'PROTECTED-DATA' } else { $status = 401; $body = 'DENIED' } }
                        '^/api/orders/(\d+)$'        { $id = $Matches[1]; if (-not $bearer -and -not $hasSid) { $status = 401; $body = 'DENIED' } elseif (-not $obj.ContainsKey($id)) { $status = 404; $body = 'NOT-FOUND' } else { $status = 200; $body = $obj[$id] } }
                        '^/api/orders-secure/(\d+)$' { $id = $Matches[1]; $o = $owns[$bearer]; if (-not $o) { $status = 401; $body = 'DENIED' } elseif ($o -ne $id) { $status = 403; $body = 'FORBIDDEN' } else { $status = 200; $body = $obj[$id] } }
                        '^/api/report$'              { if ($hasSid) { $status = 200; $body = 'REPORT-DATA' } else { $status = 401; $body = 'DENIED' } }
                        '^/api/report-secure$'       { if ($bearer -in 'tokA', 'tokB') { $status = 200; $body = 'REPORT-DATA' } else { $status = 401; $body = 'DENIED' } }
                        '^/api/public/(\d+)$'        { $id = $Matches[1]; if ($obj.ContainsKey($id)) { $status = 200; $body = $obj[$id] } else { $status = 404; $body = 'NOT-FOUND' } }
                        '^/api/same/(\d+)$'          { $id = $Matches[1]; if (-not $bearer) { $status = 401; $body = 'DENIED' } elseif ($obj.ContainsKey($id)) { $status = 200; $body = 'SAME-BODY' } else { $status = 404; $body = 'NOT-FOUND' } }
                        default { $status = 404; $body = 'NO-ROUTE' }
                    }
                    $c.Response.StatusCode = $status
                    $b = [Text.Encoding]::UTF8.GetBytes($body); $c.Response.OutputStream.Write($b, 0, $b.Length); $c.Response.Close()
                }
            } finally { $ln.Stop() }
        }
        # readiness poll (Start-Job can be slow to spin up on some hosts)
        $script:ready = $false
        foreach ($i in 1..100) {
            try { Invoke-WebRequest -Uri "$($script:base)/x" -TimeoutSec 1 -SkipHttpErrorCheck -ErrorAction Stop | Out-Null; $script:ready = $true; break }
            catch { Start-Sleep -Milliseconds 300 }
        }
    }
    AfterAll {
        try { Disable-TcpkExploit | Out-Null } catch {}
        if ($script:job) { Stop-Job $script:job -EA SilentlyContinue; Remove-Job $script:job -Force -EA SilentlyContinue }
    }

    It 'listener came up' { $script:ready | Should -BeTrue }

    It 'New-TcpkHttpSnapshot returns status/len/hash' {
        InModuleScope TCPK -Parameters @{ url = "$($script:base)/x" } {
            param($url)
            $s = New-TcpkHttpSnapshot -Method GET -Url $url -Headers @{ Authorization = 'Bearer t' }
            $s.Status | Should -Be 200
            $s.Hash   | Should -Match '^sha256:'
            $s.BodyHead | Should -Match 'PROTECTED'
        }
    }
    It 'Invoke-TcpkJwtProbe accept-vs-anon bodies differ and drive the predicate' {
        InModuleScope TCPK -Parameters @{ url = "$($script:base)/x" } {
            param($url)
            $valid = Invoke-TcpkJwtProbe -Url $url -Token 'eyJ.a.b'
            $anon = Invoke-TcpkJwtProbe -Url $url -Token ''
            $valid.Status | Should -Be 200
            $anon.Status | Should -Be 401
            $valid.Hash | Should -Not -Be $anon.Hash
            (Test-TcpkResponseAccepted -Candidate $valid -AcceptRef $valid -RejectRef $anon) | Should -BeTrue
        }
    }
    It 'Invoke-TcpkReplay confirms missing function-level authz (bearer not enforced)' {
        $f = @(Invoke-TcpkReplay -Url "$($script:base)/api/report" -Header @('Authorization: Bearer tokA', 'Cookie: sid=sess-alice') -Target $script:vhost -ConfirmActive)
        $m = $f | Where-Object RuleId -eq 'replay.missing-authz'
        $m | Should -Not -BeNullOrEmpty
        $m.Confidence | Should -Be 'Confirmed (exploit)'
    }
    It 'Invoke-TcpkReplay reports authz-enforced when the credential is required' {
        $f = @(Invoke-TcpkReplay -Url "$($script:base)/api/report-secure" -Header @('Authorization: Bearer tokA') -Target $script:vhost -ConfirmActive)
        ($f | Where-Object RuleId -eq 'replay.authz-enforced') | Should -Not -BeNullOrEmpty
        ($f | Where-Object RuleId -eq 'replay.missing-authz') | Should -BeNullOrEmpty
    }
    It 'Invoke-TcpkReplay blocks a non-idempotent verb and sends nothing' {
        $f = @(Invoke-TcpkReplay -Method DELETE -Url "$($script:base)/api/orders/1001" -Header @('Authorization: Bearer tokA') -Target $script:vhost -ConfirmActive)
        ($f | Where-Object RuleId -eq 'replay.blocked-unsafe-method') | Should -Not -BeNullOrEmpty
    }
    It 'Invoke-TcpkIdorProbe confirms horizontal IDOR (A reads B''s object)' {
        $f = @(Invoke-TcpkIdorProbe -Url "$($script:base)/api/orders/1001" -Header @('Authorization: Bearer tokA') -SwapId 1002 -SecondIdentityToken tokB -Target $script:vhost -ConfirmActive)
        $h = $f | Where-Object RuleId -eq 'idor.horizontal'
        $h | Should -Not -BeNullOrEmpty
        $h.Confidence | Should -Be 'Confirmed (exploit)'
    }
    It 'Invoke-TcpkIdorProbe reports authz-enforced on the secure endpoint' {
        $f = @(Invoke-TcpkIdorProbe -Url "$($script:base)/api/orders-secure/1001" -Header @('Authorization: Bearer tokA') -SwapId 1002 -SecondIdentityToken tokB -Target $script:vhost -ConfirmActive)
        ($f | Where-Object RuleId -eq 'idor.authz-enforced') | Should -Not -BeNullOrEmpty
        ($f | Where-Object RuleId -eq 'idor.horizontal') | Should -BeNullOrEmpty
    }
    It 'Invoke-TcpkIdorProbe reports public-object (no false IDOR on public data)' {
        $f = @(Invoke-TcpkIdorProbe -Url "$($script:base)/api/public/1001" -Header @('Authorization: Bearer tokA') -SwapId 1002 -SecondIdentityToken tokB -Target $script:vhost -ConfirmActive)
        ($f | Where-Object RuleId -eq 'idor.public-object') | Should -Not -BeNullOrEmpty
        ($f | Where-Object RuleId -eq 'idor.horizontal') | Should -BeNullOrEmpty
    }
    It 'Invoke-TcpkIdorProbe reports no-object-variance when A and B objects are identical' {
        $f = @(Invoke-TcpkIdorProbe -Url "$($script:base)/api/same/1001" -Header @('Authorization: Bearer tokA') -SwapId 1002 -SecondIdentityToken tokB -Target $script:vhost -ConfirmActive)
        ($f | Where-Object RuleId -eq 'idor.no-object-variance') | Should -Not -BeNullOrEmpty
    }
    It 'Invoke-TcpkIdorProbe -AutoMutate surfaces a neighbour-id lead' {
        $f = @(Invoke-TcpkIdorProbe -Url "$($script:base)/api/orders/1001" -Header @('Authorization: Bearer tokA') -AutoMutate -Target $script:vhost -ConfirmActive)
        ($f | Where-Object RuleId -eq 'idor.candidate') | Should -Not -BeNullOrEmpty
    }
    It 'Invoke-TcpkIdorProbe / Invoke-TcpkReplay require -ConfirmActive and the gate' {
        { Invoke-TcpkIdorProbe -Url "$($script:base)/api/orders/1001" -SwapId 1002 -Target $script:vhost } | Should -Throw
        { Invoke-TcpkReplay -Url "$($script:base)/api/report" -Target $script:vhost } | Should -Throw
        Disable-TcpkExploit | Out-Null
        { Invoke-TcpkReplay -Url "$($script:base)/api/report" -Target $script:vhost -ConfirmActive } | Should -Throw
        Enable-TcpkExploit -Acknowledge | Out-Null
    }
}
