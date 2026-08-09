#requires -Version 5.1
# Pester 5: Invoke-TcpkAuthMatrix against a real local HttpListener that enforces roles.
#
# Not mocked. The listener implements an actual privilege model so the matrix is exercised
# end to end: a route that checks the role correctly must produce NO escalation finding,
# and a route that only checks authentication must produce one. A test that only asserted
# the broken case would pass just as happily against a cmdlet that flags everything.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
    Enable-TcpkExploit -Acknowledge | Out-Null

    $l = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0); $l.Start()
    $script:port = ([System.Net.IPEndPoint]$l.LocalEndpoint).Port; $l.Stop()
    $script:base = "http://127.0.0.1:$($script:port)"

    # Two routes, same two tokens:
    #   /admin-only  -> requires the admin token           (correctly enforced)
    #   /broken      -> requires ANY token, role unchecked (the defect being hunted)
    $script:job = Start-Job -ArgumentList $script:port -ScriptBlock {
        param($port)
        $ln = [System.Net.HttpListener]::new()
        $ln.Prefixes.Add("http://127.0.0.1:$port/")
        $ln.Start()
        while ($ln.IsListening) {
            $ctx = $ln.GetContext()
            $req = $ctx.Request; $res = $ctx.Response
            $auth = "$($req.Headers['Authorization'])"
            $isAdmin = ($auth -eq 'Bearer ADMIN-TOKEN')
            $isUser  = ($auth -eq 'Bearer USER-TOKEN')
            $body = ''; $code = 403
            switch -Regex ($req.Url.AbsolutePath) {
                '/shutdown' { $code = 200; $body = 'bye'; $res.StatusCode = 200
                              $b = [Text.Encoding]::UTF8.GetBytes($body)
                              $res.OutputStream.Write($b, 0, $b.Length); $res.Close()
                              $ln.Stop(); return }
                '/admin-only' {
                    if ($isAdmin) { $code = 200; $body = 'SECRET-ADMIN-PAYLOAD-0123456789' }
                    elseif ($isUser) { $code = 403; $body = 'forbidden' }
                    else { $code = 401; $body = 'unauthorized' }
                }
                '/broken' {
                    # Authenticates but never checks the role: both tokens get the payload.
                    if ($isAdmin -or $isUser) { $code = 200; $body = 'SECRET-ADMIN-PAYLOAD-0123456789' }
                    else { $code = 401; $body = 'unauthorized' }
                }
                '/public' { $code = 200; $body = 'SECRET-ADMIN-PAYLOAD-0123456789' }
                default   { $code = 404; $body = 'nope' }
            }
            $res.StatusCode = $code
            $b = [Text.Encoding]::UTF8.GetBytes($body)
            $res.OutputStream.Write($b, 0, $b.Length)
            $res.Close()
        }
    }

    # Wait for the listener to accept connections.
    $script:up = $false
    for ($i = 0; $i -lt 40; $i++) {
        try {
            $c = [System.Net.Sockets.TcpClient]::new(); $c.Connect('127.0.0.1', $script:port); $c.Close()
            $script:up = $true; break
        } catch { Start-Sleep -Milliseconds 250 }
    }

    $script:roles = @(
        @{ Name = 'admin'; Header = 'Authorization: Bearer ADMIN-TOKEN' },
        @{ Name = 'user';  Header = 'Authorization: Bearer USER-TOKEN'  }
    )
}

AfterAll {
    try { Invoke-WebRequest -Uri "$($script:base)/shutdown" -TimeoutSec 3 -UseBasicParsing | Out-Null } catch { }
    if ($script:job) { Stop-Job $script:job -ErrorAction SilentlyContinue; Remove-Job $script:job -Force -ErrorAction SilentlyContinue }
    try { Disable-TcpkExploit | Out-Null } catch { }
}

Describe 'Invoke-TcpkAuthMatrix: safety gates' {
    It 'refuses to run without -ConfirmActive' {
        { Invoke-TcpkAuthMatrix -Role $script:roles -Url "$($script:base)/admin-only" -Target "127.0.0.1:$($script:port)" } |
            Should -Throw -ExpectedMessage '*ConfirmActive*'
    }

    It 'refuses a single role, because a matrix of one compares nothing' {
        { Invoke-TcpkAuthMatrix -Role @(@{ Name = 'only'; Header = 'Authorization: Bearer X' }) `
            -Url "$($script:base)/admin-only" -ConfirmActive -Target "127.0.0.1:$($script:port)" } |
            Should -Throw -ExpectedMessage '*at least two roles*'
    }

    It 'refuses a host that is not in the allow-list' {
        { Invoke-TcpkAuthMatrix -Role $script:roles -Url 'http://not-authorized.invalid/admin' `
            -ConfirmActive -Target "127.0.0.1:$($script:port)" } |
            Should -Throw -ExpectedMessage '*allow-list*'
    }
}

Describe 'Invoke-TcpkAuthMatrix: a correctly enforced route' -Skip:(-not $script:up) {
    BeforeAll {
        $script:okF = @(Invoke-TcpkAuthMatrix -Role $script:roles -Url "$($script:base)/admin-only" `
            -ConfirmActive -Target "127.0.0.1:$($script:port)")
    }

    It 'reports NO vertical escalation when the lower role is denied' {
        @($script:okF | Where-Object { $_.RuleId -eq 'authmatrix.vertical-escalation' }).Count | Should -Be 0
    }

    It 'still emits the matrix, so a clean result is distinguishable from a run that never happened' {
        $m = @($script:okF | Where-Object { $_.RuleId -eq 'authmatrix.matrix' })
        $m.Count | Should -Be 1
        "$($m[0].Title)" | Should -Match '0 escalation'
        "$($m[0].Evidence)" | Should -Match '(?i)admin'
        "$($m[0].Evidence)" | Should -Match '(?i)user'
    }
}

Describe 'Invoke-TcpkAuthMatrix: a route that authenticates but never checks the role' -Skip:(-not $script:up) {
    BeforeAll {
        $script:badF = @(Invoke-TcpkAuthMatrix -Role $script:roles -Url "$($script:base)/broken" `
            -ConfirmActive -Target "127.0.0.1:$($script:port)")
    }

    It 'flags the lower-privilege role reaching the privileged payload' {
        $e = @($script:badF | Where-Object { $_.RuleId -eq 'authmatrix.vertical-escalation' })
        $e.Count | Should -Be 1
        $e[0].Severity | Should -Be 'HIGH'
        $e[0].Confidence | Should -Be 'Confirmed (exploit)'
    }

    It 'names both roles so the finding is actionable on its own' {
        $e = @($script:badF | Where-Object { $_.RuleId -eq 'authmatrix.vertical-escalation' })
        "$($e[0].Title)" | Should -Match "user"
        "$($e[0].Title)" | Should -Match "admin"
    }

    It 'records the no-credential control, which rules out the route simply being public' {
        $e = @($script:badF | Where-Object { $_.RuleId -eq 'authmatrix.vertical-escalation' })
        "$($e[0].Evidence)" | Should -Match '(?i)no-credential control returned 401'
    }

    It 'does not also claim missing authentication, which is a different defect' {
        @($script:badF | Where-Object { $_.RuleId -eq 'authmatrix.no-auth-accepted' }).Count | Should -Be 0
    }
}

Describe 'Invoke-TcpkAuthMatrix: a fully public route' -Skip:(-not $script:up) {
    BeforeAll {
        $script:pubF = @(Invoke-TcpkAuthMatrix -Role $script:roles -Url "$($script:base)/public" `
            -ConfirmActive -Target "127.0.0.1:$($script:port)")
    }

    It 'reports missing authentication as CRITICAL, separate from escalation' {
        $n = @($script:pubF | Where-Object { $_.RuleId -eq 'authmatrix.no-auth-accepted' })
        $n.Count | Should -Be 1
        $n[0].Severity | Should -Be 'CRITICAL'
    }

    # The false-clean case. With no authentication the no-credential control returns the
    # same bytes as the baseline, so it is simultaneously the reject and the accept
    # reference and every role scores 'denied'. The matrix must not read as a pass.
    It 'does not announce "0 escalations" on an endpoint that is wide open' {
        $m = @($script:pubF | Where-Object { $_.RuleId -eq 'authmatrix.matrix' })
        $m.Count | Should -Be 1
        "$($m[0].Title)" | Should -Not -Match '0 escalation'
        "$($m[0].Title)" | Should -Match '(?i)not conclusive'
    }

    It 'says the result is untested rather than clean, and points at the real defect first' {
        $m = @($script:pubF | Where-Object { $_.RuleId -eq 'authmatrix.matrix' })
        "$($m[0].Description)" | Should -Match '(?i)untested, not as clean'
        "$($m[0].Fix)" | Should -Match '(?i)no-auth-accepted'
    }
}

Describe 'Invoke-TcpkAuthMatrix: stale baseline' -Skip:(-not $script:up) {
    It 'stops rather than reporting every lower role as correctly denied' {
        $stale = @(
            @{ Name = 'admin'; Header = 'Authorization: Bearer EXPIRED' },
            @{ Name = 'user';  Header = 'Authorization: Bearer USER-TOKEN' }
        )
        $f = @(Invoke-TcpkAuthMatrix -Role $stale -Url "$($script:base)/admin-only" `
            -ConfirmActive -Target "127.0.0.1:$($script:port)")
        $b = @($f | Where-Object { $_.RuleId -eq 'authmatrix.baseline-not-accepted' })
        $b.Count | Should -Be 1
        $b[0].Confidence | Should -Be 'Skipped'
        @($f | Where-Object { $_.RuleId -eq 'authmatrix.vertical-escalation' }).Count | Should -Be 0
    }
}
