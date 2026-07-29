#requires -Version 5.1
# Pester 5: the replay/IDOR engine. This first block unit-tests the false-positive core
# (Test-TcpkResponseAccepted) with hand-built snapshots, then confirms the shared HTTP
# sender (New-TcpkHttpSnapshot / Invoke-TcpkJwtProbe) against a local HttpListener.
# Parser + missing-authz + IDOR blocks are added as those cmdlets land. Cross-platform.

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
            $cand = @{ Status = 200; Len = 12; Hash = 'sha256:REJ' }   # 200 with the error/login body
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
            $cand = @{ Status = 200; Len = 40; Hash = 'sha256:CLOSE' }   # ~same size, different hash
            (Test-TcpkResponseAccepted -Candidate $cand -AcceptRef $a -RejectRef $r) | Should -BeFalse
            (Test-TcpkResponseAccepted -Candidate $cand -AcceptRef $a -RejectRef $r -FuzzyBodyMatch) | Should -BeTrue
        }
    }
}

Describe 'HTTP sender + JWT probe (live)' {
    BeforeAll {
        $l = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0); $l.Start()
        $script:port = ([System.Net.IPEndPoint]$l.LocalEndpoint).Port; $l.Stop()
        $script:base = "http://127.0.0.1:$($script:port)"
        $script:job = Start-Job -ArgumentList $script:port -ScriptBlock {
            param($port)
            $ln = [System.Net.HttpListener]::new(); $ln.Prefixes.Add("http://127.0.0.1:$port/"); $ln.Start()
            try {
                while ($true) {
                    $c = $ln.GetContext()
                    $auth = "$($c.Request.Headers['Authorization'])"
                    if ($auth) { $body = 'PROTECTED-DATA'; $c.Response.StatusCode = 200 }
                    else { $body = 'DENIED'; $c.Response.StatusCode = 401 }
                    $b = [Text.Encoding]::UTF8.GetBytes($body)
                    $c.Response.OutputStream.Write($b, 0, $b.Length); $c.Response.Close()
                }
            } finally { $ln.Stop() }
        }
        Start-Sleep -Seconds 2
    }
    AfterAll { if ($script:job) { Stop-Job $script:job -EA SilentlyContinue; Remove-Job $script:job -Force -EA SilentlyContinue } }

    It 'New-TcpkHttpSnapshot returns status/len/hash and redacts nothing benign' {
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
            $anon  = Invoke-TcpkJwtProbe -Url $url -Token ''
            $valid.Status | Should -Be 200
            $anon.Status  | Should -Be 401
            $valid.Hash | Should -Not -Be $anon.Hash
            (Test-TcpkResponseAccepted -Candidate $valid -AcceptRef $valid -RejectRef $anon) | Should -BeTrue
        }
    }
}
