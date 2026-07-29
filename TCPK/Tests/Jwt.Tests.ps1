#requires -Version 5.1
# Pester 5: offline JWT crypto core (_Jwt.ps1) + Invoke-TcpkJwtCrack. Pure crypto and
# dictionary crack; no network. Includes the canonical jwt.io KAT vector to prove the
# b64url + HMAC implementation is byte-exact with reference JWT libraries.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
    Enable-TcpkExploit -Acknowledge | Out-Null
}
AfterAll { try { Disable-TcpkExploit | Out-Null } catch {} }

Describe 'b64url encode/decode' {
    It 'Convert-TcpkToB64Url round-trips Convert-TcpkFromB64Url and is url-safe, padding-free' {
        InModuleScope TCPK {
            $bytes = [Text.Encoding]::UTF8.GetBytes('hello/world+data==?')
            $enc = Convert-TcpkToB64Url -Bytes $bytes
            $enc | Should -Not -Match '[+/=]'
            $dec = Convert-TcpkFromB64Url -Text $enc
            [Text.Encoding]::UTF8.GetString($dec) | Should -Be 'hello/world+data==?'
        }
    }
    It 'encodes empty input as empty string' {
        InModuleScope TCPK { (Convert-TcpkToB64Url -Bytes ([byte[]]@())) | Should -Be '' }
    }
}

Describe 'JWT HMAC (_Jwt.ps1)' {
    It 'matches the canonical jwt.io KAT vector (HS256)' {
        InModuleScope TCPK {
            $si = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ'
            $sig = New-TcpkJwtHmac -SigningInput $si -Key ([Text.Encoding]::UTF8.GetBytes('your-256-bit-secret')) -Alg 'HS256'
            $sig | Should -Be 'SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'
        }
    }
    It 'Test-TcpkJwtHmacSecret is true for the right secret, false for a wrong one' {
        InModuleScope TCPK {
            $tok = New-TcpkJwtToken -Header ([ordered]@{ alg = 'HS256'; typ = 'JWT' }) `
                -Payload ([ordered]@{ sub = 'admin'; role = 'admin' }) -Alg 'HS256' -Key ([Text.Encoding]::UTF8.GetBytes('secret123'))
            (Test-TcpkJwtHmacSecret -Token $tok -Secret 'secret123' -Alg 'HS256') | Should -BeTrue
            (Test-TcpkJwtHmacSecret -Token $tok -Secret 'nope'      -Alg 'HS256') | Should -BeFalse
        }
    }
    It 'New-TcpkJwtToken with alg=none yields h.p. (empty signature segment)' {
        InModuleScope TCPK {
            $tok = New-TcpkJwtToken -Header ([ordered]@{ alg = 'none'; typ = 'JWT' }) `
                -Payload ([ordered]@{ sub = 'admin' }) -Alg 'none'
            $tok.EndsWith('.') | Should -BeTrue
            ($tok.Split('.')).Count | Should -Be 3
            ($tok.Split('.'))[2] | Should -Be ''
        }
    }
}

Describe 'ConvertFrom-TcpkJwt' {
    It 'decodes a real 3-segment token' {
        InModuleScope TCPK {
            $tok = New-TcpkJwtToken -Header ([ordered]@{ alg = 'HS256'; typ = 'JWT' }) `
                -Payload ([ordered]@{ sub = 'u1'; role = 'user' }) -Alg 'HS256' -Key ([Text.Encoding]::UTF8.GetBytes('k'))
            $j = ConvertFrom-TcpkJwt -Token $tok
            $j.Valid | Should -BeTrue
            $j.Alg   | Should -Be 'HS256'
            $j.Payload.role | Should -Be 'user'
            $j.SigningInput | Should -Be ($tok.Split('.')[0] + '.' + $tok.Split('.')[1])
        }
    }
    It 'returns Valid=$false (no throw) for an opaque non-JWT bearer' {
        InModuleScope TCPK {
            $j = ConvertFrom-TcpkJwt -Token 'opaque-session-abc123'
            $j.Valid | Should -BeFalse
        }
    }
}

Describe 'Invoke-TcpkJwtCrack (offline, gated)' {
    It 'recovers a weak HMAC secret and reports jwt.weak-secret CONFIRMED without leaking the secret' {
        $tok = & (Get-Module TCPK) {
            New-TcpkJwtToken -Header ([ordered]@{ alg = 'HS256'; typ = 'JWT' }) `
                -Payload ([ordered]@{ sub = 'admin'; role = 'admin' }) -Alg 'HS256' -Key ([Text.Encoding]::UTF8.GetBytes('secret123'))
        }
        $f = @(Invoke-TcpkJwtCrack -Token $tok)
        $weak = $f | Where-Object RuleId -eq 'jwt.weak-secret'
        $weak | Should -Not -BeNullOrEmpty
        $weak.Severity   | Should -Be 'CRITICAL'
        $weak.Confidence | Should -Be 'Confirmed'
        # the recovered secret must never appear in the finding
        ($weak | ConvertTo-Json -Depth 6) | Should -Not -Match 'secret123'
    }
    It 'flags an alg=none token as jwt.alg-none-issued HIGH Confirmed' {
        $tok = & (Get-Module TCPK) {
            New-TcpkJwtToken -Header ([ordered]@{ alg = 'none'; typ = 'JWT' }) -Payload ([ordered]@{ sub = 'admin' }) -Alg 'none'
        }
        $f = @(Invoke-TcpkJwtCrack -Token $tok)
        $none = $f | Where-Object RuleId -eq 'jwt.alg-none-issued'
        $none | Should -Not -BeNullOrEmpty
        $none.Severity | Should -Be 'HIGH'
    }
    It 'reports jwt.not-a-token for an opaque bearer' {
        (@(Invoke-TcpkJwtCrack -Token 'opaque-abc') | Where-Object RuleId -eq 'jwt.not-a-token') | Should -Not -BeNullOrEmpty
    }
    It 'is gated behind Enable-TcpkExploit' {
        Disable-TcpkExploit | Out-Null
        { Invoke-TcpkJwtCrack -Token 'x.y.z' } | Should -Throw
        Enable-TcpkExploit -Acknowledge | Out-Null
    }
}
