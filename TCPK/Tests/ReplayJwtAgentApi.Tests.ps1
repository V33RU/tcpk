#requires -Version 5.1
# Pester 5: the agentic web-workbench backends for the replay/IDOR/JWT actions. Control flow
# and redaction only (no browser): every active backend refuses without confirm/gate, the
# offline backends return findings, and no secret/token leaks into the returned payload.
# The live findings paths are proven by Replay.Tests / JwtAttack.Tests.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
}
AfterAll { try { Disable-TcpkExploit | Out-Null } catch {} }

Describe 'agentic backends: control flow + redaction' {
    It 'Get-TcpkAgentReplayCandidates returns id-candidates for a pasted request (offline)' {
        InModuleScope TCPK {
            $raw = "GET /api/orders/1001 HTTP/1.1`r`nHost: shop.test`r`n`r`n"
            $r = Get-TcpkAgentReplayCandidates -Request $raw
            $r.error | Should -BeNullOrEmpty
            ($r.findings | Where-Object { $_.rule -eq 'replay.id-candidates' }) | Should -Not -BeNullOrEmpty
        }
    }
    It 'Get-TcpkAgentReplay refuses without confirm and without a request' {
        InModuleScope TCPK {
            (Get-TcpkAgentReplay -Request 'x' -Target 'shop.test' -Confirm:$false).error | Should -Match 'confirm'
            (Get-TcpkAgentReplay -Request '' -Target 'shop.test' -Confirm:$true).error | Should -Match 'request|paste'
            (Get-TcpkAgentReplay -Request 'x' -Target '' -Confirm:$true).error | Should -Match 'host'
        }
    }
    It 'Get-TcpkAgentIdor refuses without confirm' {
        InModuleScope TCPK {
            (Get-TcpkAgentIdor -Request 'x' -Target 'shop.test' -SwapId '2' -Confirm:$false).error | Should -Match 'confirm'
        }
    }
    It 'Get-TcpkAgentJwtAttack refuses without confirm' {
        InModuleScope TCPK {
            (Get-TcpkAgentJwtAttack -Token 'eyJ.a.b' -Target 'http://x' -Confirm:$false).error | Should -Match 'confirm'
        }
    }
    It 'Get-TcpkAgentJwtCrack cracks a weak token and never returns the secret' {
        Enable-TcpkExploit -Acknowledge | Out-Null
        $payload = & (Get-Module TCPK) {
            $tok = New-TcpkJwtToken -Header ([ordered]@{ alg = 'HS256'; typ = 'JWT' }) -Payload ([ordered]@{ sub = 'admin' }) -Alg 'HS256' -Key ([Text.Encoding]::UTF8.GetBytes('secret123'))
            Get-TcpkAgentJwtCrack -Token $tok
        }
        ($payload.findings | Where-Object { $_.rule -eq 'jwt.weak-secret' }) | Should -Not -BeNullOrEmpty
        ($payload | ConvertTo-Json -Depth 8) | Should -Not -Match 'secret123'
    }
    It 'Get-TcpkAgentJwtCrack surfaces the gate error when the Exploit bucket is disabled' {
        Disable-TcpkExploit | Out-Null
        InModuleScope TCPK {
            (Get-TcpkAgentJwtCrack -Token 'eyJ.a.b').error | Should -Match 'Enable-TcpkExploit|gated'
        }
        Enable-TcpkExploit -Acknowledge | Out-Null
    }
}
