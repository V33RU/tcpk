#requires -Version 5.1
# Pester 5: gated active probe - Test-TcpkTlsHandshake. Asserts the cmdlet is exported,
# refuses without Enable-TcpkExploit, and (once enabled) behaves deterministically
# against an unreachable loopback port. A full live handshake is environment-dependent
# and exercised manually.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
    try { Disable-TcpkExploit | Out-Null } catch {}
}
AfterAll {
    try { Disable-TcpkExploit | Out-Null } catch {}
}

Describe 'Test-TcpkTlsHandshake (gated)' {
    It 'is exported' {
        Get-Command Test-TcpkTlsHandshake -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
    }
    It 'refuses without Enable-TcpkExploit' {
        try { Disable-TcpkExploit | Out-Null } catch {}
        { Test-TcpkTlsHandshake -Endpoint '127.0.0.1:1' } | Should -Throw
    }
    It 'returns tls-handshake.unreachable for a dead port (no throw) once enabled' {
        Enable-TcpkExploit -Acknowledge | Out-Null
        $r = @(Test-TcpkTlsHandshake -Endpoint '127.0.0.1:9' -TimeoutMs 1500)
        ($r | Where-Object RuleId -eq 'tls-handshake.unreachable') | Should -Not -BeNullOrEmpty
    }
}
