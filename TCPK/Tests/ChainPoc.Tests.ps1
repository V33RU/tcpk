#requires -Version 5.1
# Pester 5: New-TcpkChainPoc emits a lab-safe PoC procedure for each correlated exploit chain,
# reusing the tested Get-TcpkExploitChains matcher. Offline, gated. Cross-platform.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
    Enable-TcpkExploit -Acknowledge | Out-Null
    function New-F($rid, $sev, $file) {
        & (Get-Module TCPK) { param($r, $s, $f) New-TcpkFinding -Module 'x' -RuleId $r -Severity $s -Confidence 'Confirmed' -Title $r -File $f } $rid $sev $file
    }
}
AfterAll { try { Disable-TcpkExploit | Out-Null } catch {} }

Describe 'New-TcpkChainPoc (gated)' {
    It 'emits a PoC procedure with the concrete writable-binary artifact' {
        $findings = @((New-F 'service.writable-binary' 'HIGH' 'C:\Program Files\Vuln\svc.exe'))
        $poc = @($findings | New-TcpkChainPoc)
        $p = $poc | Where-Object RuleId -eq 'chain.writable-privileged-binary.poc'
        $p | Should -Not -BeNullOrEmpty
        $p.Severity | Should -Be 'CRITICAL'
        $p.Description | Should -Match 'svc\.exe'          # artifact filled in
        $p.Description | Should -Match 'proof-of-control|STOP'
        $p.Description | Should -Match 'tcpk-poc-marker'    # lab-safe marker present
    }
    It 'emits a PoC for the impactful-privilege chain naming the sink' {
        $findings = @((New-F 'process.impactful-privileges' 'MEDIUM' 'app.exe'), (New-F 'callsites.command-execution' 'HIGH' 'Runner.dll'))
        $poc = @($findings | New-TcpkChainPoc)
        ($poc | Where-Object RuleId -eq 'chain.impactful-priv-to-system.poc') | Should -Not -BeNullOrEmpty
    }
    It 'emits nothing when no chain fires' {
        $findings = @((New-F 'entropy.high-entropy-string' 'LOW' 'a.txt'))
        @($findings | New-TcpkChainPoc) | Should -BeNullOrEmpty
    }
    It 'never weaponises: no persistence / shellcode / real payload language' {
        $findings = @((New-F 'service.writable-binary' 'HIGH' 'svc.exe'))
        $p = @($findings | New-TcpkChainPoc)[0]
        $p.Description | Should -Not -Match 'shellcode|meterpreter|reverse shell|persistence'
    }
    It 'is gated behind Enable-TcpkExploit' {
        Disable-TcpkExploit | Out-Null
        { @((New-F 'service.writable-binary' 'HIGH' 'svc.exe')) | New-TcpkChainPoc } | Should -Throw
        Enable-TcpkExploit -Acknowledge | Out-Null
    }
}
