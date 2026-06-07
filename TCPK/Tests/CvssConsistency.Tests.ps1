#requires -Version 5.1
# Guards two things:
#  1) the CVSS v4.0 engine reproduces official FIRST.org reference scores (no drift), and
#  2) a finding's displayed CVSS band never contradicts its severity badge for the
#     credential/secret family (the "CRITICAL badge but 6.9 Medium score" bug).

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
}

Describe 'CVSS v4.0 engine reproduces official anchor scores' {
    It 'matches FIRST.org reference base scores' {
        $r = & (Get-Module TCPK) {
            [pscustomobject]@{
                Max  = (Get-TcpkCvss40Score -Vector 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H').Score
                Rce  = (Get-TcpkCvss40Score -Vector 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N').Score
                None = (Get-TcpkCvss40Score -Vector 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N').Score
                Key  = (Get-TcpkCvss40Score -Vector 'CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N').Score
            }
        }
        $r.Max  | Should -Be 10.0
        $r.Rce  | Should -Be 9.3
        $r.None | Should -Be 0.0
        $r.Key  | Should -Be 8.5
    }
}

Describe 'Secret severity badge and CVSS band are consistent' {
    It 'a CRITICAL secret scores in the Critical band' {
        (& (Get-Module TCPK) { (Get-TcpkCvssVector (New-TcpkFinding -Module 'static' -RuleId 'secrets.stripe-secret' -Severity 'CRITICAL' -Confidence 'Inferred' -Title 't' -File 'x')).Rating }) | Should -Be 'Critical'
    }
    It 'a HIGH secret scores in the High band' {
        (& (Get-Module TCPK) { (Get-TcpkCvssVector (New-TcpkFinding -Module 'static' -RuleId 'secrets.pem-private-key' -Severity 'HIGH' -Confidence 'Inferred' -Title 't' -File 'x')).Rating }) | Should -Be 'High'
    }
    It 'a LOW secret scores in the Low band' {
        (& (Get-Module TCPK) { (Get-TcpkCvssVector (New-TcpkFinding -Module 'static' -RuleId 'secrets.aptabase-app-key' -Severity 'LOW' -Confidence 'Inferred' -Title 't' -File 'x')).Rating }) | Should -Be 'Low'
    }
}
