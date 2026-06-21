# Regression tests:
#   1. the attribution scoping fix (path-anchored + generic-token stopwords)
#   2. the OWASP Desktop Application Top 10 (2021) RuleId -> DA map
BeforeAll {
    Import-Module "$PSScriptRoot\..\TCPK.psd1" -Force
}

Describe 'Attribution scoping' {
    It 'Test-TcpkPathUnderTarget: in-dir path resolves under the install dir' {
        InModuleScope TCPK { Test-TcpkPathUnderTarget -Value 'C:\App\sub\x.dll' -InstallDir 'C:\App' } | Should -BeTrue
    }
    It 'Test-TcpkPathUnderTarget: System32 path is NOT under the install dir' {
        InModuleScope TCPK { Test-TcpkPathUnderTarget -Value 'C:\Windows\System32\SurfaceCaptureAPO.dll' -InstallDir 'C:\App' } | Should -BeFalse
    }
    It 'Test-TcpkPathUnderTarget: quoted path with trailing args is extracted' {
        InModuleScope TCPK { Test-TcpkPathUnderTarget -Value '"C:\App\app.exe" /S' -InstallDir 'C:\App' } | Should -BeTrue
    }
    It 'Test-TcpkPathUnderTarget: a sibling dir with a shared prefix is NOT a match' {
        InModuleScope TCPK { Test-TcpkPathUnderTarget -Value 'C:\App-evil\x.dll' -InstallDir 'C:\App' } | Should -BeFalse
    }
    It 'generic component tokens are stopworded (installer / desktop / updater)' {
        InModuleScope TCPK {
            ($script:TcpkIdentityStopwords -contains 'installer') -and
            ($script:TcpkIdentityStopwords -contains 'desktop') -and
            ($script:TcpkIdentityStopwords -contains 'updater')
        } | Should -BeTrue
    }
}

Describe 'OWASP Desktop Top 10 (2021) RuleId map' {
    It 'maps <rule>' -ForEach @(
        @{ rule = 'authenticode.pe-not-signed';     da = '^DA8' }
        @{ rule = 'truststore.app-installed-cert';  da = '^DA7' }
        @{ rule = 'scheme.cleartext-http';          da = '^DA7' }
        @{ rule = 'browser.cred-store';             da = '^DA3' }
        @{ rule = 'devartifact.internal-docs';      da = '^DA3' }
        @{ rule = 'electron.argv-session-override'; da = '^DA2' }
        @{ rule = 'electron.sandbox';               da = '^DA6' }
        @{ rule = 'firewall.inbound-allow';         da = '^DA6' }
        @{ rule = 'csv.formula-injection-risk';     da = '^DA1' }
        @{ rule = 'cve.match';                      da = '^DA9' }
    ) {
        $got = InModuleScope TCPK -Parameters @{ rule = $rule } { param($rule) Get-TcpkOwaspDa -RuleId $rule }
        $got | Should -Match $da
    }
    It 'returns empty for an unknown rule family' {
        InModuleScope TCPK { Get-TcpkOwaspDa -RuleId 'totally.unknown-rule-xyz' } | Should -BeNullOrEmpty
    }
}
