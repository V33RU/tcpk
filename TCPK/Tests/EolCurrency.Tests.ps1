#requires -Version 5.1
# Pester 5: library version-currency / EOL logic (Get-TcpkLibLifecycle, Get-TcpkEolProduct).
# Network is MOCKED so the suite stays offline and deterministic -- we assert the status math
# (eol / outdated / current) and the product mapping, not live endoflife.date data.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
}

Describe 'Native-lib -> endoflife product mapping' {
    It 'maps openssl family and sqlite family; unmapped -> null' {
        InModuleScope TCPK {
            Get-TcpkEolProduct 'libcrypto-3-x64.dll' | Should -Be 'openssl'
            Get-TcpkEolProduct 'libssl-3-x64.dll'    | Should -Be 'openssl'
            Get-TcpkEolProduct 'e_sqlite3.dll'       | Should -Be 'sqlite'
            Get-TcpkEolProduct 'zlib1.dll'           | Should -BeNullOrEmpty
            Get-TcpkEolProduct 'MyAppCore.dll'       | Should -BeNullOrEmpty
        }
    }
}

Describe 'Lifecycle status math (mocked endoflife.date)' {
    BeforeAll {
        # newest-first cycle list, as the API returns it. 3.0 eol is in the PAST (deterministic 'eol'),
        # 3.5 / 4.0 eol far in the FUTURE (so never near-eol regardless of the test clock).
        Mock -ModuleName TCPK Invoke-RestMethod {
            @(
                [pscustomobject]@{ cycle='4.0'; latest='4.0.1';  lts=$false; eol='2027-05-14' }
                [pscustomobject]@{ cycle='3.5'; latest='3.5.7';  lts=$true;  eol='2030-04-08' }
                [pscustomobject]@{ cycle='3.0'; latest='3.0.21'; lts=$false; eol='2000-01-01' }
            )
        }
    }
    It 'flags a past-EOL branch as eol' {
        InModuleScope TCPK { (Get-TcpkLibLifecycle -Name 'libcrypto' -Version '3.0.21').Status | Should -Be 'eol' }
    }
    It 'flags a supported branch behind its latest patch as outdated' {
        InModuleScope TCPK {
            $l = Get-TcpkLibLifecycle -Name 'libcrypto' -Version '3.5.0'
            $l.Status       | Should -Be 'outdated'
            $l.LatestVersion| Should -Be '4.0.1'
            $l.LtsLatest    | Should -Be '3.5.7'
        }
    }
    It 'reports current when on the newest branch at its latest patch' {
        InModuleScope TCPK { (Get-TcpkLibLifecycle -Name 'libcrypto' -Version '4.0.1').Status | Should -Be 'current' }
    }
}
