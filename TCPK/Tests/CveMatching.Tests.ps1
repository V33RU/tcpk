#requires -Version 5.1
# Pester 5: online CVE version math -- the numeric semver comparison (shared by NVD range
# filtering) and the NVD cpeName version-bound filter. CVE matching is online-only (no offline
# catalog), so these assert the deterministic version logic without touching the network.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
}

Describe 'CVE version comparison is numeric, not lexical' {
    # A lexical string compare ranks "3.0.21" < "3.0.8" ('2' < '8'), which would mis-order native
    # library versions in the NVD range filter. Test-TcpkSemVerLt compares each component as an
    # integer so 3.0.21 is correctly NEWER than 3.0.8.
    It 'ranks 3.0.21 as NEWER than 3.0.8 (21 > 8), not older' {
        InModuleScope TCPK {
            (Test-TcpkSemVerLt -A '3.0.21' -B '3.0.8')  | Should -BeFalse
            (Test-TcpkSemVerLt -A '3.0.8'  -B '3.0.21') | Should -BeTrue
        }
    }
    It 'compares multi-digit and mixed components correctly' {
        InModuleScope TCPK {
            (Test-TcpkSemVerLt -A '3.0.13' -B '3.0.9')  | Should -BeFalse   # 13 > 9
            (Test-TcpkSemVerLt -A '1.1.1w' -B '3.0.8')  | Should -BeTrue    # 1.x < 3.x
            (Test-TcpkSemVerLt -A '3.0.0'  -B '3.0.0')  | Should -BeFalse   # equal -> not below
        }
    }
}

Describe 'NVD native CVE filter (offline / no network)' {
    # The NVD cpeName query over-returns: old CVEs whose CPE has NO version bound match every
    # version, so a current patched lib looks vulnerable. Test-TcpkNvdInRange must keep ONLY
    # CVEs whose match range actually bounds the shipped version, and drop unbounded/wildcard ones.
    It 'drops an unbounded match (no versionEnd) even if it names the product' {
        InModuleScope TCPK {
            (Test-TcpkNvdInRange -Shipped '3.0.21' -CpeMatch ([pscustomobject]@{ versionStartIncluding='1.1.1' })) | Should -BeFalse
            (Test-TcpkNvdInRange -Shipped '3.0.21' -CpeMatch ([pscustomobject]@{}))                                | Should -BeFalse
        }
    }
    It 'keeps a bounded match only when the shipped version is inside [start,end)' {
        InModuleScope TCPK {
            # CVE fixed in 3.0.8 -> 3.0.0 affected, 3.0.21 not.
            $cm = [pscustomobject]@{ versionEndExcluding='3.0.8' }
            (Test-TcpkNvdInRange -Shipped '3.0.0'  -CpeMatch $cm) | Should -BeTrue
            (Test-TcpkNvdInRange -Shipped '3.0.21' -CpeMatch $cm) | Should -BeFalse
            # with a start bound too
            $cm2 = [pscustomobject]@{ versionStartIncluding='3.0.0'; versionEndExcluding='3.0.8' }
            (Test-TcpkNvdInRange -Shipped '1.1.1'  -CpeMatch $cm2) | Should -BeFalse   # below start
            (Test-TcpkNvdInRange -Shipped '3.0.5'  -CpeMatch $cm2) | Should -BeTrue
        }
    }
    It 'maps only known native libs to a CPE (unmapped -> null, no guess)' {
        InModuleScope TCPK {
            (Get-TcpkNvdCpe 'libcrypto-3-x64.dll')[1] | Should -Be 'openssl'
            (Get-TcpkNvdCpe 'zlib1.dll')[1]           | Should -Be 'zlib'
            (Get-TcpkNvdCpe 'e_sqlite3.dll')[1]       | Should -Be 'sqlite'
            Get-TcpkNvdCpe 'MyAppCore.dll'            | Should -BeNullOrEmpty
        }
    }
    It 'expanded map resolves common libs (verified CPEs) and ABI-suffixed names' {
        InModuleScope TCPK {
            (Get-TcpkNvdCpe 'libpng16.dll')[0]  | Should -Be 'libpng'      # trailing-digit strip
            (Get-TcpkNvdCpe 'libssl-3-x64.dll')[1] | Should -Be 'openssl'  # -N-arch strip
            (Get-TcpkNvdCpe 'libcurl.dll')[0]   | Should -Be 'haxx'        # curl is haxx:libcurl, not curl:curl
            (Get-TcpkNvdCpe 'libssh2.dll')[1]   | Should -Be 'libssh2'
            (Get-TcpkNvdCpe 'libtiff.dll')[1]   | Should -Be 'libtiff'
        }
    }
    It 'rejects the CPEs that did not resolve on NVD (removed, no false confidence)' {
        InModuleScope TCPK {
            Get-TcpkNvdCpe 'libyaml.dll'  | Should -BeNullOrEmpty
            Get-TcpkNvdCpe 'libevent.dll' | Should -BeNullOrEmpty
            Get-TcpkNvdCpe 'pcre2.dll'    | Should -BeNullOrEmpty
        }
    }
}
