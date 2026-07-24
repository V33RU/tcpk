#requires -Version 5.1
# CVE native-banner scan: a statically-linked native library has no matching DLL
# basename, but stamps its version banner into the host binary (a statically-linked
# OpenSSL leaves "OpenSSL 3.0.x" inside app.exe). The scan must pick that up and feed
# it to the NVD-by-CPE path. NVD/KEV are mocked so the test is offline + deterministic.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force

    $script:work = Join-Path ([IO.Path]::GetTempPath()) ("tcpk-cveb-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:work -Force | Out-Null
    # a "native" app.exe with a statically-linked OpenSSL banner, no libssl*.dll on disk
    $blob = ("MZ padding padding " * 8) + "OpenSSL 3.0.1 14 Dec 2021" + (" trailer" * 8)
    [IO.File]::WriteAllText((Join-Path $script:work 'app.exe'), $blob, [Text.Encoding]::ASCII)
}

AfterAll {
    if ($script:work -and (Test-Path -LiteralPath $script:work)) {
        try { [System.IO.Directory]::Delete($script:work, $true) } catch {}
    }
}

Describe 'CVE native-banner scan (statically-linked libs)' {
    It 'extracts an OpenSSL banner from app.exe and feeds it to the NVD-by-CPE path' {
        $r = InModuleScope TCPK -Parameters @{ dir = $script:work } {
            param($dir)
            # capture what the NVD path is asked to look up; return a synthetic match per component
            Mock Get-TcpkNvdMatches {
                param($Components, $TimeoutSec, $ApiKey)
                @($Components | ForEach-Object {
                    [pscustomobject]@{ Cve = 'CVE-2022-0778'; Package = $_.Name; ShippedVersion = $_.Version
                        FixedVersion = '3.0.2'; Severity = 'high'; Title = 'test'; File = $_.File }
                })
            }
            Mock Get-TcpkOsvMatches { @() }
            Mock Get-TcpkKevSet { , (New-Object 'System.Collections.Generic.HashSet[string]') }
            @(Get-TcpkCveMatches -Path $dir)
        }
        $hit = $r | Where-Object { $_.ShippedVersion -eq '3.0.1' -and $_.Package -match 'openssl' }
        $hit | Should -Not -BeNullOrEmpty
        $hit.Cve  | Should -Be 'CVE-2022-0778'
        $hit.File | Should -Match 'app\.exe'
    }

    It 'does not invent a component when no known banner is present' {
        $clean = Join-Path $script:work 'sub'
        New-Item -ItemType Directory -Path $clean -Force | Out-Null
        [IO.File]::WriteAllText((Join-Path $clean 'plain.exe'), 'no library banners here at all', [Text.Encoding]::ASCII)
        $r = InModuleScope TCPK -Parameters @{ dir = $clean } {
            param($dir)
            Mock Get-TcpkNvdMatches { param($Components) @($Components | ForEach-Object { [pscustomobject]@{ Cve = 'X'; Package = $_.Name; ShippedVersion = $_.Version; FixedVersion = ''; Severity = 'low'; Title = ''; File = $_.File } }) }
            Mock Get-TcpkOsvMatches { @() }
            Mock Get-TcpkKevSet { , (New-Object 'System.Collections.Generic.HashSet[string]') }
            @(Get-TcpkCveMatches -Path $dir)
        }
        ($r | Where-Object { $_.Package -match 'openssl|sqlite|zlib' }) | Should -BeNullOrEmpty
    }
}
