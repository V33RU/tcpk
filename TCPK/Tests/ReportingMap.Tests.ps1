#requires -Version 5.1
# Pester 5: reporting batch - CVSS v4.0 banding (v3.1 dropped), per-finding Impact,
# and OWASP TASVS / Desktop App Top 10 mapping (Get-TcpkTasvsMap).

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
}

Describe 'CVSS is v4.0 only' {
    It 'returns a CVSS:4.0 vector and no v3.1' {
        $b = & (Get-Module TCPK) { Get-TcpkCvssBand 'CRITICAL' }
        $b | Should -Match 'CVSS:4\.0/'
        $b | Should -Not -Match 'CVSS:3\.'
    }
}

Describe 'Get-TcpkCvssVector - per-finding, attack-archetype based' {
    It 'scores a NETWORK rule (TLS bypass) as AV:N' {
        $v = & (Get-Module TCPK) {
            $f = New-TcpkFinding -Module 'static' -RuleId 'tls-bypass.cert-callback-accepts-all' -Severity 'CRITICAL' -Title 't'
            Get-TcpkCvssVector $f
        }
        $v.Vector | Should -Match 'AV:N'
        $v.Source | Should -Be 'archetype:net-mitm'
    }
    It 'scores a LOCAL rule (weak ACL) as AV:L, not AV:N' {
        $v = & (Get-Module TCPK) {
            $f = New-TcpkFinding -Module 'os' -RuleId 'acl.world-writable' -Severity 'CRITICAL' -Title 't'
            Get-TcpkCvssVector $f
        }
        $v.Vector | Should -Match 'AV:L'
        $v.Vector | Should -Not -Match 'AV:N'
        $v.Source | Should -Be 'archetype:local-privesc'
    }
    It 'scores a shipped credential with a severity-matched, consistent vector' {
        # Credential/secret family is severity-tiered so the CVSS band always matches the
        # badge: CRITICAL -> live-credential (network read+write). A MEDIUM secret would
        # instead map to shipped-secret (local, confidentiality-only).
        $v = & (Get-Module TCPK) {
            $f = New-TcpkFinding -Module 'static' -RuleId 'secrets.azure-storage-connection-string' -Severity 'CRITICAL' -Title 't'
            Get-TcpkCvssVector $f
        }
        $v.Source | Should -Be 'archetype:live-credential'
        $v.Rating | Should -Be 'Critical'
        $v.Vector | Should -Match 'VC:H'
        $v.Vector | Should -Match 'VI:H'
    }
    It 'maps a MEDIUM secret to the local confidentiality-only archetype' {
        $v = & (Get-Module TCPK) {
            $f = New-TcpkFinding -Module 'static' -RuleId 'secrets.some-low-value-token' -Severity 'MEDIUM' -Title 't'
            Get-TcpkCvssVector $f
        }
        $v.Source | Should -Be 'archetype:shipped-secret'
        $v.Vector | Should -Match 'AV:L'
        $v.Vector | Should -Match 'VI:N'
    }
    It 'honours an explicit per-finding CVSS override' {
        $v = & (Get-Module TCPK) {
            $f = New-TcpkFinding -Module 'static' -RuleId 'anything.x' -Severity 'HIGH' -Title 't' -Cvss 'CVSS:4.0/AV:A/AC:H/AT:P/PR:L/UI:P/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N'
            Get-TcpkCvssVector $f
        }
        $v.Source | Should -Be 'override'
        $v.Vector | Should -Match 'AV:A'
    }
    It 'returns N/A for INFO findings (not a vulnerability)' {
        $v = & (Get-Module TCPK) {
            $f = New-TcpkFinding -Module 'recon' -RuleId 'attacksurface.summary' -Severity 'INFO' -Title 't'
            Get-TcpkCvssVector $f
        }
        $v.Vector  | Should -BeNullOrEmpty
        $v.Display | Should -Match 'N/A'
    }
    It 'defers CVE findings to the linked advisory vector' {
        $v = & (Get-Module TCPK) {
            $f = New-TcpkFinding -Module 'static' -RuleId 'cve.CVE-2024-21907' -Severity 'HIGH' -Title 't'
            Get-TcpkCvssVector $f
        }
        $v.Source  | Should -Be 'nvd'
        $v.Display | Should -Match 'NVD'
    }
    It 'displays a COMPUTED score that matches the engine (not a guess)' {
        $check = & (Get-Module TCPK) {
            $f = New-TcpkFinding -Module 'static' -RuleId 'tls-bypass.x' -Severity 'CRITICAL' -Title 't'
            $r = Get-TcpkCvssVector $f
            $engine = Get-TcpkCvss40Score -Vector $r.Vector
            [pscustomobject]@{ Display = $r.Display; Score = $r.Score; Engine = $engine.Score }
        }
        $check.Score  | Should -Be $check.Engine          # the shown score is the engine's, not invented
        $check.Display | Should -Match '^\d+\.\d \('       # "9.3 (Critical) CVSS:4.0/..."
    }
    It 'a NVD/per-finding/INFO finding shows NO decimal score (honest)' {
        $disps = & (Get-Module TCPK) {
            'cve.CVE-2024-21907','callsites.command-exec' | ForEach-Object {
                $f = New-TcpkFinding -Module 'static' -RuleId $_ -Severity 'HIGH' -Title 't'
                (Get-TcpkCvssVector $f).Display
            }
        }
        foreach ($d in $disps) { $d | Should -Not -Match '^\d+\.\d' }
    }
}

Describe 'CVSS v4.0 base-score engine (faithful FIRST.org port)' {
    It 'reproduces known-exact reference scores' {
        $r = & (Get-Module TCPK) {
            @{
                allhigh_sub  = (Get-TcpkCvss40Score 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H').Score
                allhigh_nosub= (Get-TcpkCvss40Score 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N').Score
                noimpact     = (Get-TcpkCvss40Score 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N').Score
                local_high   = (Get-TcpkCvss40Score 'CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N').Score
            }
        }
        $r.allhigh_sub   | Should -Be 10.0
        $r.allhigh_nosub | Should -Be 9.3
        $r.noimpact      | Should -Be 0.0
        $r.local_high    | Should -Be 8.7
    }
    It 'returns a rating band consistent with the score' {
        $rat = & (Get-Module TCPK) { (Get-TcpkCvss40Score 'CVSS:4.0/AV:L/AC:H/AT:P/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N').Rating }
        $rat | Should -Be 'Low'
    }
}

Describe 'Per-finding Impact' {
    It 'derives a default impact from severity when none is set' {
        $t = & (Get-Module TCPK) {
            $f = New-TcpkFinding -Module 'static' -RuleId 'x' -Severity 'CRITICAL' -Title 't'
            Get-TcpkImpactText $f
        }
        $t | Should -Not -BeNullOrEmpty
    }
    It 'uses an explicit Impact when provided' {
        $t = & (Get-Module TCPK) {
            $f = New-TcpkFinding -Module 'static' -RuleId 'x' -Severity 'LOW' -Title 't' -Impact 'Custom.'
            Get-TcpkImpactText $f
        }
        $t | Should -Be 'Custom.'
    }
}

Describe 'Get-TcpkTasvsMap' {
    It 'is exported' {
        Get-Command Get-TcpkTasvsMap -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
    }
    It 'maps a storage rule to TASVS-STORAGE + DA3' {
        $m = Get-TcpkTasvsMap -RuleId 'secrets.azure-key'
        $m.Tasvs | Should -Match 'TASVS-STORAGE'
        $m.DesktopTop10 | Should -Match 'DA3'
    }
    It 'maps a TLS rule to TASVS-NETWORK + DA7' {
        $m = Get-TcpkTasvsMap -RuleId 'tls-bypass.foo'
        $m.Tasvs | Should -Match 'TASVS-NETWORK'
        $m.DesktopTop10 | Should -Match 'DA7'
    }
    It 'dumps the full table with no args' {
        @(Get-TcpkTasvsMap).Count | Should -BeGreaterThan 10
    }
    It 'maps piped findings' {
        $rows = & (Get-Module TCPK) { New-TcpkFinding -Module 'creds' -RuleId 'localdb.sqlite-unencrypted' -Severity 'HIGH' -Title 'db' } | Get-TcpkTasvsMap
        $rows.Tasvs | Should -Match 'TASVS-STORAGE'
    }
}
