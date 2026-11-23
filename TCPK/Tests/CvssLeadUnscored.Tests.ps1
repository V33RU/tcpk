#requires -Version 5.1
# Pester 5: the CVSS proof gate. Only a PROVEN finding (Confidence like 'Confirmed*', the
# Get-TcpkAssuranceSplit test) gets a CVSS v4.0 score. A lead, a likely false positive, a
# finding triage could not resolve and a skipped one are unscored: no Score, no Vector,
# Source 'unscored', and a Display that says why and starts with "Not scored". The score
# the finding WOULD get once confirmed stays in IfConfirmedScore / IfConfirmedRating /
# IfConfirmedVector. A leading number in Display is what the web dashboard reads as a
# score (TCPK/Private/_Agentic.ps1, dScore), so an unscored Display must never start with one.
#
# NB: -ForEach data lives at top-level (discovery) scope, not in BeforeAll.

$script:ReasonCases = @(
    @{ Conf = 'Inferred';        Assurance = 'lead';          Reason = 'unverified lead' }
    @{ Conf = 'Unverified';      Assurance = 'lead';          Reason = 'unverified lead' }
    @{ Conf = '';                Assurance = 'lead';          Reason = 'unverified lead' }
    @{ Conf = 'Likely-FP (IL)';  Assurance = 'likely-fp';     Reason = 'likely false positive' }
    @{ Conf = 'Likely-FP (LLM)'; Assurance = 'likely-fp';     Reason = 'likely false positive' }
    @{ Conf = 'Uncertain (LLM)'; Assurance = 'uncertain';     Reason = 'unresolved by triage' }
    @{ Conf = 'Skipped';         Assurance = 'not-evaluated'; Reason = 'not evaluated' }
)

$script:ProvenCases = @(
    @{ Conf = 'Confirmed' }
    @{ Conf = 'Confirmed (IL)' }
    @{ Conf = 'Confirmed (dynamic)' }
    @{ Conf = 'Confirmed (exploit)' }
    @{ Conf = 'Confirmed (LLM)' }
)

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
    # The regex the web dashboard uses to pull a score out of a Display string.
    $script:DashRx = '^\s*([0-9]+(?:\.[0-9])?)\s*\('
}

Describe 'CVSS proof gate: proven findings are scored' {
    It 'scores a Confirmed HIGH local finding 8.5 with Assurance proven' {
        $r = InModuleScope TCPK {
            Get-TcpkCvssVector (New-TcpkFinding -Module 'os' -RuleId 'acl.world-writable' -Severity 'HIGH' -Confidence 'Confirmed' -Title 't')
        }
        $r.Score             | Should -Be 8.5
        $r.Rating            | Should -Be 'High'
        $r.Vector            | Should -Match '^CVSS:4\.0/AV:L/'
        $r.Source            | Should -Be 'anchored:local'
        $r.Display           | Should -Match '^8\.5 \(High\) CVSS:4\.0/'
        $r.Assurance         | Should -Be 'proven'
        $r.IfConfirmedScore  | Should -BeNullOrEmpty
        $r.IfConfirmedRating | Should -BeNullOrEmpty
        $r.IfConfirmedVector | Should -BeNullOrEmpty
    }

    It '<Conf> stays scored' -ForEach $script:ProvenCases {
        $r = InModuleScope TCPK -Parameters @{ c = $Conf } {
            param($c)
            Get-TcpkCvssVector (New-TcpkFinding -Module 'os' -RuleId 'acl.world-writable' -Severity 'HIGH' -Confidence $c -Title 't')
        }
        $r.Score     | Should -Be 8.5
        $r.Source    | Should -Be 'anchored:local'
        $r.Assurance | Should -Be 'proven'
    }
}

Describe 'CVSS proof gate: anything not proven is unscored' {
    It 'an Inferred HIGH is unscored, and says what it would score once confirmed' {
        $r = InModuleScope TCPK {
            Get-TcpkCvssVector (New-TcpkFinding -Module 'os' -RuleId 'acl.world-writable' -Severity 'HIGH' -Confidence 'Inferred' -Title 't')
        }
        $r.Score             | Should -BeNullOrEmpty
        $r.Vector            | Should -Be ''
        $r.Rating            | Should -Be ''
        $r.Source            | Should -Be 'unscored'
        $r.Assurance         | Should -Be 'lead'
        $r.Display           | Should -BeLike 'Not scored (unverified lead)*'
        $r.Display           | Should -Match '8\.5'
        $r.Display           | Should -Match 'If confirmed: 8\.5 \(High\) CVSS:4\.0/AV:L/'
        $r.IfConfirmedScore  | Should -Be 8.5
        $r.IfConfirmedRating | Should -Be 'High'
        $r.IfConfirmedVector | Should -Match '^CVSS:4\.0/AV:L/'
    }

    It 'confidence <Conf> is unscored as "<Reason>"' -ForEach $script:ReasonCases {
        $r = InModuleScope TCPK -Parameters @{ c = $Conf } {
            param($c)
            $f = New-TcpkFinding -Module 'os' -RuleId 'acl.world-writable' -Severity 'HIGH' -Title 't'
            # The factory's ValidateSet refuses an empty label; a finding rebuilt from a
            # findings.json row can still carry one, so set it on the object directly.
            $f.Confidence = $c
            Get-TcpkCvssVector $f
        }
        $r.Source           | Should -Be 'unscored'
        $r.Score            | Should -BeNullOrEmpty
        $r.Vector           | Should -Be ''
        $r.Assurance        | Should -Be $Assurance
        $r.Display          | Should -BeLike "Not scored ($Reason).*"
        $r.IfConfirmedScore | Should -Be 8.5
        $r.Display          | Should -Not -Match $script:DashRx
    }

    It 'leaves INFO as N/A for a proven and for an unproven finding' {
        $r = InModuleScope TCPK {
            @(
                Get-TcpkCvssVector (New-TcpkFinding -Module 'recon' -RuleId 'attacksurface.summary' -Severity 'INFO' -Confidence 'Confirmed' -Title 't')
                Get-TcpkCvssVector (New-TcpkFinding -Module 'recon' -RuleId 'attacksurface.summary' -Severity 'INFO' -Confidence 'Inferred'  -Title 't')
            )
        }
        foreach ($x in $r) {
            $x.Source  | Should -Be 'info'
            $x.Display | Should -Be 'N/A (informational)'
            $x.Rating  | Should -Be 'None'
            $x.Score   | Should -BeNullOrEmpty
            $x.IfConfirmedScore | Should -BeNullOrEmpty
        }
    }

    It 'gates an explicit .Cvss override too, keeping it as IfConfirmedVector' {
        $ov = 'CVSS:4.0/AV:A/AC:H/AT:P/PR:L/UI:P/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N'
        $r = InModuleScope TCPK -Parameters @{ v = $ov } {
            param($v)
            [pscustomobject]@{
                Lead   = Get-TcpkCvssVector (New-TcpkFinding -Module 'static' -RuleId 'anything.x' -Severity 'HIGH' -Confidence 'Inferred'  -Title 't' -Cvss $v)
                Proven = Get-TcpkCvssVector (New-TcpkFinding -Module 'static' -RuleId 'anything.x' -Severity 'HIGH' -Confidence 'Confirmed' -Title 't' -Cvss $v)
            }
        }
        $r.Lead.Source            | Should -Be 'unscored'
        $r.Lead.Vector            | Should -Be ''
        $r.Lead.Score             | Should -BeNullOrEmpty
        $r.Lead.IfConfirmedVector | Should -Be $ov
        $r.Lead.IfConfirmedScore  | Should -Not -BeNullOrEmpty
        $r.Lead.Display           | Should -BeLike 'Not scored (unverified lead). If confirmed: *'
        $r.Proven.Source          | Should -Be 'override'
        $r.Proven.Vector          | Should -Be $ov
    }

    It 'keeps the advisory note on a cve. / deps. lead, unscored' {
        $r = InModuleScope TCPK {
            @(
                Get-TcpkCvssVector (New-TcpkFinding -Module 'static' -RuleId 'cve.CVE-2024-21907' -Severity 'HIGH' -Confidence 'Inferred' -Title 't')
                Get-TcpkCvssVector (New-TcpkFinding -Module 'static' -RuleId 'deps.some-package'  -Severity 'HIGH' -Confidence 'Inferred' -Title 't')
            )
        }
        foreach ($x in $r) {
            $x.Source            | Should -Be 'unscored'
            $x.Assurance         | Should -Be 'lead'
            $x.Display           | Should -BeLike 'Not scored (unverified lead). See the linked * advisory for the official CVSS v4.0 score'
            $x.IfConfirmedScore  | Should -BeNullOrEmpty
            $x.IfConfirmedVector | Should -Be ''
        }
    }

    It 'never gives the dashboard a leading number for an unscored result' {
        $disp = InModuleScope TCPK {
            foreach ($rid in 'acl.world-writable', 'deser.binaryformatter', 'tls-bypass.cert-accept-all', 'cve.CVE-2024-21907', 'process.impactful-privileges') {
                foreach ($sev in 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW') {
                    (Get-TcpkCvssVector (New-TcpkFinding -Module 'static' -RuleId $rid -Severity $sev -Confidence 'Inferred' -Title 't')).Display
                }
            }
        }
        @($disp).Count | Should -Be 20
        foreach ($d in $disp) {
            $d | Should -BeLike 'Not scored*'
            $d | Should -Not -Match $script:DashRx
        }
        # and the proven twin still matches it, so the regex is the right one to test against
        $scored = InModuleScope TCPK { (Get-TcpkCvssVector (New-TcpkFinding -Module 'static' -RuleId 'acl.world-writable' -Severity 'HIGH' -Title 't')).Display }
        $scored | Should -Match $script:DashRx
    }
}

Describe 'CVSS proof gate: Export-TcpkReportSarif' {
    BeforeAll {
        $script:sarifPath = Join-Path $TestDrive 'gate.sarif'
        InModuleScope TCPK -Parameters @{ o = $script:sarifPath } {
            param($o)
            @(
                New-TcpkFinding -Module 'os' -RuleId 'acl.world-writable'  -Severity 'HIGH' -Confidence 'Inferred'  -Title 'lead'   -File 'C:\a.exe'
                New-TcpkFinding -Module 'os' -RuleId 'acl.service-binary'  -Severity 'HIGH' -Confidence 'Confirmed' -Title 'proven' -File 'C:\b.exe'
                New-TcpkFinding -Module 'static' -RuleId 'pe.no-aslr'      -Severity 'INFO' -Confidence 'Inferred'  -Title 'info lead'   -File 'C:\c.exe'
                New-TcpkFinding -Module 'static' -RuleId 'pe.no-dep'       -Severity 'INFO' -Confidence 'Confirmed' -Title 'info proven' -File 'C:\d.exe'
            ) | Export-TcpkReportSarif -OutFile $o -Target 'gate'
        }
        $script:sarif = Get-Content -Raw -LiteralPath $script:sarifPath | ConvertFrom-Json
    }

    It 'omits security-severity on an Inferred HIGH and tags it as a lead' {
        $lead = @($script:sarif.runs[0].results | Where-Object { $_.ruleId -eq 'acl.world-writable' })
        $lead.Count | Should -Be 1
        @($lead[0].properties.PSObject.Properties.Name) | Should -Not -Contain 'security-severity'
        $lead[0].properties.'tcpk-assurance'    | Should -Be 'lead'
        $lead[0].properties.'cvss-if-confirmed' | Should -Be '8.5'
        $lead[0].level                          | Should -Be 'error'
    }

    It 'keeps security-severity 8.5 on a Confirmed HIGH' {
        $prov = @($script:sarif.runs[0].results | Where-Object { $_.ruleId -eq 'acl.service-binary' })
        $prov.Count | Should -Be 1
        $prov[0].properties.'security-severity' | Should -Be '8.5'
        $prov[0].properties.'tcpk-assurance'    | Should -Be 'proven'
        @($prov[0].properties.PSObject.Properties.Name) | Should -Not -Contain 'cvss-if-confirmed'
        $prov[0].level                          | Should -Be 'error'
    }

    It 'gives an INFO lead no band-fallback security-severity, and keeps 0.0 on a proven INFO' {
        $lead = @($script:sarif.runs[0].results | Where-Object { $_.ruleId -eq 'pe.no-aslr' })
        $lead.Count | Should -Be 1
        @($lead[0].properties.PSObject.Properties.Name) | Should -Not -Contain 'security-severity'
        @($lead[0].properties.PSObject.Properties.Name) | Should -Not -Contain 'cvss-if-confirmed'
        $lead[0].properties.'tcpk-assurance' | Should -Be 'lead'
        $lead[0].level                       | Should -Be 'note'
        $prov = @($script:sarif.runs[0].results | Where-Object { $_.ruleId -eq 'pe.no-dep' })
        $prov.Count | Should -Be 1
        $prov[0].properties.'security-severity' | Should -Be '0.0'
        $prov[0].properties.'tcpk-assurance'    | Should -Be 'proven'
    }
}

Describe 'CVSS proof gate: Export-TcpkReportMarkdown' {
    It 'renders a "CVSS v4.0: Not scored" line for a lead and a scored line for a proven finding' {
        $out = Join-Path $TestDrive 'gate.md'
        InModuleScope TCPK -Parameters @{ o = $out } {
            param($o)
            @(
                New-TcpkFinding -Module 'os' -RuleId 'acl.world-writable' -Severity 'HIGH' -Confidence 'Inferred'  -Title 'Lead finding'
                New-TcpkFinding -Module 'os' -RuleId 'acl.service-binary' -Severity 'HIGH' -Confidence 'Confirmed' -Title 'Proven finding'
            ) | Export-TcpkReportMarkdown -OutFile $o -Target 'gate' | Out-Null
        }
        $md = [IO.File]::ReadAllText($out)
        $md | Should -Match '(?m)^- CVSS v4\.0: Not scored \(unverified lead\)\. If confirmed: 8\.5 \(High\) CVSS:4\.0/'
        $md | Should -Match '(?m)^- CVSS v4\.0: 8\.5 `CVSS:4\.0/'
    }
}

# Archetype mappings added to $script:TcpkCvssRuleArchetype. Each case is a rule at a
# severity its emitter can produce (INFO short-circuits and is not listed). The expected
# vectors are spelled out here, not read from the band table, so a change to either the
# mapping or the band shows up as a failure.
$script:Vec = @{
    NetC = 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N'
    NetH = 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N'
    NetM = 'CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N'
    AdjC = 'CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H'
    AdjH = 'CVSS:4.0/AV:A/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N'
    AdjM = 'CVSS:4.0/AV:A/AC:L/AT:P/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N'
    LocC = 'CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H'
    LocH = 'CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N'
    LocM = 'CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N'
}

$script:ArchetypeCases = @(
    # msix .appinstaller http:// Uri: on-path network
    @{ Rule = 'msix.appinstaller.plaintext-uri';    Sev = 'HIGH';     A = 'cleartext-net';  Source = 'anchored:network';  Vector = $script:Vec.NetH; Score = 8.5 }
    # OAuth CSRF: remote attacker, victim navigation
    @{ Rule = 'oauth.missing-state';                Sev = 'MEDIUM';   A = 'web-bridge';     Source = 'anchored:network';  Vector = $script:Vec.NetM; Score = 6.3 }
    @{ Rule = 'oauth.callback-no-state-check';      Sev = 'MEDIUM';   A = 'web-bridge';     Source = 'anchored:network';  Vector = $script:Vec.NetM; Score = 6.3 }
    @{ Rule = 'oauth.oidc-state-disabled';          Sev = 'HIGH';     A = 'web-bridge';     Source = 'anchored:network';  Vector = $script:Vec.NetH; Score = 8.5 }
    # pcap IP-layer rules: on-path network observation
    @{ Rule = 'pcap.http-basic-cleartext';          Sev = 'HIGH';     A = 'cleartext-net';  Source = 'anchored:network';  Vector = $script:Vec.NetH; Score = 8.5 }
    @{ Rule = 'pcap.cleartext-http';                Sev = 'MEDIUM';   A = 'cleartext-net';  Source = 'anchored:network';  Vector = $script:Vec.NetM; Score = 6.3 }
    @{ Rule = 'pcap.weak-tls';                      Sev = 'HIGH';     A = 'cleartext-net';  Source = 'anchored:network';  Vector = $script:Vec.NetH; Score = 8.5 }
    @{ Rule = 'pcap.weak-tls';                      Sev = 'MEDIUM';   A = 'cleartext-net';  Source = 'anchored:network';  Vector = $script:Vec.NetM; Score = 6.3 }
    @{ Rule = 'pcap.ftp-cleartext-cred';            Sev = 'HIGH';     A = 'cleartext-net';  Source = 'anchored:network';  Vector = $script:Vec.NetH; Score = 8.5 }
    @{ Rule = 'pcap.weak-cipher';                   Sev = 'CRITICAL'; A = 'cleartext-net';  Source = 'anchored:network';  Vector = $script:Vec.NetC; Score = 9.3 }
    @{ Rule = 'pcap.weak-cipher';                   Sev = 'HIGH';     A = 'cleartext-net';  Source = 'anchored:network';  Vector = $script:Vec.NetH; Score = 8.5 }
    @{ Rule = 'pcap.secret-in-url';                 Sev = 'HIGH';     A = 'cleartext-net';  Source = 'anchored:network';  Vector = $script:Vec.NetH; Score = 8.5 }
    @{ Rule = 'pcap.insecure-cookie';               Sev = 'MEDIUM';   A = 'cleartext-net';  Source = 'anchored:network';  Vector = $script:Vec.NetM; Score = 6.3 }
    @{ Rule = 'pcap.smtp-cleartext-auth';           Sev = 'HIGH';     A = 'cleartext-net';  Source = 'anchored:network';  Vector = $script:Vec.NetH; Score = 8.5 }
    @{ Rule = 'pcap.telnet-cleartext';              Sev = 'CRITICAL'; A = 'cleartext-net';  Source = 'anchored:network';  Vector = $script:Vec.NetC; Score = 9.3 }
    @{ Rule = 'pcap.mqtt-cleartext';                Sev = 'HIGH';     A = 'cleartext-net';  Source = 'anchored:network';  Vector = $script:Vec.NetH; Score = 8.5 }
    @{ Rule = 'pcap.form-cred-cleartext';           Sev = 'CRITICAL'; A = 'cleartext-net';  Source = 'anchored:network';  Vector = $script:Vec.NetC; Score = 9.3 }
    @{ Rule = 'pcap.ldap-cleartext';                Sev = 'HIGH';     A = 'cleartext-net';  Source = 'anchored:network';  Vector = $script:Vec.NetH; Score = 8.5 }
    @{ Rule = 'pcap.snmp-community';                Sev = 'CRITICAL'; A = 'cleartext-net';  Source = 'anchored:network';  Vector = $script:Vec.NetC; Score = 9.3 }
    @{ Rule = 'pcap.snmp-community';                Sev = 'HIGH';     A = 'cleartext-net';  Source = 'anchored:network';  Vector = $script:Vec.NetH; Score = 8.5 }
    @{ Rule = 'pcap.dns-exfil';                     Sev = 'HIGH';     A = 'cleartext-net';  Source = 'anchored:network';  Vector = $script:Vec.NetH; Score = 8.5 }
    @{ Rule = 'pcap.ntlm-http';                     Sev = 'HIGH';     A = 'cleartext-net';  Source = 'anchored:network';  Vector = $script:Vec.NetH; Score = 8.5 }
    @{ Rule = 'pcap.sensitive-path';                Sev = 'HIGH';     A = 'cleartext-net';  Source = 'anchored:network';  Vector = $script:Vec.NetH; Score = 8.5 }
    @{ Rule = 'pcap.jwt-cleartext';                 Sev = 'CRITICAL'; A = 'cleartext-net';  Source = 'anchored:network';  Vector = $script:Vec.NetC; Score = 9.3 }
    @{ Rule = 'pcap.vnc-cleartext';                 Sev = 'HIGH';     A = 'cleartext-net';  Source = 'anchored:network';  Vector = $script:Vec.NetH; Score = 8.5 }
    # pcap BLE / Zigbee: radio range, adjacent
    @{ Rule = 'pcap.bt-justworks';                  Sev = 'HIGH';     A = 'net-mitm';       Source = 'anchored:adjacent'; Vector = $script:Vec.AdjH; Score = 7.6 }
    @{ Rule = 'pcap.bt-gatt-cleartext';             Sev = 'HIGH';     A = 'net-mitm';       Source = 'anchored:adjacent'; Vector = $script:Vec.AdjH; Score = 7.6 }
    @{ Rule = 'pcap.bt-gatt-read-cleartext';        Sev = 'MEDIUM';   A = 'net-mitm';       Source = 'anchored:adjacent'; Vector = $script:Vec.AdjM; Score = 6.0 }
    @{ Rule = 'pcap.zigbee-unencrypted';            Sev = 'HIGH';     A = 'net-mitm';       Source = 'anchored:adjacent'; Vector = $script:Vec.AdjH; Score = 7.6 }
    @{ Rule = 'pcap.zigbee-transport-key';          Sev = 'CRITICAL'; A = 'net-mitm';       Source = 'anchored:adjacent'; Vector = $script:Vec.AdjC; Score = 9.4 }
    # certificate-validation callback: on-path TLS interceptor
    @{ Rule = 'callsites.disabled-cert-validation'; Sev = 'CRITICAL'; A = 'net-mitm';       Source = 'anchored:adjacent'; Vector = $script:Vec.AdjC; Score = 9.4 }
    # dependency confusion: public registry delivers the package
    @{ Rule = 'nuget.dep-confusion.no-psm';         Sev = 'HIGH';     A = 'net-rce';        Source = 'anchored:network';  Vector = $script:Vec.NetH; Score = 8.5 }
    @{ Rule = 'nuget.dep-confusion.v2-feed';        Sev = 'MEDIUM';   A = 'net-rce';        Source = 'anchored:network';  Vector = $script:Vec.NetM; Score = 6.3 }
    @{ Rule = 'npm.dep-confusion.no-scope-map';     Sev = 'HIGH';     A = 'net-rce';        Source = 'anchored:network';  Vector = $script:Vec.NetH; Score = 8.5 }
    @{ Rule = 'pip.dep-confusion.extra-index-url';  Sev = 'HIGH';     A = 'net-rce';        Source = 'anchored:network';  Vector = $script:Vec.NetH; Score = 8.5 }
    # webview2.* local-position rules, listed above the web-bridge family line
    @{ Rule = 'webview2.profile-cred-store';        Sev = 'HIGH';     A = 'local-at-rest';  Source = 'anchored:local';    Vector = $script:Vec.LocH; Score = 8.5 }
    @{ Rule = 'webview2.profile-cred-store';        Sev = 'MEDIUM';   A = 'local-at-rest';  Source = 'anchored:local';    Vector = $script:Vec.LocM; Score = 6.8 }
    @{ Rule = 'webview2.devtools-enabled';          Sev = 'MEDIUM';   A = 'hardening';      Source = 'anchored:local';    Vector = $script:Vec.LocM; Score = 6.8 }
)

# Siblings the new entries must neither shadow nor be shadowed by: each keeps the mapping
# it had before. A = '' means no table entry (the local default).
$script:SiblingCases = @(
    @{ Rule = 'webview2.add-host-object';           Sev = 'HIGH';     A = 'web-bridge';     Source = 'anchored:network';  Vector = $script:Vec.NetH; Score = 8.5 }
    @{ Rule = 'oauth.pkce-missing';                 Sev = 'MEDIUM';   A = '';               Source = 'anchored:local';    Vector = $script:Vec.LocM; Score = 6.8 }
    @{ Rule = 'msix.appinstaller.hotpath-uri';      Sev = 'HIGH';     A = '';               Source = 'anchored:local';    Vector = $script:Vec.LocH; Score = 8.5 }
    @{ Rule = 'pcap.arp-spoof';                     Sev = 'CRITICAL'; A = '';               Source = 'anchored:local';    Vector = $script:Vec.LocC; Score = 9.3 }
    @{ Rule = 'callsites.command-execution';        Sev = 'HIGH';     A = '';               Source = 'anchored:local';    Vector = $script:Vec.LocH; Score = 8.5 }
)

Describe 'Archetype mappings' {
    It '<Rule> resolves to archetype <A>' -ForEach $script:ArchetypeCases {
        $got = InModuleScope TCPK -Parameters @{ id = $Rule } {
            param($id)
            foreach ($m in $script:TcpkCvssRuleArchetype) { if ($id -match $m.Rx) { return $m.A } }
            return ''
        }
        $got | Should -Be $A
    }

    It 'a Confirmed <Rule> (<Sev>) scores <Score> with <Source>' -ForEach $script:ArchetypeCases {
        $r = InModuleScope TCPK -Parameters @{ id = $Rule; s = $Sev } {
            param($id, $s)
            Get-TcpkCvssVector (New-TcpkFinding -Module 'static' -RuleId $id -Severity $s -Confidence 'Confirmed' -Title 't')
        }
        $r.Source    | Should -Be $Source
        $r.Vector    | Should -Be $Vector
        $r.Score     | Should -Be $Score
        $r.Assurance | Should -Be 'proven'
    }

    It 'sibling <Rule> (<Sev>) keeps archetype "<A>" and scores <Score> with <Source>' -ForEach $script:SiblingCases {
        $r = InModuleScope TCPK -Parameters @{ id = $Rule; s = $Sev } {
            param($id, $s)
            $a = ''
            foreach ($m in $script:TcpkCvssRuleArchetype) { if ($id -match $m.Rx) { $a = $m.A; break } }
            [pscustomobject]@{
                A = $a
                C = Get-TcpkCvssVector (New-TcpkFinding -Module 'static' -RuleId $id -Severity $s -Confidence 'Confirmed' -Title 't')
            }
        }
        $r.A        | Should -Be $A
        $r.C.Source | Should -Be $Source
        $r.C.Vector | Should -Be $Vector
        $r.C.Score  | Should -Be $Score
    }

    It 'the Inferred callsites.disabled-cert-validation the scanner emits is unscored, 9.4 adjacent if confirmed' {
        $r = InModuleScope TCPK {
            Get-TcpkCvssVector (New-TcpkFinding -Module 'static' -RuleId 'callsites.disabled-cert-validation' -Severity 'CRITICAL' -Confidence 'Inferred' -Title 't')
        }
        $r.Source            | Should -Be 'unscored'
        $r.Score             | Should -BeNullOrEmpty
        $r.IfConfirmedScore  | Should -Be 9.4
        $r.IfConfirmedRating | Should -Be 'Critical'
        # literal, not $script:Vec: discovery-scope variables are not visible when It runs
        $r.IfConfirmedVector | Should -Be 'CVSS:4.0/AV:A/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H'
    }
}
