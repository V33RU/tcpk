#requires -Version 5.1
# Pester 5: a finding's hand-assigned Severity badge and its COMPUTED CVSS v4.0 rating must
# not contradict. They come from two systems (per-rule severity vs per-family archetype),
# so this guard asserts they stay within ONE band of each other. It would have caught the
# debugflags.security-off regression (badged HIGH but mapped to the 'hardening' archetype =
# 2.0 Low) before release.
#
# NB: the -ForEach data MUST live at top-level (discovery) scope, not in BeforeAll -- Pester
# expands -ForEach during discovery, before BeforeAll runs.

$script:CvssCases = @(
    @{ Rule = 'debugflags.security-off';                Sev = 'HIGH' }     # the fix: was Low, now matches
    @{ Rule = 'debugflags.backdoor';                    Sev = 'HIGH' }
    @{ Rule = 'debugflags.debug-surface';               Sev = 'LOW' }
    @{ Rule = 'tls-bypass.cert-callback-accepts-all';   Sev = 'CRITICAL' }
    @{ Rule = 'acl.world-writable';                     Sev = 'CRITICAL' }
    @{ Rule = 'secrets.cloud-storage-key';              Sev = 'CRITICAL' }
    @{ Rule = 'keymaterial.private-key';                Sev = 'HIGH' }
    @{ Rule = 'scheme.cleartext-http';                  Sev = 'MEDIUM' }   # was net-mitm Critical, now cleartext-net Medium
    @{ Rule = 'dns.pre-resolution';                     Sev = 'LOW' }      # same family fix
    @{ Rule = 'tls.pinning-absent';                     Sev = 'LOW' }      # posture, not active MITM
    @{ Rule = 'tls.revocation-disabled';               Sev = 'MEDIUM' }   # posture, not active MITM
    @{ Rule = 'pe.missing-mitigations';                 Sev = 'LOW' }
    @{ Rule = 'dpapi.blob';                             Sev = 'MEDIUM' }
)

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
    $script:sevRank  = @{ CRITICAL = 4; HIGH = 3; MEDIUM = 2; LOW = 1 }
    $script:bandRank = @{ Critical = 4; High = 3; Medium = 2; Low = 1; None = 0 }
}

Describe 'Severity badge vs computed CVSS rating' {
    It '<Rule> (<Sev>) CVSS rating is within 1 band of the badge' -ForEach $script:CvssCases {
        $disp = & (Get-Module TCPK) {
            param($rule, $sev)
            (Get-TcpkCvssVector (New-TcpkFinding -Module 'static' -RuleId $rule -Severity $sev -Title 't')).Display
        } $Rule $Sev

        $band = ([regex]::Match("$disp", '\((\w+)\)')).Groups[1].Value
        $script:bandRank.ContainsKey($band) | Should -BeTrue -Because "$Rule should resolve to a real CVSS band (got '$disp')"
        [Math]::Abs($script:sevRank[$Sev] - $script:bandRank[$band]) |
            Should -BeLessOrEqual 1 -Because "$Rule badged $Sev must not diverge more than 1 band from its computed CVSS '$band'"
    }
}

# Severity-anchored scoring guarantee: the computed rating must EXACTLY equal the badge
# (a LOW never shows Medium, a HIGH never shows Medium), across every attack flavor.
$script:AnchorCases = @(
    @{ Rule = 'acl.world-writable';         Sev = 'CRITICAL'; Band = 'Critical' }   # local flavor
    @{ Rule = 'acl.world-writable';         Sev = 'HIGH';     Band = 'High' }
    @{ Rule = 'acl.world-writable';         Sev = 'MEDIUM';   Band = 'Medium' }
    @{ Rule = 'acl.world-writable';         Sev = 'LOW';      Band = 'Low' }
    @{ Rule = 'deser.binaryformatter';      Sev = 'CRITICAL'; Band = 'Critical' }   # network flavor
    @{ Rule = 'deser.binaryformatter';      Sev = 'HIGH';     Band = 'High' }
    @{ Rule = 'deser.binaryformatter';      Sev = 'MEDIUM';   Band = 'Medium' }
    @{ Rule = 'deser.binaryformatter';      Sev = 'LOW';      Band = 'Low' }
    @{ Rule = 'tls-bypass.cert-accept-all'; Sev = 'CRITICAL'; Band = 'Critical' }   # adjacent flavor
    @{ Rule = 'tls-bypass.cert-accept-all'; Sev = 'HIGH';     Band = 'High' }
    @{ Rule = 'tls-bypass.cert-accept-all'; Sev = 'MEDIUM';   Band = 'Medium' }
    @{ Rule = 'tls-bypass.cert-accept-all'; Sev = 'LOW';      Band = 'Low' }
    @{ Rule = 'process.impactful-privileges'; Sev = 'MEDIUM'; Band = 'Medium' }     # unmapped -> local default
    @{ Rule = 'callsites.command-execution';  Sev = 'HIGH';   Band = 'High' }
)

Describe 'CVSS rating EXACTLY matches the severity badge (anchored)' {
    It '<Rule> badged <Sev> computes to <Band>' -ForEach $script:AnchorCases {
        $rating = & (Get-Module TCPK) {
            param($rule, $sev)
            (Get-TcpkCvssVector (New-TcpkFinding -Module 'static' -RuleId $rule -Severity $sev -Title 't')).Rating
        } $Rule $Sev
        $rating | Should -Be $Band -Because "$Rule badged $Sev must compute to the $Band band"
    }
}
