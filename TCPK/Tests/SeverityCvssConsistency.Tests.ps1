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
