#requires -Version 5.1
# Regression guards for three defects the gap audit found (all fixed in this change):
#
#   1-2. OrderedDictionary .ContainsKey in the LIVE triage pipeline (_Redundancy.ps1:244,
#        _Consistency.ps1:196). [ordered]@{} is an OrderedDictionary, which exposes
#        .Contains(key) NOT .ContainsKey. On Windows PowerShell 5.1 the grouping threw a
#        MethodException the moment >=2 findings shared a Subject (routine in an OS-integration
#        audit), aborting dedupe/correlation. It stayed green on the dev's PS7/Linux, so prior
#        tests never caught it. Same class as the fix in commit f5dbe17 (_Pcap) and the CAP6
#        _PlatformCoverage fix.
#
#   3.   Resolve-TcpkFindings aggregation rebuilt the collapsed clone WITHOUT
#        -AttributionBasis/-Subject, so an 'unproven' HIGH that aggregates (>=2 locations)
#        lost its basis and slipped past Invoke-TcpkAttributionFilter as a target finding
#        (e.g. the operator's own AWS SSO token cache reported to the client as HIGH).

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
}

Describe 'Triage grouping survives the ordered dictionary (PS 5.1 crash class)' {

    It 'Invoke-TcpkRedundancyCorrelation groups >=2 same-subject findings without throwing' {
        InModuleScope TCPK {
            $a = New-TcpkFinding -Module m -RuleId 'x.a' -Severity 'LOW' -Title 'A' `
                    -Subject 'C:\Target\app\foo.exe' -Dimension 'perm' -ObsValue '{"v":1}'
            $b = New-TcpkFinding -Module m -RuleId 'x.b' -Severity 'LOW' -Title 'B' `
                    -Subject 'C:\Target\app\foo.exe' -Dimension 'perm' -ObsValue '{"v":2}'
            { @($a, $b) | Invoke-TcpkRedundancyCorrelation } | Should -Not -Throw
        }
    }

    It 'Invoke-TcpkConsistencyCheck groups >=2 same-subject findings without throwing' {
        InModuleScope TCPK {
            $a = New-TcpkFinding -Module m -RuleId 'x.a' -Severity 'LOW' -Title 'A' `
                    -Subject 'C:\Target\app\foo.exe' -Dimension 'perm' -ObsValue '{"v":1}'
            $b = New-TcpkFinding -Module m -RuleId 'x.b' -Severity 'LOW' -Title 'B' `
                    -Subject 'C:\Target\app\foo.exe' -Dimension 'perm' -ObsValue '{"v":2}'
            { @($a, $b) | Invoke-TcpkConsistencyCheck } | Should -Not -Throw
        }
    }
}

Describe 'Aggregation preserves attribution so the C8 filter still demotes' {

    It 'an unproven HIGH that aggregates across >=2 locations is still demoted to INFO/AMBIENT' {
        InModuleScope TCPK {
            $a = New-TcpkFinding -Module creds -RuleId 'creds.aws-sso-cache' -Severity 'HIGH' `
                    -Confidence 'Inferred' -Title 'SSO token cache' `
                    -File 'C:\Users\op\.aws\sso\cache\a.json' -AttributionBasis 'unproven' -Subject 'file:a'
            $b = New-TcpkFinding -Module creds -RuleId 'creds.aws-sso-cache' -Severity 'HIGH' `
                    -Confidence 'Inferred' -Title 'SSO token cache' `
                    -File 'C:\Users\op\.aws\sso\cache\b.json' -AttributionBasis 'unproven' -Subject 'file:b'

            $agg = @(@($a, $b) | Resolve-TcpkFindings -AggregateOnly)
            $agg.Count               | Should -Be 1
            $agg[0].AttributionBasis | Should -Be 'unproven'   # the fix: basis survived the clone

            $filtered = @($agg | Invoke-TcpkAttributionFilter)
            $filtered[0].Severity | Should -Be 'INFO'
            $filtered[0].Title    | Should -BeLike 'AMBIENT: *'
        }
    }

    It 'a single (non-aggregated) unproven HIGH was already demoted (baseline)' {
        InModuleScope TCPK {
            $f = New-TcpkFinding -Module creds -RuleId 'creds.aws-sso-cache' -Severity 'HIGH' `
                    -Confidence 'Inferred' -Title 'SSO token cache' `
                    -File 'C:\Users\op\.aws\sso\cache\a.json' -AttributionBasis 'unproven' -Subject 'file:a'
            $filtered = @($f | Invoke-TcpkAttributionFilter)
            $filtered[0].Severity | Should -Be 'INFO'
        }
    }
}
