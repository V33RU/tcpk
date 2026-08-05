Describe 'TCPK Finding Redundancy Model' {
    BeforeAll {
        $manifest = Join-Path $PSScriptRoot '..' 'TCPK.psd1'
        Import-Module (Resolve-Path $manifest) -Force -ErrorAction Stop
    }

    # -----------------------------------------------------------------------
    # Helpers (inside module scope so private functions are accessible)
    # -----------------------------------------------------------------------
    InModuleScope TCPK {

        function _MakeFinding {
            param(
                [string]$RuleId,
                [string]$Severity   = 'HIGH',
                [string]$Confidence = 'Confirmed',
                [string]$Subject    = '',
                [string]$Dimension  = '',
                [string]$ObsValue   = '',
                [string]$Basis      = 'Measured',
                [string[]]$BasisInputs = @()
            )
            $f = New-TcpkFinding -Module 'test' -RuleId $RuleId -Severity $Severity `
                -Confidence $Confidence -Title "$RuleId finding" `
                -Subject $Subject -Dimension $Dimension -ObsValue $ObsValue `
                -Basis $Basis -BasisInputs $BasisInputs
            $f
        }

        # -------------------------------------------------------------------
        # SECTION 1: Subject normalization
        # -------------------------------------------------------------------

        Describe 'Get-TcpkNormalizedSubject' {
            It 'normalizes Windows path to lowercase forward slash' {
                Get-TcpkNormalizedSubject 'C:\Program Files\App\App.exe' |
                    Should -Be 'c:/program files/app/app.exe'
            }

            It 'strips trailing slash' {
                Get-TcpkNormalizedSubject 'C:\App\' |
                    Should -Be 'c:/app'
            }

            It 'returns empty string for empty input' {
                Get-TcpkNormalizedSubject '' | Should -Be ''
                Get-TcpkNormalizedSubject $null | Should -Be ''
            }
        }

        # -------------------------------------------------------------------
        # SECTION 2: ObsValue parser
        # -------------------------------------------------------------------

        Describe '_TcpkParseObsValue' {
            It 'parses JSON array to set with sorted members' {
                $r = _TcpkParseObsValue '["VirtualProtect","WriteProcessMemory","CreateRemoteThread"]'
                $r.Kind    | Should -Be 'set'
                $r.Members | Should -Be @('CreateRemoteThread','VirtualProtect','WriteProcessMemory')
            }

            It 'parses integer string to count' {
                $r = _TcpkParseObsValue '42'
                $r.Kind | Should -Be 'count'
                $r.Norm | Should -Be '42'
            }

            It 'parses JSON object to struct' {
                $r = _TcpkParseObsValue '{"nx":true,"aslr":false}'
                $r.Kind | Should -Be 'struct'
            }

            It 'returns empty Kind for empty string' {
                $r = _TcpkParseObsValue ''
                $r.Kind | Should -Be 'empty'
            }

            It 'parses plain scalar string' {
                $r = _TcpkParseObsValue 'expired'
                $r.Kind | Should -Be 'scalar'
                $r.Norm | Should -Be 'expired'
            }
        }

        # -------------------------------------------------------------------
        # SECTION 3: Relationship classifier
        # -------------------------------------------------------------------

        Describe 'Get-TcpkFindingRelationship' {

            # (a) INDEPENDENT: different dimensions on the same file
            # Naive implementation catcher: same subject + same evidence string
            # but genuinely different questions -> must NOT fold.
            It '(a) INDEPENDENT when dimensions differ even with same subject [naive catcher]' {
                $A = _MakeFinding 'pe.sig-status'  -Subject 'c:/app/app.exe' -Dimension 'signature-status'   -ObsValue '"unsigned"'
                $B = _MakeFinding 'pe.load-config' -Subject 'c:/app/app.exe' -Dimension 'load-configuration' -ObsValue '"unsigned"'
                $r = Get-TcpkFindingRelationship -A $A -B $B
                $r.Relationship | Should -Be 'INDEPENDENT'
            }

            # (b) INDEPENDENT: absent Subject forces independence
            It '(b) INDEPENDENT when Subject is absent' {
                $A = _MakeFinding 'rule.a' -Subject ''               -Dimension 'import-set' -ObsValue '["VirtualProtect"]'
                $B = _MakeFinding 'rule.b' -Subject 'c:/app/app.exe' -Dimension 'import-set' -ObsValue '["VirtualProtect"]'
                $r = Get-TcpkFindingRelationship -A $A -B $B
                $r.Relationship | Should -Be 'INDEPENDENT'
            }

            # (c) INDEPENDENT: absent Dimension forces independence
            It '(c) INDEPENDENT when Dimension is absent' {
                $A = _MakeFinding 'rule.a' -Subject 'c:/app/app.exe' -Dimension '' -ObsValue '["A"]'
                $B = _MakeFinding 'rule.b' -Subject 'c:/app/app.exe' -Dimension '' -ObsValue '["A"]'
                $r = Get-TcpkFindingRelationship -A $A -B $B
                $r.Relationship | Should -Be 'INDEPENDENT'
            }

            # (d) IDENTICAL: same dimension + same value -> emit one
            It '(d) IDENTICAL: same dimension and value' {
                $A = _MakeFinding 'rule.a' -Subject 'c:/app/app.exe' -Dimension 'import-set' -ObsValue '["VirtualProtect","WriteProcessMemory"]'
                $B = _MakeFinding 'rule.b' -Subject 'c:/app/app.exe' -Dimension 'import-set' -ObsValue '["WriteProcessMemory","VirtualProtect"]'
                $r = Get-TcpkFindingRelationship -A $A -B $B
                $r.Relationship | Should -Be 'IDENTICAL'
                $r.SurvivingIsA | Should -Be $true
            }

            # (e) CONTAINED: superset survives -- naive implementation catcher
            # If naively comparing by string equality, CONTAINED would be missed.
            It '(e) CONTAINED: superset survives, subset is folded [naive catcher]' {
                $subset    = _MakeFinding 'rule.narrow' -Subject 'c:/app/app.exe' -Dimension 'import-set' -ObsValue '["VirtualProtect"]'
                $superset  = _MakeFinding 'rule.wide'   -Subject 'c:/app/app.exe' -Dimension 'import-set' -ObsValue '["VirtualProtect","WriteProcessMemory","CreateRemoteThread"]'
                $r = Get-TcpkFindingRelationship -A $subset -B $superset
                $r.Relationship  | Should -Be 'CONTAINED'
                $r.SurvivingIsA  | Should -Be $false   # B (superset) survives
                $r.Explanation   | Should -Match 'proper subset'
            }

            It '(e2) CONTAINED: superset in A position' {
                $superset  = _MakeFinding 'rule.wide'   -Subject 'c:/app/app.exe' -Dimension 'import-set' -ObsValue '["VirtualProtect","WriteProcessMemory","CreateRemoteThread"]'
                $subset    = _MakeFinding 'rule.narrow' -Subject 'c:/app/app.exe' -Dimension 'import-set' -ObsValue '["VirtualProtect"]'
                $r = Get-TcpkFindingRelationship -A $superset -B $subset
                $r.Relationship  | Should -Be 'CONTAINED'
                $r.SurvivingIsA  | Should -Be $true    # A (superset) survives
            }

            # (f) REFINED: same value, stronger basis wins
            It '(f) REFINED: Measured beats Inferred' {
                $inferred = _MakeFinding 'rule.infer'   -Subject 'c:/app/app.exe' -Dimension 'cert-validity' -ObsValue '"expired"' -Basis 'Inferred'
                $measured = _MakeFinding 'rule.measure' -Subject 'c:/app/app.exe' -Dimension 'cert-validity' -ObsValue '"expired"' -Basis 'Measured'
                $r = Get-TcpkFindingRelationship -A $inferred -B $measured
                $r.Relationship  | Should -Be 'REFINED'
                $r.SurvivingIsA  | Should -Be $false   # B (Measured) survives
                $r.Explanation   | Should -Match 'Measured'
            }

            # (g) DERIVED: count is aggregate of set
            It '(g) DERIVED: count == cardinality of set; set survives' {
                $setFinding   = _MakeFinding 'rule.enum'  -Subject 'c:/app/app.exe' -Dimension 'import-set' -ObsValue '["VirtualProtect","WriteProcessMemory","CreateRemoteThread"]'
                $countFinding = _MakeFinding 'rule.count' -Subject 'c:/app/app.exe' -Dimension 'import-set' -ObsValue '3'
                $r = Get-TcpkFindingRelationship -A $countFinding -B $setFinding
                $r.Relationship  | Should -Be 'DERIVED'
                $r.SurvivingIsA  | Should -Be $false   # B (set) survives
                $r.Explanation   | Should -Match 'aggregate'
            }

            # (h) COMPOSED: B declares A as BasisInput -> B is the composer
            It '(h) COMPOSED: composer declares source via BasisInputs' {
                $src      = _MakeFinding 'rule.src'  -Subject 'c:/app/app.exe' -Dimension 'import-set' -ObsValue '["VirtualProtect"]' -Basis 'Measured'
                $composed = _MakeFinding 'rule.comp' -Subject 'c:/app/app.exe' -Dimension 'import-set' -ObsValue '["VirtualProtect"]' -Basis 'Composed' -BasisInputs @('rule.src')
                $r = Get-TcpkFindingRelationship -A $src -B $composed
                $r.Relationship | Should -Be 'COMPOSED'
                $r.Explanation  | Should -Match 'Composed-from'
            }

            # (i) INDEPENDENT even when the struct/value differs on same dim
            It '(i) INDEPENDENT: same dimension but genuinely different struct values' {
                $A = _MakeFinding 'rule.nx-on'  -Subject 'c:/app/app.exe' -Dimension 'pe-mitigations' -ObsValue '{"nx":true,"aslr":false}'
                $B = _MakeFinding 'rule.nx-off' -Subject 'c:/app/app.exe' -Dimension 'pe-mitigations' -ObsValue '{"nx":false,"aslr":true}'
                $r = Get-TcpkFindingRelationship -A $A -B $B
                $r.Relationship | Should -Be 'INDEPENDENT'
            }
        }

        # -------------------------------------------------------------------
        # SECTION 4: Invoke-TcpkRedundancyCorrelation (end-to-end pass)
        # -------------------------------------------------------------------

        Describe 'Invoke-TcpkRedundancyCorrelation' {

            It 'emits all findings unchanged when -NoCollapse' {
                $A = _MakeFinding 'rule.a' -Subject 'c:/app/app.exe' -Dimension 'import-set' -ObsValue '["VirtualProtect"]'
                $B = _MakeFinding 'rule.b' -Subject 'c:/app/app.exe' -Dimension 'import-set' -ObsValue '["VirtualProtect"]'
                $out = @($A, $B | Invoke-TcpkRedundancyCorrelation -NoCollapse)
                $out.Count | Should -Be 2
            }

            It 'collapses IDENTICAL pair to single survivor with AdjustmentLog' {
                $A = _MakeFinding 'rule.a' -Subject 'c:/app/app.exe' -Dimension 'import-set' -ObsValue '["VirtualProtect"]'
                $B = _MakeFinding 'rule.b' -Subject 'c:/app/app.exe' -Dimension 'import-set' -ObsValue '["VirtualProtect"]'
                $out = @($A, $B | Invoke-TcpkRedundancyCorrelation)
                $out.Count | Should -Be 1
                $out[0].AdjustmentLog | Should -Match 'REDUNDANCY:.*IDENTICAL'
            }

            It 'emits two INDEPENDENT findings unchanged' {
                $A = _MakeFinding 'rule.sig'  -Subject 'c:/app/app.exe' -Dimension 'signature-status'   -ObsValue '"unsigned"'
                $B = _MakeFinding 'rule.load' -Subject 'c:/app/app.exe' -Dimension 'load-configuration' -ObsValue '"unsigned"'
                $out = @($A, $B | Invoke-TcpkRedundancyCorrelation)
                $out.Count | Should -Be 2
                $out.AdjustmentLog | Should -Not -Match 'REDUNDANCY'
            }

            It 'collapses CONTAINED pair; superset survives' {
                $subset   = _MakeFinding 'rule.sub'   -Subject 'c:/app/app.exe' -Dimension 'import-set' -ObsValue '["VirtualProtect"]'   -Severity 'HIGH'
                $superset = _MakeFinding 'rule.super' -Subject 'c:/app/app.exe' -Dimension 'import-set' -ObsValue '["VirtualProtect","WriteProcessMemory"]' -Severity 'HIGH'
                $out = @($subset, $superset | Invoke-TcpkRedundancyCorrelation)
                $out.Count    | Should -Be 1
                $out[0].RuleId | Should -Be 'rule.super'
                $out[0].AdjustmentLog | Should -Match 'CONTAINED'
            }

            It 'passes through findings with no Subject (un-migrated rules)' {
                $old = _MakeFinding 'rule.legacy' -Subject '' -Dimension '' -ObsValue ''
                $out = @($old | Invoke-TcpkRedundancyCorrelation)
                $out.Count | Should -Be 1
            }

            It 'handles transitive fold chain (A->B->C all collapse to A)' {
                $A = _MakeFinding 'rule.a' -Subject 'c:/app/app.exe' -Dimension 'import-set' -ObsValue '["VirtualProtect"]'
                $B = _MakeFinding 'rule.b' -Subject 'c:/app/app.exe' -Dimension 'import-set' -ObsValue '["VirtualProtect"]'
                $C = _MakeFinding 'rule.c' -Subject 'c:/app/app.exe' -Dimension 'import-set' -ObsValue '["VirtualProtect"]'
                $out = @($A, $B, $C | Invoke-TcpkRedundancyCorrelation)
                $out.Count | Should -Be 1
                # All folds should land on the one surviving finding
                ($out[0].AdjustmentLog | Where-Object { $_ -match 'REDUNDANCY' }).Count | Should -BeGreaterOrEqual 2
            }

            It 'REFINED: Measured finding survives over Inferred' {
                $inferred = _MakeFinding 'rule.infer'   -Subject 'c:/app/app.exe' -Dimension 'cert-validity' -ObsValue '"expired"' -Basis 'Inferred'
                $measured = _MakeFinding 'rule.measure' -Subject 'c:/app/app.exe' -Dimension 'cert-validity' -ObsValue '"expired"' -Basis 'Measured'
                $out = @($inferred, $measured | Invoke-TcpkRedundancyCorrelation)
                $out.Count     | Should -Be 1
                $out[0].RuleId | Should -Be 'rule.measure'
                $out[0].AdjustmentLog | Should -Match 'REFINED'
            }
        }

        # -------------------------------------------------------------------
        # SECTION 5: Get-TcpkObservationCounts
        # -------------------------------------------------------------------

        Describe 'Get-TcpkObservationCounts' {
            It 'reports raw vs distinct counts correctly' {
                $raw = @(
                    _MakeFinding 'rule.a' -Severity 'HIGH'   -Subject 'c:/app/app.exe' -Dimension 'import-set' -ObsValue '["A"]'
                    _MakeFinding 'rule.b' -Severity 'HIGH'   -Subject 'c:/app/app.exe' -Dimension 'import-set' -ObsValue '["A"]'
                    _MakeFinding 'rule.c' -Severity 'MEDIUM' -Subject 'c:/app/app.exe' -Dimension 'signature-status' -ObsValue '"unsigned"'
                )
                $distinct = @($raw | Invoke-TcpkRedundancyCorrelation)
                $counts = Get-TcpkObservationCounts -Raw $raw -Distinct $distinct

                $counts.RawTotal       | Should -Be 3
                $counts.DistinctTotal  | Should -Be 2
                $counts.Folded         | Should -Be 1
                $counts.RawCounts['HIGH']   | Should -Be 2
                $counts.DistinctCounts['HIGH'] | Should -Be 1
                $counts.RelationshipBreakdown['IDENTICAL'] | Should -BeGreaterOrEqual 1
            }
        }
    }
}
