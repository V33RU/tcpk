Describe 'TCPK CAP7 - Internal Consistency Enforcement' {
    BeforeAll {
        $manifest = Join-Path $PSScriptRoot '..' 'TCPK.psd1'
        Import-Module (Resolve-Path $manifest) -Force -ErrorAction Stop
    }

    InModuleScope TCPK {

        function _MakeFinding {
            param(
                [string]$RuleId,
                [string]$Severity   = 'HIGH',
                [string]$Confidence = 'Confirmed',
                [string]$Subject    = '',
                [string]$Dimension  = '',
                [string]$ObsValue   = '',
                [string]$Basis      = 'Measured'
            )
            New-TcpkFinding -Module 'test' -RuleId $RuleId -Severity $Severity `
                -Confidence $Confidence -Title "$RuleId" `
                -Subject $Subject -Dimension $Dimension -ObsValue $ObsValue -Basis $Basis
        }

        # -----------------------------------------------------------------------
        # Get-TcpkPlatformConstraints
        # -----------------------------------------------------------------------

        Describe 'Get-TcpkPlatformConstraints' {

            It 'returns constraints for electron including cfg-mitigation negation' {
                $c = @(Get-TcpkPlatformConstraints -PlatformClass 'electron')
                $cfgConstraint = @($c | Where-Object { $_.NegatesDim -eq 'cfg-mitigation' })
                $cfgConstraint.Count | Should -BeGreaterThan 0
                $cfgConstraint[0].GoverningPattern | Should -Match 'electron'
            }

            It 'returns rwx constraint for electron (ExpectedBehavior)' {
                $c = @(Get-TcpkPlatformConstraints -PlatformClass 'electron')
                $rwx = @($c | Where-Object { $_.NegatesDim -eq 'memory-protection' })
                $rwx.Count | Should -BeGreaterThan 0
            }

            It 'returns no constraints for unknown platform' {
                $c = @(Get-TcpkPlatformConstraints -PlatformClass 'unknown')
                $c.Count | Should -Be 0
            }

            It 'returns constraints for native-win32 (no CanEnable=false features)' {
                # native-win32 can enable everything; no can-enable constraints.
                # But this tests that it does not crash.
                { Get-TcpkPlatformConstraints -PlatformClass 'native-win32' } | Should -Not -Throw
            }

            It 'does NOT emit cfg constraint for dotnet (dotnet CanEnable cfg=$true)' {
                $c = @(Get-TcpkPlatformConstraints -PlatformClass 'dotnet')
                $cfgConstraint = @($c | Where-Object { $_.NegatesDim -eq 'cfg-mitigation' })
                $cfgConstraint.Count | Should -Be 0
            }
        }

        # -----------------------------------------------------------------------
        # Invoke-TcpkConsistencyCheck - contradiction detection
        # -----------------------------------------------------------------------

        Describe 'Invoke-TcpkConsistencyCheck' {

            # (a) TRUE POSITIVE: two consistent findings must NOT be suppressed
            It '(a) two non-contradicting findings on the same subject both survive' {
                $sig  = _MakeFinding 'rule.sig'    -Subject 'c:/app/app.exe' -Dimension 'signature-status'   -ObsValue '"unsigned"'
                $mem  = _MakeFinding 'rule.mem'    -Subject 'c:/app/app.exe' -Dimension 'memory-protection'  -ObsValue 'nx-missing'
                $out  = @($sig, $mem | Invoke-TcpkConsistencyCheck)
                $out.Count | Should -Be 2
            }

            # (b) Signature status contradiction: valid vs unsigned on same binary
            It '(b) valid-signature suppresses unsigned-claim on same subject' {
                $valid    = _MakeFinding 'rule.sig-measured'  -Subject 'c:/app/app.exe' -Dimension 'signature-status' -ObsValue '"valid"'    -Basis 'Measured'
                $unsigned = _MakeFinding 'rule.sig-inferred'  -Subject 'c:/app/app.exe' -Dimension 'signature-status' -ObsValue '"unsigned"' -Basis 'Inferred'
                $out = @($valid, $unsigned | Invoke-TcpkConsistencyCheck)
                $out.Count    | Should -Be 1
                $out[0].RuleId | Should -Be 'rule.sig-measured'
                $out[0].AdjustmentLog | Should -Match 'CAP7'
            }

            # (c) TRUE POSITIVE control for (b): same Basis -- weaker (Inferred) is still suppressed
            It '(c) valid-signature (Measured) suppresses unsigned (Inferred) regardless of order' {
                $unsigned = _MakeFinding 'rule.sig-inferred'  -Subject 'c:/app/app.exe' -Dimension 'signature-status' -ObsValue '"unsigned"' -Basis 'Inferred'
                $valid    = _MakeFinding 'rule.sig-measured'  -Subject 'c:/app/app.exe' -Dimension 'signature-status' -ObsValue '"valid"'    -Basis 'Measured'
                $out = @($unsigned, $valid | Invoke-TcpkConsistencyCheck)
                $out.Count    | Should -Be 1
                $out[0].RuleId | Should -Be 'rule.sig-measured'
            }

            # (d) Store encryption disabled contradicts dpapi-exposure finding
            It '(d) encryption-disabled suppresses dpapi-exposure finding' {
                $encOff  = _MakeFinding 'rule.enc-state' -Subject 'c:/app/db.sqlite' -Dimension 'store-encryption-state'   -ObsValue '"disabled"' -Basis 'Measured'
                $dpapiHi = _MakeFinding 'rule.dpapi-exp' -Subject 'c:/app/db.sqlite' -Dimension 'dpapi-credential-exposure' -ObsValue '"high"'     -Basis 'Inferred'
                $out = @($encOff, $dpapiHi | Invoke-TcpkConsistencyCheck)
                $out.Count     | Should -Be 1
                $out[0].RuleId | Should -Be 'rule.enc-state'
                $out[0].AdjustmentLog | Should -Match 'CAP7.*dpapi-credential-exposure'
            }

            # (e) TRUE POSITIVE: encryption enabled -> dpapi-exposure finding is consistent, NOT suppressed
            It '(e) encryption-enabled does NOT suppress dpapi-exposure (no contradiction)' {
                $encOn   = _MakeFinding 'rule.enc-state' -Subject 'c:/app/db.sqlite' -Dimension 'store-encryption-state'   -ObsValue '"enabled"' -Basis 'Measured'
                $dpapiHi = _MakeFinding 'rule.dpapi-exp' -Subject 'c:/app/db.sqlite' -Dimension 'dpapi-credential-exposure' -ObsValue '"high"'    -Basis 'Inferred'
                $out = @($encOn, $dpapiHi | Invoke-TcpkConsistencyCheck)
                $out.Count | Should -Be 2
            }

            # (f) Platform-derived constraint: electron + cfg-mitigation=missing is suppressed
            # The governing finding is platform-class=electron; the negated is cfg-mitigation=missing
            It '(f) electron platform-class suppresses cfg-mitigation=missing finding' {
                $platformFinding = _MakeFinding 'rule.profile' -Subject 'c:/app/app.exe' -Dimension 'platform-class'  -ObsValue '"electron"'  -Basis 'Measured'
                $cfgMissing      = _MakeFinding 'rule.cfg'     -Subject 'c:/app/app.exe' -Dimension 'cfg-mitigation'  -ObsValue '"missing"'   -Basis 'Inferred'
                $out = @($platformFinding, $cfgMissing | Invoke-TcpkConsistencyCheck)
                $out.Count     | Should -Be 1
                $out[0].RuleId | Should -Be 'rule.profile'
                $out[0].AdjustmentLog | Should -Match 'CAP7'
            }

            # (g) TRUE POSITIVE control for (f): native-win32 + cfg-mitigation=missing is NOT suppressed
            # native-win32 can enable cfg; a missing cfg on a native binary is a real finding.
            It '(g) native-win32 does NOT suppress cfg-mitigation=missing [true-positive control]' {
                $platformFinding = _MakeFinding 'rule.profile' -Subject 'c:/app/app.exe' -Dimension 'platform-class' -ObsValue '"native-win32"' -Basis 'Measured'
                $cfgMissing      = _MakeFinding 'rule.cfg'     -Subject 'c:/app/app.exe' -Dimension 'cfg-mitigation' -ObsValue '"missing"'      -Basis 'Inferred'
                $out = @($platformFinding, $cfgMissing | Invoke-TcpkConsistencyCheck)
                $out.Count | Should -Be 2
            }

            # (h) Stronger basis wins: if negated has higher basis, it survives and governing is suppressed
            It '(h) negated finding with stronger basis suppresses the governing claim' {
                # governing is Inferred; negated is Measured -- negated wins
                $govInferred  = _MakeFinding 'rule.enc-inferred' -Subject 'c:/app/db' -Dimension 'store-encryption-state'    -ObsValue '"disabled"' -Basis 'Inferred'
                $negMeasured  = _MakeFinding 'rule.dpapi-meas'   -Subject 'c:/app/db' -Dimension 'dpapi-credential-exposure'  -ObsValue '"high"'     -Basis 'Measured'
                $out = @($govInferred, $negMeasured | Invoke-TcpkConsistencyCheck)
                $out.Count     | Should -Be 1
                $out[0].RuleId | Should -Be 'rule.dpapi-meas'
                $out[0].AdjustmentLog | Should -Match 'CAP7'
            }

            # (i) Findings on DIFFERENT subjects are never conflated
            It '(i) contradicting dimensions on different subjects both survive' {
                $a = _MakeFinding 'rule.a' -Subject 'c:/app/a.exe' -Dimension 'signature-status' -ObsValue '"valid"'    -Basis 'Measured'
                $b = _MakeFinding 'rule.b' -Subject 'c:/app/b.exe' -Dimension 'signature-status' -ObsValue '"unsigned"' -Basis 'Inferred'
                $out = @($a, $b | Invoke-TcpkConsistencyCheck)
                $out.Count | Should -Be 2
            }

            # (j) Findings with no Subject pass through unchanged
            It '(j) findings without Subject are not touched' {
                $a = _MakeFinding 'rule.legacy' -Subject '' -Dimension '' -ObsValue ''
                $b = _MakeFinding 'rule.other'  -Subject '' -Dimension '' -ObsValue ''
                $out = @($a, $b | Invoke-TcpkConsistencyCheck)
                $out.Count | Should -Be 2
                $out.AdjustmentLog | Should -Not -Match 'CAP7'
            }

            # (k) AdjustmentLog entry includes reason text for auditability
            It '(k) suppression entry contains constraint reason text' {
                $valid    = _MakeFinding 'rule.sig-m' -Subject 'c:/app/app.exe' -Dimension 'signature-status' -ObsValue '"valid"'    -Basis 'Measured'
                $unsigned = _MakeFinding 'rule.sig-i' -Subject 'c:/app/app.exe' -Dimension 'signature-status' -ObsValue '"unsigned"' -Basis 'Inferred'
                $out = @($valid, $unsigned | Invoke-TcpkConsistencyCheck)
                # The survivor's AdjustmentLog should explain WHY
                $entry = $out[0].AdjustmentLog | Where-Object { $_ -match 'CAP7' }
                $entry | Should -Match 'signature'
                $entry | Should -Match 'Measured'
            }
        }
    }
}
