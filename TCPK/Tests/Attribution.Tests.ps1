Describe 'TCPK C8 - Attribution' {
    BeforeAll {
        $manifest = Join-Path $PSScriptRoot '..' 'TCPK.psd1'
        Import-Module (Resolve-Path $manifest) -Force -ErrorAction Stop
    }

    InModuleScope TCPK {

        function _MakeF {
            param([string]$RuleId, [string]$Severity='HIGH', [string]$AttrBasis='', [string]$Subject='')
            New-TcpkFinding -Module 'test' -RuleId $RuleId -Severity $Severity `
                -Title "$RuleId" -AttributionBasis $AttrBasis -Subject $Subject
        }

        # -----------------------------------------------------------------------
        # New-TcpkAttributionEvidence + Test-TcpkAttributionEstablished
        # -----------------------------------------------------------------------

        Describe 'Test-TcpkAttributionEstablished' {

            It 'code-capability establishes attribution' {
                $ev = New-TcpkAttributionEvidence -Type 'code-capability' -Detail 'installer calls CertAddEncodedCertificateToStore'
                $r  = Test-TcpkAttributionEstablished -Evidence @($ev)
                $r.Established | Should -Be $true
                $r.Basis       | Should -Be 'established-code'
                $r.Explanation | Should -Match 'code-capability'
            }

            It 'install-footprint establishes attribution' {
                $ev = New-TcpkAttributionEvidence -Type 'install-footprint' -Detail 'file is under C:\Program Files\App'
                $r  = Test-TcpkAttributionEstablished -Evidence @($ev)
                $r.Established | Should -Be $true
                $r.Basis       | Should -Be 'established-footprint'
            }

            It 'baseline-diff establishes attribution' {
                $ev = New-TcpkAttributionEvidence -Type 'baseline-diff' -Detail 'mitigation DISABLE_ATL_THUNK_EMULATION differs from OS default'
                $r  = Test-TcpkAttributionEstablished -Evidence @($ev)
                $r.Established | Should -Be $true
                $r.Basis       | Should -Be 'established-baseline-diff'
            }

            It 'name-match-only does NOT establish attribution' {
                $ev = New-TcpkAttributionEvidence -Type 'name-match' -Detail 'string "AppName" found in registry key'
                $r  = Test-TcpkAttributionEstablished -Evidence @($ev)
                $r.Established | Should -Be $false
                $r.Basis       | Should -Be 'name-match-only'
                $r.Explanation | Should -Match 'name/string match'
            }

            It 'no evidence -> unproven' {
                $r = Test-TcpkAttributionEstablished -Evidence @()
                $r.Established | Should -Be $false
                $r.Basis       | Should -Be 'unproven'
            }

            It 'strong evidence beats name-match when both provided' {
                $evs = @(
                    New-TcpkAttributionEvidence -Type 'name-match'        -Detail 'string match'
                    New-TcpkAttributionEvidence -Type 'install-footprint'  -Detail 'file in target dir'
                )
                $r = Test-TcpkAttributionEstablished -Evidence $evs
                $r.Established | Should -Be $true
                $r.Basis       | Should -Be 'established-footprint'
            }
        }

        # -----------------------------------------------------------------------
        # Get-TcpkSharedSurfaceInfo
        # -----------------------------------------------------------------------

        Describe 'Get-TcpkSharedSurfaceInfo' {

            It 'detects machine trust store as ambient' {
                $info = Get-TcpkSharedSurfaceInfo -NormalizedSubject 'cert:/localmachine/root'
                $info.Ambient | Should -Be $true
                $info.SurfaceType | Should -Be 'machine-trust-store'
            }

            It 'detects system COM CLSID as ambient' {
                $info = Get-TcpkSharedSurfaceInfo -NormalizedSubject 'hkey_local_machine/software/classes/clsid/{6d809377-6af0-444b-8957-a3773f02200e}'
                $info.Ambient | Should -Be $true
                $info.SurfaceType | Should -Be 'system-com-clsid'
            }

            It 'detects process-mitigation policy key as ambient' {
                $info = Get-TcpkSharedSurfaceInfo -NormalizedSubject 'hkey_local_machine/system/currentcontrolset/control/session manager/kernel'
                $info.Ambient | Should -Be $true
            }

            It 'per-user trust store is NOT automatically ambient' {
                $info = Get-TcpkSharedSurfaceInfo -NormalizedSubject 'cert:/currentuser/my'
                $info | Should -Not -BeNullOrEmpty
                $info.Ambient | Should -Be $false
            }

            It 'returns null for target-specific path' {
                $info = Get-TcpkSharedSurfaceInfo -NormalizedSubject 'c:/program files/myapp/app.exe'
                $info | Should -BeNullOrEmpty
            }
        }

        # -----------------------------------------------------------------------
        # Invoke-TcpkAttributionFilter
        # -----------------------------------------------------------------------

        Describe 'Invoke-TcpkAttributionFilter' {

            # TRUE POSITIVE controls - established attribution must NOT be demoted
            It '(TP) established-code finding is not demoted' {
                $f = _MakeF 'rule.cert' -Severity 'HIGH' -AttrBasis 'established-code'
                $out = @($f | Invoke-TcpkAttributionFilter)
                $out.Count    | Should -Be 1
                $out[0].Severity | Should -Be 'HIGH'
                $out[0].AdjustmentLog | Should -Not -Match 'CAP8:.*->INFO'
            }

            It '(TP) established-footprint finding is not demoted' {
                $f = _MakeF 'rule.cert' -Severity 'MEDIUM' -AttrBasis 'established-footprint'
                $out = @($f | Invoke-TcpkAttributionFilter)
                $out[0].Severity | Should -Be 'MEDIUM'
            }

            # FALSE POSITIVE scenarios - unproven attribution must be demoted
            It 'name-match-only finding is demoted to INFO' {
                $f = _MakeF 'rule.com' -Severity 'HIGH' -AttrBasis 'name-match-only'
                $out = @($f | Invoke-TcpkAttributionFilter)
                $out[0].Severity   | Should -Be 'INFO'
                $out[0].Confidence | Should -Be 'Unverified'
                $out[0].Title      | Should -Match '^AMBIENT:'
                $out[0].AdjustmentLog | Should -Match 'CAP8:.*name-match'
            }

            It 'unproven attribution finding is demoted to INFO' {
                $f = _MakeF 'rule.path' -Severity 'CRITICAL' -AttrBasis 'unproven'
                $out = @($f | Invoke-TcpkAttributionFilter)
                $out[0].Severity | Should -Be 'INFO'
                $out[0].AdjustmentLog | Should -Match 'CAP8:.*CRITICAL->INFO'
            }

            It 'un-migrated rule on known ambient surface gets CAP8 WARNING (no demotion)' {
                $f = _MakeF 'rule.mitigation' -Severity 'HIGH' -AttrBasis '' `
                    -Subject 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel'
                $out = @($f | Invoke-TcpkAttributionFilter)
                $out[0].Severity | Should -Be 'HIGH'    # NOT demoted
                $out[0].AdjustmentLog | Should -Match 'CAP8:.*WARNING'
            }

            It 'un-migrated rule on NON-ambient path gets no annotation' {
                $f = _MakeF 'rule.app' -Severity 'HIGH' -AttrBasis '' -Subject 'C:\Program Files\App\app.exe'
                $out = @($f | Invoke-TcpkAttributionFilter)
                $out[0].Severity | Should -Be 'HIGH'
                $out[0].AdjustmentLog | Should -Not -Match 'CAP8'
            }

            It 'AdjustmentLog records original severity in the demotion entry' {
                $f = _MakeF 'rule.com' -Severity 'CRITICAL' -AttrBasis 'name-match-only'
                $out = @($f | Invoke-TcpkAttributionFilter)
                $out[0].AdjustmentLog | Should -Match 'CRITICAL->INFO'
            }
        }
    }
}
