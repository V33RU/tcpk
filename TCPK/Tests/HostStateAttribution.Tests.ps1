#requires -Version 5.1
#
# C8 host-state scoping. Guards the fix for the scan-host defect: host-state detectors
# (services, scheduled tasks, WMI consumers, drivers, App Paths / IFEO / registry load points)
# must not attribute the operator's machine to the audit target. The decision runs through
# Resolve-TcpkHostStateBasis: a matched object is actionable ONLY when its binary resolves
# inside the audited tree (install-footprint); a pure name match is demoted to INFO.
#
# Two layers are asserted:
#   1. the helper's logic, directly;
#   2. a wiring ratchet - every patched detector must still call the helper, so the gate
#      cannot be silently removed while leaving the detector emitting unscoped HIGHs.

Describe 'C8 - host-state attribution scoping' {

    BeforeAll {
        $manifest = Join-Path $PSScriptRoot '..' 'TCPK.psd1'
        Import-Module (Resolve-Path $manifest) -Force -ErrorAction Stop
        $script:PublicDir = Join-Path (Split-Path $PSScriptRoot -Parent) 'Public'
    }

    InModuleScope TCPK {

        Describe 'Resolve-TcpkHostStateBasis' {

            It 'binary under the target tree -> established-footprint, keeps actionable severity' {
                $r = Resolve-TcpkHostStateBasis -ImagePath 'C:\Target\app\svc.exe' -TargetRoot 'C:\Target' `
                        -ActionableSeverity 'HIGH' -MatchDetail "Service 'Foo' matched target term"
                $r.Established | Should -BeTrue
                $r.Basis       | Should -Be 'established-footprint'
                $r.Severity    | Should -Be 'HIGH'
                $r.Subject     | Should -Be 'C:\Target\app\svc.exe'
            }

            It 'name match but binary OUTSIDE the target tree -> name-match-only, demoted to INFO' {
                $r = Resolve-TcpkHostStateBasis -ImagePath 'C:\Windows\System32\svchost.exe' -TargetRoot 'C:\Target' `
                        -ActionableSeverity 'HIGH' -MatchDetail "Service 'Foo' matched target term"
                $r.Established | Should -BeFalse
                $r.Basis       | Should -Be 'name-match-only'
                $r.Severity    | Should -Be 'INFO'
            }

            It 'preserves a non-HIGH actionable severity when attributed' {
                $r = Resolve-TcpkHostStateBasis -ImagePath 'C:\Target\drv.sys' -TargetRoot 'C:\Target' `
                        -ActionableSeverity 'MEDIUM' -MatchDetail 'driver matched'
                $r.Established | Should -BeTrue
                $r.Severity    | Should -Be 'MEDIUM'
            }

            It 'no resolvable path -> unproven, INFO, subject falls back to the override' {
                $r = Resolve-TcpkHostStateBasis -ImagePath '' -TargetRoot 'C:\Target' `
                        -Subject 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs'
                $r.Established | Should -BeFalse
                $r.Basis       | Should -Be 'unproven'
                $r.Severity    | Should -Be 'INFO'
                $r.Subject     | Should -Be 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs'
            }

            It 'empty target root disables the footprint test (never attributes)' {
                $r = Resolve-TcpkHostStateBasis -ImagePath 'C:\Target\app\svc.exe' -TargetRoot '' `
                        -ActionableSeverity 'HIGH' -MatchDetail 'svc matched'
                $r.Established | Should -BeFalse
                $r.Severity    | Should -Be 'INFO'
            }

            It 'subject defaults to the image path when not overridden' {
                $r = Resolve-TcpkHostStateBasis -ImagePath 'C:\Target\app\svc.exe' -TargetRoot 'C:\Target' -MatchDetail 'x'
                $r.Subject | Should -Be 'C:\Target\app\svc.exe'
            }

            It 'a name-match-only basis is demoted to INFO by the CAP8 filter (end to end)' {
                $r = Resolve-TcpkHostStateBasis -ImagePath 'C:\Windows\System32\svchost.exe' -TargetRoot 'C:\Target' `
                        -ActionableSeverity 'HIGH' -MatchDetail 'svc matched'
                $f = New-TcpkFinding -Module 'os' -RuleId 'service.weak-dacl' -Severity $r.Severity `
                        -Title 'x' -AttributionBasis $r.Basis -Subject $r.Subject
                $out = @($f | Invoke-TcpkAttributionFilter)
                $out[0].Severity | Should -Be 'INFO'
            }
        }
    }

    It 'every patched host-state detector still calls the scoping helper' {
        # Wiring ratchet: if a future edit drops the Resolve-TcpkHostStateBasis call, the
        # detector would go back to emitting unscoped HIGH findings. Fail loudly instead.
        $detectors = @(
            'Test-TcpkServicePermissions', 'Test-TcpkServiceBinaryAcl', 'Test-TcpkUnquotedServicePath',
            'Test-TcpkScheduledTaskAcl', 'Test-TcpkWmiPersistence', 'Test-TcpkKernelDrivers',
            'Test-TcpkAppPaths', 'Test-TcpkIfeoHijack', 'Test-TcpkPersistenceLoadPoints'
        )
        foreach ($d in $detectors) {
            $file = Join-Path $script:PublicDir (Join-Path 'OsIntegration' "$d.ps1")
            (Get-Content -LiteralPath $file -Raw) | Should -Match 'Resolve-TcpkHostStateBasis' -Because "$d must scope host-state findings"
        }
    }
}
