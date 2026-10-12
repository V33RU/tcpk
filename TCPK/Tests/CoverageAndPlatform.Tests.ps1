#requires -Version 5.1
# Regression guards for two bugs seen in a live Windows audit:
#   1. A coverage status ($script:TcpkCoverageStatuses) that is not in the Add-TcpkCoverage
#      ValidateSet, so emitting it throws a parameter-binding error (GatedNoPfn did this).
#   2. .ContainsKey called on the [ordered] store catalog in Get-TcpkDerivedSearchSurface --
#      OrderedDictionary has .Contains, not .ContainsKey, so the call threw on every invocation.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
}

Describe 'Add-TcpkCoverage accepts every declared status' {
    It 'the ValidateSet and $script:TcpkCoverageStatuses agree' {
        InModuleScope TCPK {
            Clear-TcpkCoverage
            foreach ($s in $script:TcpkCoverageStatuses) {
                { Add-TcpkCoverage -Name "t-$s" -Status $s } |
                    Should -Not -Throw -Because "$s is a declared coverage status and must be in the Add-TcpkCoverage ValidateSet"
            }
        }
    }
}

Describe 'Get-TcpkDerivedSearchSurface does not choke on the ordered catalog' {
    It 'resolves a known platform/store without a ContainsKey error' {
        InModuleScope TCPK {
            { Get-TcpkDerivedSearchSurface -PlatformClass 'electron' -StoreClass 'credential' } | Should -Not -Throw
        }
    }
    It 'falls back for an unknown platform without throwing' {
        InModuleScope TCPK {
            { Get-TcpkDerivedSearchSurface -PlatformClass 'no-such-platform' -StoreClass 'credential' } | Should -Not -Throw
        }
    }
}
