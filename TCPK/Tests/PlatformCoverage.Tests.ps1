Describe 'TCPK CAP6 - Platform-Aware Coverage' {
    BeforeAll {
        $manifest = Join-Path $PSScriptRoot '..' 'TCPK.psd1'
        Import-Module (Resolve-Path $manifest) -Force -ErrorAction Stop
    }

    InModuleScope TCPK {

        # -----------------------------------------------------------------------
        # Get-TcpkDerivedSearchSurface
        # -----------------------------------------------------------------------

        Describe 'Get-TcpkDerivedSearchSurface' {

            It 'returns non-empty surface for electron/credential' {
                $surface = Get-TcpkDerivedSearchSurface -PlatformClass 'electron' -StoreClass 'credential'
                $surface.Count | Should -BeGreaterThan 0
            }

            It 'includes both protected and unprotected stores for electron/credential' {
                $surface = Get-TcpkDerivedSearchSurface -PlatformClass 'electron' -StoreClass 'credential'
                $protected   = @($surface | Where-Object { $_.Protected })
                $unprotected = @($surface | Where-Object { -not $_.Protected })
                $protected.Count   | Should -BeGreaterThan 0
                $unprotected.Count | Should -BeGreaterThan 0
            }

            It 'unprotected stores are NOT absent from the surface (no silent exclusion)' {
                $surface = Get-TcpkDerivedSearchSurface -PlatformClass 'electron' -StoreClass 'credential'
                # local-storage-leveldb must be present -- it is the most common
                # cleartext token store in Electron apps and must never be silently omitted
                $names = @($surface | ForEach-Object { $_.StoreName })
                $names | Should -Contain 'local-storage-leveldb'
            }

            It 'resolves relative paths when BaseDir is supplied' {
                $surface = Get-TcpkDerivedSearchSurface -PlatformClass 'electron' -StoreClass 'credential' `
                    -BaseDir 'C:\App\AppData'
                $withPaths = @($surface | Where-Object { $_.Paths.Count -gt 0 })
                $withPaths.Count | Should -BeGreaterThan 0
                $withPaths[0].Paths[0] | Should -Match '^C:\\App\\AppData'
            }

            It 'falls back to unknown platform gracefully' {
                $surface = Get-TcpkDerivedSearchSurface -PlatformClass 'cobol-mainframe' -StoreClass 'credential'
                $surface.Count | Should -BeGreaterThan 0
            }

            It 'surface descriptors start with Inspected=$false' {
                $surface = Get-TcpkDerivedSearchSurface -PlatformClass 'dotnet' -StoreClass 'credential'
                $preMarked = @($surface | Where-Object { $_.Inspected })
                $preMarked.Count | Should -Be 0
            }

            It 'returns native-win32 stores covering plaintext locations' {
                $surface = Get-TcpkDerivedSearchSurface -PlatformClass 'native-win32' -StoreClass 'credential'
                $plaintextStores = @($surface | Where-Object { -not $_.Protected })
                $plaintextStores.Count | Should -BeGreaterThan 0
            }
        }

        # -----------------------------------------------------------------------
        # New-TcpkCoverageExclusion -- exclusion logging
        # -----------------------------------------------------------------------

        Describe 'New-TcpkCoverageExclusion' {

            It 'creates exclusion record with required fields' {
                $ex = New-TcpkCoverageExclusion -Location 'C:\App\Cache' -Reason 'performance budget exceeded' -RuleId 'test.rule' -Capacity 'credential'
                $ex.Location | Should -Be 'C:\App\Cache'
                $ex.Reason   | Should -Match 'performance'
                $ex.RuleId   | Should -Be 'test.rule'
                $ex.Capacity | Should -Be 'credential'
            }

            It 'records timestamp in ISO-8601' {
                $ex = New-TcpkCoverageExclusion -Location 'X' -Reason 'Y'
                $ex.Timestamp | Should -Match '^\d{4}-\d{2}-\d{2}T'
            }
        }

        # -----------------------------------------------------------------------
        # Assert-TcpkCoverageComplete -- gap detection
        # -----------------------------------------------------------------------

        Describe 'Assert-TcpkCoverageComplete' {

            It 'emits no preconditions when all stores are inspected' {
                $surface = Get-TcpkDerivedSearchSurface -PlatformClass 'electron' -StoreClass 'credential'
                foreach ($s in $surface) { $s.Inspected = $true }
                $gaps = @(Assert-TcpkCoverageComplete -Surface $surface)
                $gaps.Count | Should -Be 0
            }

            It 'emits UNTESTED precondition for each uninspected UNPROTECTED store' {
                $surface = Get-TcpkDerivedSearchSurface -PlatformClass 'electron' -StoreClass 'credential'
                # Mark only the protected stores as inspected
                foreach ($s in $surface) { $s.Inspected = $s.Protected }
                $gaps = @(Assert-TcpkCoverageComplete -Surface $surface)
                $gaps.Count | Should -BeGreaterThan 0
                $gaps[0].State | Should -Be 'UNTESTED'
            }

            It 'does NOT emit gap for a protected uninspected store (protected = platform guards it)' {
                # CAP6 is specifically about UNPROTECTED stores.  A protected store
                # the rule missed is a coverage concern but not an UNPROTECTED gap.
                $surface = Get-TcpkDerivedSearchSurface -PlatformClass 'electron' -StoreClass 'credential'
                # Leave all stores Inspected=$false but check ONLY for unprotected gaps
                $gaps = @(Assert-TcpkCoverageComplete -Surface $surface)
                $gapNames = @($gaps | ForEach-Object { $_.Name })
                # All gaps should correspond to unprotected stores
                foreach ($g in $gapNames) {
                    $storeName = $g -replace '^store-','' -replace '-inspected$',''
                    $descriptor = $surface | Where-Object { $_.StoreName -eq $storeName }
                    if ($descriptor) {
                        $descriptor.Protected | Should -Be $false
                    }
                }
            }

            It 'InspectedStoreNames union with .Inspected flag' {
                $surface = Get-TcpkDerivedSearchSurface -PlatformClass 'electron' -StoreClass 'credential'
                $unprotectedNames = @($surface | Where-Object { -not $_.Protected } | ForEach-Object { $_.StoreName })
                $gaps = @(Assert-TcpkCoverageComplete -Surface $surface -InspectedStoreNames $unprotectedNames)
                # All unprotected stores named in InspectedStoreNames should NOT appear as gaps
                $gapNames = @($gaps | ForEach-Object { $_.Name })
                foreach ($n in $unprotectedNames) {
                    $gapNames | Should -Not -Contain "store-$n-inspected"
                }
            }
        }

        # -----------------------------------------------------------------------
        # Format-TcpkCoverageLog -- report output
        # -----------------------------------------------------------------------

        Describe 'Format-TcpkCoverageLog' {

            It 'marks uninspected unprotected stores as coverage gaps' {
                $surface = Get-TcpkDerivedSearchSurface -PlatformClass 'electron' -StoreClass 'credential'
                foreach ($s in $surface) { $s.Inspected = $s.Protected }  # only protected inspected
                $log = Format-TcpkCoverageLog -Surface $surface
                $gaps = @($log | Where-Object { $_ -match 'COVERAGE GAP' })
                $gaps.Count | Should -BeGreaterThan 0
            }

            It 'includes exclusion details when exclusions are provided' {
                $surface = @()   # empty surface for this test
                $ex = New-TcpkCoverageExclusion -Location 'C:\Temp\cache' -Reason 'read error' -RuleId 'tokens.scan' -Capacity 'credential'
                $log = Format-TcpkCoverageLog -Surface $surface -Exclusions @($ex)
                $log | Should -Match 'EXCLUDED'
                $log | Should -Match 'read error'
                $log | Should -Match 'credential'
            }
        }
    }
}
