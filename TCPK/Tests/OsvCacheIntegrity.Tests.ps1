#requires -Version 5.1
# Pester 5: a component may only be cached as "checked, none" when OSV actually answered.
#
# THE BUG. Get-TcpkOsvQueryNet failed closed -- on any error it warned and returned nothing.
# Get-TcpkOsvMatches then ran its write-back loop UNCONDITIONALLY over every queried
# component and stored @{ fetchedUtc = now; matches = @() } for each. For the next 7 days
# the freshness test passed, no network call was made, and not even the warning printed
# again. The HTML report stated the components "were matched live against OSV", and
# Export-TcpkSbom emitted an empty CycloneDX vulnerabilities[] -- a machine-readable file
# another pipeline ingests as truth. A silent, self-perpetuating false negative on the only
# CVE path in the tool.
#
# Two of the three routes to it need NO network failure at all, and both fire on a fully
# successful HTTP 200 run:
#   * the MaxDetail cap stopped enrichment with `break`, so every component whose vulns fell
#     past the cap was cached clean
#   * a single per-vuln detail fetch that 404s or times out hit `catch { continue }`, and
#     that vuln's component was cached clean
#
# These tests pin the contract: cache only what was ANSWERED, and never let -OnlineCve alone
# license the "matched live" wording.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
}

Describe 'Query status tracking' {

    It 'starts not-Ok, so nothing is cacheable before a successful query' {
        InModuleScope TCPK {
            Reset-TcpkOsvQueryStatus
            $st = Get-TcpkOsvQueryStatus
            $st.Ok | Should -BeFalse
            $st.Answered.Count | Should -Be 0
        }
    }

    It 'reports Ok with nothing answered when the batch call throws' {
        InModuleScope TCPK {
            Mock Invoke-RestMethod { throw 'no route to host' }
            $r = @(Get-TcpkOsvQueryNet -Components @(@{ Name = 'lodash'; Version = '4.17.15' }) -Ecosystem 'npm')
            $st = Get-TcpkOsvQueryStatus
            $st.Ok | Should -BeFalse -Because 'a failed batch query answered for nothing'
            $st.Answered.Count | Should -Be 0
            $st.Reason | Should -Not -BeNullOrEmpty
        }
    }
}

Describe 'Cache write-back is gated on a real answer' {

    It 'caches NOTHING when the query failed' {
        InModuleScope TCPK {
            Mock Invoke-RestMethod { throw 'proxy refused' }
            Mock Save-TcpkOsvCache { }
            Mock Get-TcpkOsvCache { @{} }
            $null = Get-TcpkOsvMatches -Components @(@{ Name = 'lodash'; Version = '4.17.15' }) -Ecosystem 'npm'
            # The regression: this used to be called with every component stamped clean.
            Assert-MockCalled Save-TcpkOsvCache -Times 0 -Exactly `
                -Because 'a failed lookup must leave the cache untouched so the next run retries'
        }
    }

    It 'records the failure on the session roll-up' {
        InModuleScope TCPK {
            Reset-TcpkOsvSession
            Mock Invoke-RestMethod { throw 'timeout' }
            Mock Save-TcpkOsvCache { }
            Mock Get-TcpkOsvCache { @{} }
            $null = Get-TcpkOsvMatches -Components @(@{ Name = 'x'; Version = '1.0.0' }) -Ecosystem 'npm'
            $s = Get-TcpkOsvSession
            $s.Attempted | Should -BeTrue
            $s.Failures  | Should -BeGreaterThan 0
        }
    }

    It 'DOES cache a component OSV genuinely answered clean' {
        InModuleScope TCPK {
            Reset-TcpkOsvSession
            # One query, one result slot, zero vulns -> a real "checked, none".
            Mock Invoke-RestMethod { [pscustomobject]@{ results = @([pscustomobject]@{ vulns = @() }) } }
            $saved = $null
            Mock Save-TcpkOsvCache { $saved = $Cache } -Verifiable
            Mock Get-TcpkOsvCache { @{} }
            $null = Get-TcpkOsvMatches -Components @(@{ Name = 'clean-pkg'; Version = '1.0.0' }) -Ecosystem 'npm'
            Assert-MockCalled Save-TcpkOsvCache -Times 1 -Exactly `
                -Because 'zero vulns WITH a result slot is a genuine answer and should cache'
        }
    }

    It 'does NOT cache a component whose result slot is missing from a short response' {
        InModuleScope TCPK {
            Reset-TcpkOsvSession
            # Two components queried, only one result slot returned.
            Mock Invoke-RestMethod { [pscustomobject]@{ results = @([pscustomobject]@{ vulns = @() }) } }
            Mock Get-TcpkOsvCache { @{} }
            Mock Save-TcpkOsvCache { }
            $null = Get-TcpkOsvMatches -Components @(
                @{ Name = 'a'; Version = '1.0.0' }, @{ Name = 'b'; Version = '2.0.0' }) -Ecosystem 'npm'
            $st = Get-TcpkOsvQueryStatus
            $st.Answered.Count | Should -Be 1 -Because 'only the component with a result slot was answered'
            (Get-TcpkOsvSession).Incomplete | Should -BeGreaterThan 0
        }
    }
}

Describe 'Run-completeness gates the reports' {

    It 'is not complete when a query failed' {
        InModuleScope TCPK {
            Reset-TcpkOsvSession
            $s = Get-TcpkOsvSession
            $s.Attempted = $true; $s.Failures = 1
            Test-TcpkOsvRunComplete | Should -BeFalse
        }
    }

    It 'is not complete when the detail cap truncated the run' {
        InModuleScope TCPK {
            Reset-TcpkOsvSession
            $s = Get-TcpkOsvSession
            $s.Attempted = $true; $s.Truncated = $true
            Test-TcpkOsvRunComplete | Should -BeFalse -Because 'the cap leaves components unenriched on a HTTP 200 run'
        }
    }

    It 'is not complete when a component went unanswered' {
        InModuleScope TCPK {
            Reset-TcpkOsvSession
            $s = Get-TcpkOsvSession
            $s.Attempted = $true; $s.Incomplete = 3
            Test-TcpkOsvRunComplete | Should -BeFalse
        }
    }

    It 'is not complete when no lookup was attempted at all' {
        InModuleScope TCPK {
            Reset-TcpkOsvSession
            Test-TcpkOsvRunComplete | Should -BeFalse -Because 'never asked is not the same as asked and clean'
        }
    }

    It 'IS complete on a clean full run' {
        InModuleScope TCPK {
            Reset-TcpkOsvSession
            (Get-TcpkOsvSession).Attempted = $true
            Test-TcpkOsvRunComplete | Should -BeTrue
        }
    }
}

Describe 'Runtime-CVE text does not claim a query that did not complete' {

    It 'says UNKNOWN, not "no advisories", after an incomplete lookup' {
        $txt = InModuleScope TCPK {
            Reset-TcpkOsvSession
            $s = Get-TcpkOsvSession; $s.Attempted = $true; $s.Failures = 1
            $f = New-TcpkFinding -Module 'static' -RuleId 'electron.outdated-runtime' `
                 -Severity 'MEDIUM' -Confidence 'Inferred' -Title 'old electron' `
                 -Description 'Bundled electron@41.2.0 is behind. Run with -OnlineCve to enumerate advisories.'
            (Update-TcpkRuntimeCveText -Finding $f -CveMatches @() -OnlineCve $true).Description
        }
        $txt | Should -Match 'UNKNOWN'
        $txt | Should -Not -Match 'returned no advisories'
    }

    It 'says "queried, no advisories" after a complete lookup' {
        $txt = InModuleScope TCPK {
            Reset-TcpkOsvSession
            (Get-TcpkOsvSession).Attempted = $true
            $f = New-TcpkFinding -Module 'static' -RuleId 'electron.outdated-runtime' `
                 -Severity 'MEDIUM' -Confidence 'Inferred' -Title 'old electron' `
                 -Description 'Bundled electron@41.2.0 is behind. Run with -OnlineCve to enumerate advisories.'
            (Update-TcpkRuntimeCveText -Finding $f -CveMatches @() -OnlineCve $true).Description
        }
        $txt | Should -Match 'returned no advisories'
    }
}
