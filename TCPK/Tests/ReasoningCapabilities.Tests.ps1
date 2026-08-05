#requires -Module Pester

<#
Fixture matrix for the five TCPK reasoning capabilities (CAP1-CAP5).

Fixtures are written against the CAPABILITY, not against rule names or target names.
Each fixture declares a synthetic observation and asserts:
  - the resulting severity
  - the confidence (where it changes)
  - the specific explanation recorded in the adjustment log

A correct verdict reached by wrong reasoning must fail: tests check the log,
not just the headline severity.

True-positive fixtures are paired with false-positive fixtures so that tightening
a capability cannot silently suppress legitimate findings.
#>

BeforeAll {
    $modPath = Join-Path $PSScriptRoot '..\TCPK.psd1'
    if (-not (Test-Path $modPath)) { throw "Cannot locate TCPK.psd1 relative to $PSScriptRoot" }
    Import-Module $modPath -Force -ErrorAction Stop
}

# =============================================================================
Describe 'CAP1: Impact scored from measured facts, not asserted' {
# =============================================================================

    Context 'Resolve-TcpkImpact downgrade path' {

        It 'HIGH with no facts -> MEDIUM; log records CAP1' {
            InModuleScope TCPK {
                $log = [System.Collections.Generic.List[string]]::new()
                $sev = Resolve-TcpkImpact -RuleId 'cap1.test' -Facts @{} -Candidate 'HIGH' -Log ([ref]$log)
                $sev          | Should -Be 'MEDIUM'
                $log.Count    | Should -BeGreaterThan 0
                $log[0]       | Should -Match 'CAP1'
                $log[0]       | Should -Match 'HIGH->MEDIUM'
                $log[0]       | Should -Match 'no high-tier'
            }
        }

        It 'HIGH with page_count=42 (medium-tier only) -> MEDIUM; log records reason' {
            InModuleScope TCPK {
                $log = [System.Collections.Generic.List[string]]::new()
                $sev = Resolve-TcpkImpact -RuleId 'cap1.page' -Facts @{ page_count = 42 } -Candidate 'HIGH' -Log ([ref]$log)
                $sev       | Should -Be 'MEDIUM'
                $log[0]    | Should -Match 'HIGH->MEDIUM'
            }
        }

        It 'MEDIUM with no facts -> INFO; log records CAP1' {
            InModuleScope TCPK {
                $log = [System.Collections.Generic.List[string]]::new()
                $sev = Resolve-TcpkImpact -RuleId 'cap1.med' -Facts @{} -Candidate 'MEDIUM' -Log ([ref]$log)
                $sev       | Should -Be 'INFO'
                $log[0]    | Should -Match 'CAP1'
                $log[0]    | Should -Match 'MEDIUM->INFO'
            }
        }

        It 'HIGH with cookie_row_count=5 -> HIGH preserved (true positive kept)' {
            InModuleScope TCPK {
                $log = [System.Collections.Generic.List[string]]::new()
                $sev = Resolve-TcpkImpact -RuleId 'cap1.hit' -Facts @{ cookie_row_count = 5 } -Candidate 'HIGH' -Log ([ref]$log)
                $sev       | Should -Be 'HIGH'
                $log.Count | Should -Be 0     # no downgrade -> no log entry
            }
        }

        It 'INFO passes through unchanged (no downgrade below INFO)' {
            InModuleScope TCPK {
                $log = [System.Collections.Generic.List[string]]::new()
                $sev = Resolve-TcpkImpact -RuleId 'cap1.info' -Facts @{} -Candidate 'INFO' -Log ([ref]$log)
                $sev | Should -Be 'INFO'
            }
        }
    }

    Context 'Build-TcpkImpactSentences - fact-gated description' {

        It 'fact present (int > 0) -> sentence emitted' {
            InModuleScope TCPK {
                $sentences = Build-TcpkImpactSentences `
                    -Facts @{ cookie_row_count = 7 } `
                    -Templates @{ cookie_row_count = { param($v) "$v encrypted cookie(s)" } }
                $sentences.Count | Should -Be 1
                $sentences[0]    | Should -Match '7'
            }
        }

        It 'fact present (bool true) -> sentence emitted' {
            InModuleScope TCPK {
                $sentences = Build-TcpkImpactSentences `
                    -Facts @{ gcm_verified = $true } `
                    -Templates @{ gcm_verified = { 'AES-256-GCM round-trip verified' } }
                $sentences.Count | Should -Be 1
            }
        }

        It 'fact zero -> sentence suppressed (noun does not appear in description)' {
            InModuleScope TCPK {
                $sentences = Build-TcpkImpactSentences `
                    -Facts @{ cookie_row_count = 0 } `
                    -Templates @{ cookie_row_count = { param($v) "$v cookies" } }
                $sentences.Count | Should -Be 0
            }
        }

        It 'fact absent -> sentence suppressed' {
            InModuleScope TCPK {
                $sentences = Build-TcpkImpactSentences `
                    -Facts @{} `
                    -Templates @{ login_row_count = { param($v) "$v logins" } }
                $sentences.Count | Should -Be 0
            }
        }

        It 'mixed facts -> only truthy ones produce sentences' {
            InModuleScope TCPK {
                $facts = @{ cookie_row_count = 3; login_row_count = 0; gcm_verified = $true }
                $templates = @{
                    cookie_row_count = { param($v) "$v cookie(s)" }
                    login_row_count  = { param($v) "$v login(s)" }
                    gcm_verified     = { 'GCM ok' }
                }
                $sentences = Build-TcpkImpactSentences -Facts $facts -Templates $templates
                $sentences.Count | Should -Be 2
                $sentences       | Should -Contain '3 cookie(s)'
                $sentences       | Should -Contain 'GCM ok'
                $sentences       | Should -Not -Contain '0 login(s)'
            }
        }
    }

    Context 'Get-TcpkSeverityAudit - raw vs adjusted counts' {

        It 'reports raw HIGH and adjusted MEDIUM separately' {
            InModuleScope TCPK {
                $f = New-TcpkFinding -Module 'test' -RuleId 'cap1.audit' -Severity 'MEDIUM' -Title 'test'
                $f.AdjustmentLog = @('CAP1: cap1.audit HIGH->MEDIUM; no high-tier fact')
                $r = @($f) | Get-TcpkSeverityAudit
                $r.RawCounts['HIGH']    | Should -Be 1
                $r.AdjustedCounts['HIGH']   | Should -Be 0
                $r.AdjustedCounts['MEDIUM'] | Should -Be 1
                $r.Adjustments.Count | Should -BeGreaterThan 0
            }
        }
    }
}

# =============================================================================
Describe 'CAP2: Absence of signal is not absence of condition' {
# =============================================================================

    Context 'module-name detection without alternatives tested' {

        It 'not justified when no alternatives tested; Degradation = severity; log has CAP2' {
            InModuleScope TCPK {
                $r = Get-TcpkNegativeEvidenceStatus -Method 'module-name' -Tested @()
                $r.Justified            | Should -Be $false
                $r.Degradation          | Should -BeIn @('confidence','severity')
                $r.UntestedAlternatives.Count | Should -BeGreaterThan 0
                $r.Explanation          | Should -Match 'CAP2'
            }
        }

        It 'partially justified when one alternative tested; Degradation = confidence' {
            InModuleScope TCPK {
                $r = Get-TcpkNegativeEvidenceStatus -Method 'module-name' -Tested @('binary-header-scan')
                $r.Justified   | Should -Be $false       # not all alternatives tested
                $r.Degradation | Should -Be 'confidence'  # only 1 untested -> confidence, not severity
            }
        }

        It 'justified when ALL alternatives tested; Degradation = none (true positive preserved)' {
            InModuleScope TCPK {
                $r = Get-TcpkNegativeEvidenceStatus -Method 'module-name' `
                    -Tested @('binary-header-scan','resource-string-scan','companion-file-scan')
                $r.Justified   | Should -Be $true
                $r.Degradation | Should -Be 'none'
                $r.Explanation | Should -Match 'CAP2'
                $r.Explanation | Should -Match 'justified'
            }
        }
    }

    Context 'import-table detection' {

        It 'string-match finding of GetProcAddress APIs: not justified without delay-import check' {
            InModuleScope TCPK {
                $r = Get-TcpkNegativeEvidenceStatus -Method 'import-table' -Tested @()
                $r.Justified             | Should -Be $false
                $r.BlindSpots            | Should -Not -BeNullOrEmpty
                $r.BlindSpots[0]         | Should -Match 'GetProcAddress'
            }
        }
    }

    Context 'single-store-trust detection' {

        It 'reading only Root without checking Disallowed: not justified' {
            InModuleScope TCPK {
                $r = Get-TcpkNegativeEvidenceStatus -Method 'single-store-trust' -Tested @()
                $r.Justified             | Should -Be $false
                ($r.BlindSpots | Where-Object { $_ -match 'Disallowed' }).Count | Should -BeGreaterThan 0
            }
        }

        It 'reading Root AND Disallowed AND building chain: justified' {
            InModuleScope TCPK {
                $r = Get-TcpkNegativeEvidenceStatus -Method 'single-store-trust' `
                    -Tested @('check-disallowed-store','chain-build-verification','check-all-scopes')
                $r.Justified   | Should -Be $true
                $r.Degradation | Should -Be 'none'
            }
        }
    }

    Context 'unknown detection method' {

        It 'unknown method: not justified, Degradation = confidence' {
            InModuleScope TCPK {
                $r = Get-TcpkNegativeEvidenceStatus -Method 'xray-vision'
                $r.Justified   | Should -Be $false
                $r.Degradation | Should -Be 'confidence'
                $r.Explanation | Should -Match 'CAP2'
            }
        }
    }
}

# =============================================================================
Describe 'CAP3: Evidence carries provenance; claims are gated on it' {
# =============================================================================

    Context 'New-TcpkEvidenceItem and Assert-TcpkClaimSupported' {

        It 'structural-parse item supports calls claim' {
            InModuleScope TCPK {
                $item = New-TcpkEvidenceItem -Value 'WriteProcessMemory' -Provenance 'structural-parse' -Source 'kernel32 import in testapp.exe'
                $r = Assert-TcpkClaimSupported -Claim 'calls' -Items @($item)
                $r.Supported       | Should -Be $true
                $r.BestProvenance  | Should -Be 'structural-parse'
                $r.Explanation     | Should -Match 'CAP3'
            }
        }

        It 'dynamic observation item supports calls claim' {
            InModuleScope TCPK {
                $item = New-TcpkEvidenceItem -Value 'NtAllocateVirtualMemory' -Provenance 'dynamic' -Source 'Frida trace'
                $r = Assert-TcpkClaimSupported -Claim 'calls' -Items @($item)
                $r.Supported | Should -Be $true
            }
        }

        It 'string-match item does NOT support calls claim (CAP3 false positive guard)' {
            InModuleScope TCPK {
                $item = New-TcpkEvidenceItem -Value 'WriteProcessMemory' -Provenance 'string-match' -Source 'binary scan'
                $r = Assert-TcpkClaimSupported -Claim 'calls' -Items @($item)
                $r.Supported       | Should -Be $false
                $r.MinRequired     | Should -Be 'dynamic'
                $r.Explanation     | Should -Match 'CAP3'
                $r.Explanation     | Should -Match 'downgrade'
            }
        }

        It 'string-match item DOES support references claim' {
            InModuleScope TCPK {
                $item = New-TcpkEvidenceItem -Value 'WriteProcessMemory' -Provenance 'string-match' -Source 'binary scan'
                $r = Assert-TcpkClaimSupported -Claim 'references' -Items @($item)
                $r.Supported | Should -Be $true
            }
        }

        It 'prose-doc item does not support calls or references (true positive gating preserved)' {
            InModuleScope TCPK {
                $item = New-TcpkEvidenceItem -Value 'SetThreadContext' -Provenance 'prose-doc' -Source 'release-notes.txt'
                $callsR = Assert-TcpkClaimSupported -Claim 'calls'      -Items @($item)
                $refR   = Assert-TcpkClaimSupported -Claim 'references' -Items @($item)
                $callsR.Supported | Should -Be $false
                $refR.Supported   | Should -Be $false
                # prose-doc CAN support 'documents' claim
                $docR   = Assert-TcpkClaimSupported -Claim 'documents'  -Items @($item)
                $docR.Supported   | Should -Be $true
            }
        }

        It 'empty item list does not support any claim' {
            InModuleScope TCPK {
                $r = Assert-TcpkClaimSupported -Claim 'exists' -Items @()
                $r.Supported | Should -Be $false
            }
        }
    }

    Context 'Format-TcpkEvidenceItems renders provenance visibly' {

        It 'renders provenance labels in the Evidence string' {
            InModuleScope TCPK {
                $items = @(
                    (New-TcpkEvidenceItem -Value 'WriteProcessMemory' -Provenance 'structural-parse' -Source 'testapp.exe'),
                    (New-TcpkEvidenceItem -Value 'VirtualAllocEx'     -Provenance 'string-match'     -Source 'testapp.exe scan')
                )
                $ev = Format-TcpkEvidenceItems -Items $items
                $ev | Should -Match 'structural-parse'
                $ev | Should -Match 'string-match'
                $ev | Should -Match 'WriteProcessMemory'
                $ev | Should -Match 'VirtualAllocEx'
            }
        }
    }
}

# =============================================================================
Describe 'CAP4: Platform context conditions the claim' {
# =============================================================================

    Context 'Electron platform profile' {

        It 'rwx-for-jit is an expected behavior on Electron (no escalation)' {
            InModuleScope TCPK {
                $p = Get-TcpkRuntimeProfile -RuntimeClass 'electron'
                Test-TcpkPlatformExpects -Profile $p -Behavior 'rwx-for-jit' | Should -Be $true
            }
        }

        It 'cfg cannot be enabled on Electron (platform limitation, not app defect)' {
            InModuleScope TCPK {
                $p = Get-TcpkRuntimeProfile -RuntimeClass 'electron'
                Test-TcpkPlatformCanEnable -Profile $p -Feature 'cfg' | Should -Be $false
            }
        }

        It 'aslr can be enabled on Electron (app CAN fix it)' {
            InModuleScope TCPK {
                $p = Get-TcpkRuntimeProfile -RuntimeClass 'electron'
                Test-TcpkPlatformCanEnable -Profile $p -Feature 'aslr' | Should -Be $true
            }
        }

        It 'Get-TcpkPlatformLimitations returns CFG limitation for Electron' {
            InModuleScope TCPK {
                $p     = Get-TcpkRuntimeProfile -RuntimeClass 'electron'
                $limits = Get-TcpkPlatformLimitations -Profile $p
                ($limits | Where-Object { $_ -match 'cfg' }).Count | Should -BeGreaterThan 0
            }
        }
    }

    Context 'native-win32 platform profile (true positives kept)' {

        It 'rwx-for-jit is NOT expected on native-win32 (RWX is a real finding)' {
            InModuleScope TCPK {
                $p = Get-TcpkRuntimeProfile -RuntimeClass 'native-win32'
                Test-TcpkPlatformExpects -Profile $p -Behavior 'rwx-for-jit' | Should -Be $false
            }
        }

        It 'cfg can be enabled on native-win32' {
            InModuleScope TCPK {
                $p = Get-TcpkRuntimeProfile -RuntimeClass 'native-win32'
                Test-TcpkPlatformCanEnable -Profile $p -Feature 'cfg' | Should -Be $true
            }
        }

        It 'no platform limitations on native-win32' {
            InModuleScope TCPK {
                $p      = Get-TcpkRuntimeProfile -RuntimeClass 'native-win32'
                $limits = Get-TcpkPlatformLimitations -Profile $p
                $limits | Should -BeNullOrEmpty
            }
        }
    }

    Context 'dotnet platform profile' {

        It 'rwx-for-jit is expected on dotnet (CLR JIT)' {
            InModuleScope TCPK {
                $p = Get-TcpkRuntimeProfile -RuntimeClass 'dotnet'
                Test-TcpkPlatformExpects -Profile $p -Behavior 'rwx-for-jit' | Should -Be $true
            }
        }

        It 'cfg can be enabled on dotnet (RyuJIT supports it)' {
            InModuleScope TCPK {
                $p = Get-TcpkRuntimeProfile -RuntimeClass 'dotnet'
                Test-TcpkPlatformCanEnable -Profile $p -Feature 'cfg' | Should -Be $true
            }
        }
    }
}

# =============================================================================
Describe 'CAP5: Preconditions are tested, not assumed' {
# =============================================================================

    Context 'Resolve-TcpkPreconditions - REFUTED suppresses to INFO' {

        It 'REFUTED store-readable: HIGH -> INFO with CAP5 log entry' {
            InModuleScope TCPK {
                $pc = New-TcpkPrecondition -Name 'store-readable' -State 'REFUTED' -Evidence 'file locked; access denied'
                $r = Resolve-TcpkPreconditions -Preconditions @($pc) -Candidate 'HIGH'
                $r.Severity       | Should -Be 'INFO'
                $r.Confidence     | Should -Be 'Inferred'
                $r.WeakestState   | Should -Be 'REFUTED'
                $r.AdjustmentEntry | Should -Match 'CAP5'
                $r.AdjustmentEntry | Should -Match 'HIGH->INFO'
                $r.AdjustmentEntry | Should -Match 'store-readable'
            }
        }

        It 'REFUTED cert-chain: MEDIUM -> INFO' {
            InModuleScope TCPK {
                $pc = New-TcpkPrecondition -Name 'cert-chain-valid' -State 'REFUTED' -Evidence 'X509Chain.Build failed'
                $r = Resolve-TcpkPreconditions -Preconditions @($pc) -Candidate 'MEDIUM'
                $r.Severity   | Should -Be 'INFO'
                $r.Confidence | Should -Be 'Inferred'
            }
        }
    }

    Context 'Resolve-TcpkPreconditions - UNTESTED caps at MEDIUM' {

        It 'UNTESTED store-populated: HIGH -> MEDIUM; confidence -> Inferred' {
            InModuleScope TCPK {
                $pc = New-TcpkPrecondition -Name 'store-populated' -State 'UNTESTED'
                $r = Resolve-TcpkPreconditions -Preconditions @($pc) -Candidate 'HIGH'
                $r.Severity   | Should -Be 'MEDIUM'
                $r.Confidence | Should -Be 'Inferred'
                $r.AdjustmentEntry | Should -Match 'CAP5'
                $r.AdjustmentEntry | Should -Match 'HIGH->MEDIUM'
            }
        }

        It 'UNTESTED does not promote: MEDIUM stays MEDIUM' {
            InModuleScope TCPK {
                $pc = New-TcpkPrecondition -Name 'endpoint-reachable' -State 'UNTESTED'
                $r = Resolve-TcpkPreconditions -Preconditions @($pc) -Candidate 'MEDIUM'
                $r.Severity | Should -Be 'MEDIUM'
            }
        }
    }

    Context 'Resolve-TcpkPreconditions - CONFIRMED preserves true positives' {

        It 'all CONFIRMED: severity and confidence unchanged' {
            InModuleScope TCPK {
                $pcs = @(
                    (New-TcpkPrecondition -Name 'store-readable'  -State 'CONFIRMED' -Evidence 'file opened; 36-byte header read'),
                    (New-TcpkPrecondition -Name 'store-populated' -State 'CONFIRMED' -Evidence 'cookie_row_count=12' -SevCap 'HIGH')
                )
                $r = Resolve-TcpkPreconditions -Preconditions $pcs -Candidate 'HIGH' -CandidateConf 'Confirmed (dynamic)'
                $r.Severity    | Should -Be 'HIGH'
                $r.Confidence  | Should -Be 'Confirmed (dynamic)'
                $r.WeakestState | Should -Be 'CONFIRMED'
                $r.AdjustmentEntry | Should -BeNullOrEmpty
            }
        }

        It 'CONFIRMED with SevCap MEDIUM caps HIGH to MEDIUM (non-CA cert in root store)' {
            InModuleScope TCPK {
                $pc = New-TcpkPrecondition -Name 'is-ca-cert' -State 'CONFIRMED' -Evidence 'CA=False' -SevCap 'MEDIUM'
                $r = Resolve-TcpkPreconditions -Preconditions @($pc) -Candidate 'HIGH'
                $r.Severity        | Should -Be 'MEDIUM'
                $r.AdjustmentEntry | Should -Match 'HIGH->MEDIUM'
            }
        }
    }

    Context 'Resolve-TcpkPreconditions - mixed states; weakest wins' {

        It 'CONFIRMED + REFUTED: weakest wins -> INFO' {
            InModuleScope TCPK {
                $pcs = @(
                    (New-TcpkPrecondition -Name 'store-readable'  -State 'CONFIRMED' -Evidence 'ok'),
                    (New-TcpkPrecondition -Name 'store-populated' -State 'REFUTED'   -Evidence 'row_count=0')
                )
                $r = Resolve-TcpkPreconditions -Preconditions $pcs -Candidate 'HIGH'
                $r.Severity     | Should -Be 'INFO'
                $r.WeakestState | Should -Be 'REFUTED'
            }
        }

        It 'CONFIRMED + UNTESTED: weakest wins -> MEDIUM with Inferred confidence' {
            InModuleScope TCPK {
                $pcs = @(
                    (New-TcpkPrecondition -Name 'store-readable'  -State 'CONFIRMED' -Evidence 'ok'),
                    (New-TcpkPrecondition -Name 'endpoint-live'   -State 'UNTESTED')
                )
                $r = Resolve-TcpkPreconditions -Preconditions $pcs -Candidate 'HIGH'
                $r.Severity    | Should -Be 'MEDIUM'
                $r.Confidence  | Should -Be 'Inferred'
                $r.WeakestState | Should -Be 'UNTESTED'
            }
        }
    }

    Context 'RenderedPreconditions appear in the output' {

        It 'RenderedPreconditions carries state and evidence for each precondition' {
            InModuleScope TCPK {
                $pc = New-TcpkPrecondition -Name 'chain-valid' -State 'REFUTED' -Evidence 'revoked'
                $r = Resolve-TcpkPreconditions -Preconditions @($pc) -Candidate 'HIGH'
                $r.RenderedPreconditions.Count | Should -BeGreaterThan 0
                $r.RenderedPreconditions[0]    | Should -Match 'REFUTED'
                $r.RenderedPreconditions[0]    | Should -Match 'chain-valid'
                $r.RenderedPreconditions[0]    | Should -Match 'revoked'
            }
        }
    }
}

# =============================================================================
Describe 'Cross-cutting: explainability and raw vs adjusted report' {
# =============================================================================

    Context 'Suppression is always logged; silent suppression is forbidden' {

        It 'every CAP1 downgrade appends to AdjustmentLog, not silently drops severity' {
            InModuleScope TCPK {
                $log = [System.Collections.Generic.List[string]]::new()
                Resolve-TcpkImpact -RuleId 'silence.test' -Facts @{} -Candidate 'HIGH' -Log ([ref]$log) | Out-Null
                # Must produce an explanation, not just a changed number
                $log.Count | Should -BeGreaterThan 0
                $log[0]    | Should -Not -BeNullOrEmpty
            }
        }

        It 'CONFIRMED precondition with no downgrade produces empty AdjustmentEntry' {
            InModuleScope TCPK {
                $pc = New-TcpkPrecondition -Name 'x' -State 'CONFIRMED' -Evidence 'ok'
                $r = Resolve-TcpkPreconditions -Preconditions @($pc) -Candidate 'HIGH'
                # No suppression -> entry is empty (not silently present)
                $r.AdjustmentEntry | Should -BeNullOrEmpty
            }
        }
    }
}
