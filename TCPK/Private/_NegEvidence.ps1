# CAP2 - Negative evidence justification.
#
# A rule that escalates severity BECAUSE something was not found must prove
# its detection method could have seen it.  Any method has known blind spots;
# if the alternatives that would catch them were not tested, the negative
# conclusion degrades to 'confidence' or 'severity' rather than supporting HIGH.
#
# Usage:
#   $neg = Get-TcpkNegativeEvidenceStatus -Method 'module-name' -Tested @('binary-header-scan')
#   if (-not $neg.Justified) { $candidate = 'MEDIUM'; $log += "CAP2: $($neg.Explanation)" }

# The blind-spot registry.  Each entry names a detection method, the gaps that
# make "not found" unreliable, and the alternatives a rule should test.
# Extend this table as new detection methods are added; do not add entries per rule.
$script:TcpkNegEvidenceRegistry = [ordered]@{
    # Runtime detected by comparing LOADED MODULE NAMES against a known list.
    'module-name' = @{
        BlindSpots = @(
            'statically linked into the main image (no separate DLL on disk)',
            'binary renamed or repackaged',
            'single-file self-contained bundle (e.g. dotnet publish or PyInstaller)',
            'loaded from a path outside the module scan root'
        )
        KnownAlternatives = @('binary-header-scan', 'resource-string-scan', 'companion-file-scan')
    }

    # Capability detected by reading the PE IMPORT TABLE (IMAGE_IMPORT_DESCRIPTOR).
    'import-table' = @{
        BlindSpots = @(
            'GetProcAddress / LoadLibrary resolution (common for sandboxing and hook APIs)',
            'delay-load import table scanned separately (IMAGE_DELAY_IMPORT_DESCRIPTOR)',
            'JIT-emitted thunk not present as a static import',
            'COM / RPC interface not represented in the PE import directory'
        )
        KnownAlternatives = @('delay-import-table', 'string-match', 'dynamic-observation')
    }

    # Trust decision read from ONE certificate store.
    'single-store-trust' = @{
        BlindSpots = @(
            'Disallowed store overrides Root: cert present in both may still be revoked',
            'per-user vs per-machine discrepancy: CurrentUser store differs from LocalMachine',
            'group policy may have modified effective trust since the store was last enumerated'
        )
        KnownAlternatives = @('check-disallowed-store', 'chain-build-verification', 'check-all-scopes')
    }

    # Finding based on a string / regex scan of binary or text content.
    'string-scan' = @{
        BlindSpots = @(
            'string constructed at runtime via concatenation or format strings',
            'obfuscated, encrypted, or Base64-encoded value',
            'string exists only in a bundled third-party or non-first-party file'
        )
        KnownAlternatives = @('import-table', 'dynamic-observation')
    }

    # Process list / loaded module list queried once at scan time.
    'process-snapshot' = @{
        BlindSpots = @(
            'process not running at snapshot time (on-demand service, transient process)',
            'process running under a different user session or privilege level',
            'injected or hollowed process may hide the real image name'
        )
        KnownAlternatives = @('file-system-scan', 'registry-scan', 'wmi-query')
    }
}

function Get-TcpkNegativeEvidenceStatus {
<#
.SYNOPSIS
    CAP2 - Assess whether a "not found" conclusion is justified given the detection method.

.PARAMETER Method
    The detection method used.  Must be a key in the blind-spot registry
    (module-name, import-table, single-store-trust, string-scan, process-snapshot).
    Unknown methods are treated as unjustified by default.

.PARAMETER Tested
    The alternatives the rule already tested (from KnownAlternatives for this method).
    When all known alternatives are in this list the conclusion is justified.

.OUTPUTS
    [PSCustomObject] with:
      Justified            - $true when all alternatives were tested
      BlindSpots           - the model's known gaps for this method
      UntestedAlternatives - KnownAlternatives minus Tested
      Degradation          - 'none' | 'confidence' | 'severity'
      Explanation          - one-sentence audit string to append to AdjustmentLog
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Method,
        [string[]]$Tested = @()
    )

    $entry = $script:TcpkNegEvidenceRegistry[$Method]
    if (-not $entry) {
        return [pscustomobject]@{
            Justified            = $false
            BlindSpots           = @("no blind-spot model for detection method '$Method'")
            UntestedAlternatives = @()
            Degradation          = 'confidence'
            Explanation          = "CAP2: unknown detection method '$Method'; negative conclusion unverified; confidence degraded"
        }
    }

    $blindSpots    = $entry.BlindSpots
    $untestedAlts  = @($entry.KnownAlternatives | Where-Object { $Tested -notcontains $_ })
    $justified     = ($untestedAlts.Count -eq 0)

    $degradation = switch ($true) {
        $justified                   { 'none'       }
        ($untestedAlts.Count -le 1)  { 'confidence' }
        default                      { 'severity'   }
    }

    $expl = if ($justified) {
        "CAP2: all alternatives for '$Method' tested ($($Tested -join ', ')); negative conclusion justified"
    } else {
        "CAP2: '$Method' has $($blindSpots.Count) blind spot(s); untested alternatives: $($untestedAlts -join ', '); confidence degraded"
    }

    return [pscustomobject]@{
        Justified            = $justified
        BlindSpots           = $blindSpots
        UntestedAlternatives = $untestedAlts
        Degradation          = $degradation
        Explanation          = $expl
    }
}
