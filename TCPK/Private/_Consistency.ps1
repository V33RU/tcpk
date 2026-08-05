# CAP7 - Internal consistency enforcement.
#
# Rules run independently, so the report can assert mutually exclusive things
# about one subject.  A reader cannot tell which is true, and both may be wrong.
#
# At report assembly, detect contradiction: two findings about the same SUBJECT
# whose claims cannot both hold.  On contradiction, prefer the finding with the
# stronger Basis (CAP3) and suppress the weaker.  Record the conflict and its
# resolution in the surviving finding's AdjustmentLog.
#
# Constraints are DERIVED from the platform profile (CAP4), not hardcoded as
# rule pairs.  Adding a new runtime automatically extends the consistency check
# to every rule that measures features that runtime cannot enable.
#
# Static registry: cross-dimension logical implications that do not depend on
# which platform the target runs on (e.g. encryption-state governs dpapi-exposure
# regardless of runtime class).
#
# Dynamic derivation: Get-TcpkPlatformConstraints reads CanEnable and
# ExpectedBehaviors from Get-TcpkRuntimeProfile (CAP4) to produce constraints
# for features a platform structurally cannot provide.

$script:TcpkStaticConstraints = @(
    # When measured store-encryption-state is disabled/false, any finding that
    # asserts DPAPI-encrypted credential exposure is internally inconsistent.
    # The data is plaintext; the claim of encryption-dependent impact is wrong.
    @{
        Name             = 'store-encryption-disabled-contradicts-dpapi-exposure'
        GoverningDim     = 'store-encryption-state'
        GoverningPattern = '^(disabled|false|off|0|no)$'
        NegatesDim       = 'dpapi-credential-exposure'
        NegatesPattern   = '.*'
        Reason           = 'Store encryption is disabled; a finding claiming DPAPI-encrypted exposure is inconsistent -- the data is plaintext, not encrypted'
    }
    # Two rules measuring signature-status disagree on the same binary.
    # "valid" and "unsigned/invalid" cannot both be true.
    @{
        Name             = 'valid-signature-contradicts-unsigned-claim'
        GoverningDim     = 'signature-status'
        GoverningPattern = '^(valid|signed|trusted)$'
        NegatesDim       = 'signature-status'
        NegatesPattern   = '^(unsigned|invalid|untrusted|missing|absent)$'
        Reason           = 'Two rules disagree on signature status for the same subject; the measured-valid verdict takes precedence'
    }
    # A finding that reports key-encryption-mode=none contradicts any finding that
    # assumes the key is encrypted (e.g. a finding whose impact is key-recovery-via-decryption).
    @{
        Name             = 'key-unencrypted-contradicts-decryption-impact'
        GoverningDim     = 'key-encryption-mode'
        GoverningPattern = '^(none|plaintext|unencrypted)$'
        NegatesDim       = 'key-exposure-requires-decryption'
        NegatesPattern   = '.*'
        Reason           = 'Key is stored unencrypted; a finding whose impact assumes a decryption step must be rewritten to reflect direct plaintext access'
    }
)

# --------------------------------------------------------------------------
# Dynamic constraint derivation from CAP4 platform profile
# --------------------------------------------------------------------------

function Get-TcpkPlatformConstraints {
<#
.SYNOPSIS
    Derive consistency constraints from the CAP4 platform profile.

.DESCRIPTION
    For each feature in CanEnable that is $false, emit a constraint that
    suppresses any finding claiming that feature is "missing" or "disabled"
    (absence is platform-expected, not a misconfiguration).

    For each ExpectedBehavior, emit a constraint that suppresses findings
    that treat that behavior as an anomaly.

    These constraints are DERIVED, not hardcoded.  Adding a new platform
    class in _RuntimeProfile.ps1 automatically extends the consistency check.
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$PlatformClass)

    if (-not $PlatformClass -or $PlatformClass -eq 'unknown') { return @() }
    $profile = $null
    try { $profile = Get-TcpkRuntimeProfile -RuntimeClass $PlatformClass } catch { return @() }
    if (-not $profile) { return @() }

    $constraints = [System.Collections.Generic.List[object]]::new()

    # CanEnable[$feature] = $false -> absence of $feature is structurally unavoidable
    foreach ($feature in @($profile.CanEnable.Keys)) {
        if ($profile.CanEnable[$feature] -eq $false) {
            $constraints.Add(@{
                Name             = "platform-$PlatformClass-cannot-enable-$feature"
                GoverningDim     = 'platform-class'
                GoverningPattern = [regex]::Escape($PlatformClass)
                NegatesDim       = "$feature-mitigation"
                NegatesPattern   = 'missing|disabled|absent|not-enabled|no|false'
                Reason           = "Platform '$PlatformClass' structurally cannot enable '$feature'; the finding is a platform limitation, not a remediable misconfiguration"
            })
        }
    }

    # ExpectedBehaviors -> findings that flag these as anomalies are inconsistent
    foreach ($behavior in @($profile.ExpectedBehaviors)) {
        switch ($behavior) {
            'rwx-for-jit' {
                $constraints.Add(@{
                    Name             = "platform-$PlatformClass-expected-rwx"
                    GoverningDim     = 'platform-class'
                    GoverningPattern = [regex]::Escape($PlatformClass)
                    NegatesDim       = 'memory-protection'
                    NegatesPattern   = 'rwx|wx|executable-and-writable|noexec-violation'
                    Reason           = "RWX memory is expected for JIT runtime '$PlatformClass'; flagging it as an anomaly is internally inconsistent"
                })
            }
            'dynamic-code-gen' {
                $constraints.Add(@{
                    Name             = "platform-$PlatformClass-expected-dynamic-code"
                    GoverningDim     = 'platform-class'
                    GoverningPattern = [regex]::Escape($PlatformClass)
                    NegatesDim       = 'code-integrity'
                    NegatesPattern   = 'dynamic-code-violation|acg-bypass|arbitrary-code-guard'
                    Reason           = "Dynamic code generation is structurally expected for '$PlatformClass'; ACG violations are platform-expected"
                })
            }
            'v8-snapshot-exec' {
                $constraints.Add(@{
                    Name             = "platform-$PlatformClass-expected-snapshot-exec"
                    GoverningDim     = 'platform-class'
                    GoverningPattern = [regex]::Escape($PlatformClass)
                    NegatesDim       = 'executable-data-file'
                    NegatesPattern   = 'v8.*snapshot|context_snapshot'
                    Reason           = "Electron's v8_context_snapshot.bin is a mapped executable heap image; this is structurally expected"
                })
            }
        }
    }

    return @($constraints)
}

# --------------------------------------------------------------------------
# Consistency pass
# --------------------------------------------------------------------------

function Invoke-TcpkConsistencyCheck {
<#
.SYNOPSIS
    CAP7 - Suppress contradictory findings at report assembly.

.DESCRIPTION
    Groups findings by normalized Subject (Get-TcpkNormalizedSubject).  For
    each group, determines the platform class (from a 'platform-class' dimension
    finding in the group, else from _Resolve-TcpkRuntimeClass via the Subject
    path).  Applies static constraints plus platform-derived constraints.

    For each constraint, identifies the GOVERNING finding (the one whose
    Dimension/ObsValue declares a fact that makes another finding logically
    impossible) and any NEGATED findings (findings that assume the impossible
    state).  The finding with the stronger Basis (CAP3) survives; the weaker
    is suppressed with a CAP7: entry in the survivor's AdjustmentLog.

    Findings without Subject pass through unchanged.

.PARAMETER Findings
    Pipeline of [TcpkFinding] objects.

.OUTPUTS
    [TcpkFinding] stream with contradictions resolved.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)][object[]]$Findings
    )
    begin { $buf = [System.Collections.Generic.List[object]]::new() }
    process { foreach ($f in $Findings) { if ($f) { $buf.Add($f) } } }
    end {
        if ($buf.Count -le 1) { foreach ($f in $buf) { $f }; return }

        $all = $buf.ToArray()
        $suppressedIdx = @{}

        # Basis strength rank (higher = stronger = wins)
        $basisRank = @{
            'Measured'              = 4
            'Confirmed (dynamic)'   = 4
            'Confirmed (IL)'        = 4
            'Composed'              = 2
            'Inferred'              = 1
            ''                      = 0
        }

        # Group indices by normalized Subject
        $groups = [ordered]@{}
        for ($k = 0; $k -lt $all.Count; $k++) {
            $subj = Get-TcpkNormalizedSubject "$($all[$k].Subject)"
            if (-not $subj) { continue }
            if (-not $groups.ContainsKey($subj)) { $groups[$subj] = [System.Collections.Generic.List[int]]::new() }
            $groups[$subj].Add($k)
        }

        $platformCache = @{}

        foreach ($grpEntry in $groups.GetEnumerator()) {
            $idxList = @($grpEntry.Value)
            if ($idxList.Count -le 1) { continue }
            $subjKey = $grpEntry.Key

            # Resolve platform class for this subject group (cached)
            if (-not $platformCache.ContainsKey($subjKey)) {
                $pc = 'unknown'
                # 1) Look for an explicit platform-class dimension finding in this group
                foreach ($i in $idxList) {
                    if ("$($all[$i].Dimension)" -eq 'platform-class') {
                        $pc = "$($all[$i].ObsValue)".Trim('"').Trim()
                        break
                    }
                }
                # 2) Fall back to probing the path (works on the scan machine)
                if ($pc -eq 'unknown' -and $subjKey -match '^[a-z]:/') {
                    try { $pc = _Resolve-TcpkRuntimeClass -Path $subjKey } catch { }
                }
                $platformCache[$subjKey] = $pc
            }
            $platformClass = $platformCache[$subjKey]

            # Combine static + dynamic constraints
            $constraints = @($script:TcpkStaticConstraints) + @(Get-TcpkPlatformConstraints -PlatformClass $platformClass)

            foreach ($constraint in $constraints) {
                # Find governing findings in this group
                $governing = @($idxList | Where-Object {
                    $f = $all[$_]
                    "$($f.Dimension)" -eq $constraint.GoverningDim -and
                    "$($f.ObsValue)"  -match $constraint.GoverningPattern
                })
                if (-not $governing) { continue }

                # Find negated findings in this group
                $negated = @($idxList | Where-Object {
                    $idx = $_
                    $f   = $all[$idx]
                    "$($f.Dimension)" -eq $constraint.NegatesDim -and
                    "$($f.ObsValue)"  -match $constraint.NegatesPattern -and
                    $idx -notin $governing
                })
                if (-not $negated) { continue }

                foreach ($govIdx in $governing) {
                    if ($suppressedIdx.ContainsKey($govIdx)) { continue }
                    $govBasis = "$($all[$govIdx].Basis)"
                    $govRank  = if ($basisRank.ContainsKey($govBasis)) { $basisRank[$govBasis] } else { 1 }

                    foreach ($negIdx in $negated) {
                        if ($suppressedIdx.ContainsKey($negIdx)) { continue }
                        $negBasis = "$($all[$negIdx].Basis)"
                        $negRank  = if ($basisRank.ContainsKey($negBasis)) { $basisRank[$negBasis] } else { 1 }

                        if ($negRank -gt $govRank) {
                            # Negated has STRONGER basis: governing claim is the one that is wrong.
                            # Suppress the governing; the negated finding survives.
                            $entry = "CAP7: CONFLICT -- governing '($($all[$govIdx].RuleId)|$($all[$govIdx].Dimension)=$($all[$govIdx].ObsValue))' suppressed; negated finding '($($all[$negIdx].RuleId))' has stronger basis ($negBasis > $govBasis); constraint: $($constraint.Name)"
                            $suppressedIdx[$govIdx] = @{ WinnerIdx=$negIdx; Entry=$entry; Constraint=$constraint.Name }
                            $all[$negIdx].AdjustmentLog = @($all[$negIdx].AdjustmentLog) + @($entry)
                        } else {
                            # Governing has EQUAL OR STRONGER basis: negated finding is impossible.
                            $entry = "CAP7: CONFLICT -- '($($all[$negIdx].RuleId)|$($all[$negIdx].Dimension)=$($all[$negIdx].ObsValue))' suppressed by governing '($($all[$govIdx].RuleId)|$($all[$govIdx].Dimension)=$($all[$govIdx].ObsValue))' ($govBasis); $($constraint.Reason)"
                            $suppressedIdx[$negIdx] = @{ WinnerIdx=$govIdx; Entry=$entry; Constraint=$constraint.Name }
                            $all[$govIdx].AdjustmentLog = @($all[$govIdx].AdjustmentLog) + @($entry)
                        }
                    }
                }
            }
        }

        for ($k = 0; $k -lt $all.Count; $k++) {
            if (-not $suppressedIdx.ContainsKey($k)) { $all[$k] }
        }
    }
}

function Get-TcpkConsistencyContraints {
<#
.SYNOPSIS
    Return the static constraint registry (for tests and reporting).
#>
    $script:TcpkStaticConstraints
}
