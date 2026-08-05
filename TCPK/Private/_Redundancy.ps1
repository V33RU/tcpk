# Finding redundancy model.
#
# Redundancy is COMPUTABLE, not hardcoded.  Given two findings that share a
# Subject, the classifier derives their relationship from their Dimension and
# ObsValue fields without knowing which rules produced them.
#
# Relationship taxonomy:
#   IDENTICAL   same dimension, equal value [-> emit one; fold the other]
#   CONTAINED   same dimension, one value set is a strict subset of the other
#               [-> emit superset; fold subset; superset inherits subset severity
#               only if subset was higher; never let subset carry the higher sev]
#   REFINED     same dimension and value, different Basis
#               [-> emit the stronger Basis; fold the weaker]
#   DERIVED     same dimension, one value is a count/aggregate of the other set
#               [-> route derived (the count) to context; emit the source set]
#   COMPOSED    one finding's BasisInputs lists the other
#               [-> emit Composed only if it adds an emergent condition; fold if
#               any input is empty/Inferred or the emergent condition is already stated]
#   INDEPENDENT same subject, DIFFERENT dimension, or SDVB fields absent
#               [-> emit both unchanged]
#
# The correlation pass is called once, at report assembly, over the full finding
# set.  Rules emit freely.  -NoCollapse on Invoke-TcpkAudit disables the pass
# so past reports stay reproducible.

# --------------------------------------------------------------------------
# Subject normalization
# --------------------------------------------------------------------------

function Get-TcpkNormalizedSubject {
<#
.SYNOPSIS
    Normalize a Subject string to a canonical form for correlation grouping.

    Canonicalizes Windows paths (lowercase, forward slash, strip trailing slash),
    registry hive abbreviations (HKLM:/HKCU: to HKEY_LOCAL_MACHINE/CURRENT_USER),
    Cert:\ store notation, and process image paths.
#>
    [CmdletBinding()]
    param([string]$Subject)
    if (-not $Subject) { return '' }
    $s = $Subject.Trim()

    # Windows drive path
    if ($s -match '^[a-zA-Z]:[\\/]') {
        return $s.ToLowerInvariant().Replace('\', '/').TrimEnd('/')
    }
    # Registry
    if ($s -match '^HK') {
        $s = $s.ToLowerInvariant()
        $s = $s -replace '^hklm[:\\]', 'hkey_local_machine\'
        $s = $s -replace '^hkcu[:\\]', 'hkey_current_user\'
        $s = $s -replace '^hkey_local_machine\\', 'hkey_local_machine/'
        $s = $s -replace '^hkey_current_user\\', 'hkey_current_user/'
        return $s.Replace('\', '/').TrimEnd('/')
    }
    # Cert:\ store notation
    if ($s -match '^Cert:') {
        return $s.ToLowerInvariant().Replace('\', '/').TrimEnd('/')
    }
    # Process image: normalize to lowercase path only (drop PID)
    if ($s -match '^\[pid:\d+\]\s*(.+)') { $s = $Matches[1].Trim() }
    return $s.ToLowerInvariant().Replace('\', '/').TrimEnd('/')
}

# --------------------------------------------------------------------------
# ObsValue parser
# --------------------------------------------------------------------------

function _TcpkParseObsValue {
    param([string]$raw)
    if (-not $raw) { return [pscustomobject]@{ Kind='empty'; Norm=''; Members=@() } }
    $t = $raw.Trim()
    # JSON array -> set
    if ($t.StartsWith('[')) {
        try {
            $arr = ConvertFrom-Json $t -ErrorAction Stop
            $members = @($arr | ForEach-Object { "$_" } | Sort-Object)
            return [pscustomobject]@{ Kind='set'; Norm=($members -join '|'); Members=$members }
        } catch { }
    }
    # Plain integer -> count
    if ($t -match '^\d+$') {
        return [pscustomobject]@{ Kind='count'; Norm=$t; Members=@() }
    }
    # JSON object -> struct/bitfield
    if ($t.StartsWith('{')) {
        return [pscustomobject]@{ Kind='struct'; Norm=$t; Members=@() }
    }
    # Quoted string or enum
    return [pscustomobject]@{ Kind='scalar'; Norm=$t; Members=@() }
}

function _TcpkIsProperSubset {
    param([string[]]$Candidate, [string[]]$Superset)
    if ($Candidate.Count -eq 0 -or $Candidate.Count -ge $Superset.Count) { return $false }
    $sup = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($x in $Superset) { [void]$sup.Add($x) }
    foreach ($x in $Candidate) { if (-not $sup.Contains($x)) { return $false } }
    return $true
}

# --------------------------------------------------------------------------
# Relationship classifier
# --------------------------------------------------------------------------

function Get-TcpkFindingRelationship {
<#
.SYNOPSIS
    Classify the relationship between two findings that share a Subject.

.DESCRIPTION
    Returns a PSCustomObject with:
      .Relationship  (string)
      .SurvivingIsA  (bool: $true -> A survives; $false -> B survives)
                     Not meaningful for INDEPENDENT or COMPOSED.
      .Explanation   (string) - audit record for every collapse

    Neither finding is mutated; the caller decides what to do.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$A,
        [Parameter(Mandatory)][object]$B
    )

    # SDVB fields required in both findings for any non-INDEPENDENT result
    $sA = Get-TcpkNormalizedSubject "$($A.Subject)"
    $sB = Get-TcpkNormalizedSubject "$($B.Subject)"
    if (-not $sA -or -not $sB -or $sA -ne $sB) {
        return [pscustomobject]@{ Relationship='INDEPENDENT'; SurvivingIsA=$true
            Explanation="subjects differ or are absent: '$($A.Subject)' vs '$($B.Subject)'" }
    }

    $dimA = "$($A.Dimension)".Trim()
    $dimB = "$($B.Dimension)".Trim()
    if (-not $dimA -or -not $dimB -or $dimA -ne $dimB) {
        return [pscustomobject]@{ Relationship='INDEPENDENT'; SurvivingIsA=$true
            Explanation="dimensions differ: '$dimA' vs '$dimB' (same question not asked)" }
    }

    # COMPOSED: one finding's BasisInputs lists the other's RuleId
    $basisA = @($A.BasisInputs); $basisB = @($B.BasisInputs)
    if ($basisB -contains $A.RuleId) {
        # B is Composed-from A -> A is the measured source, B is the derived composer
        return [pscustomobject]@{ Relationship='COMPOSED'; SurvivingIsA=$false
            Explanation="'$($B.RuleId)' is Composed-from '$($A.RuleId)' via BasisInputs" }
    }
    if ($basisA -contains $B.RuleId) {
        return [pscustomobject]@{ Relationship='COMPOSED'; SurvivingIsA=$true
            Explanation="'$($A.RuleId)' is Composed-from '$($B.RuleId)' via BasisInputs" }
    }

    $valA = _TcpkParseObsValue "$($A.ObsValue)"
    $valB = _TcpkParseObsValue "$($B.ObsValue)"

    # Same value
    if ($valA.Norm -eq $valB.Norm -and $valA.Kind -eq $valB.Kind) {
        $bA = "$($A.Basis)"; $bB = "$($B.Basis)"
        if ($bA -ne $bB -and $bA -and $bB) {
            # REFINED: same observation, different proof depth
            $rank = @{ Measured=3; 'Confirmed (dynamic)'=3; Inferred=1; Composed=2 }
            $rA = if ($rank.ContainsKey($bA)) { $rank[$bA] } else { 1 }
            $rB = if ($rank.ContainsKey($bB)) { $rank[$bB] } else { 1 }
            $survA = ($rA -ge $rB)
            return [pscustomobject]@{ Relationship='REFINED'; SurvivingIsA=$survA
                Explanation="same dimension/value; basis '$bA'(A) vs '$bB'(B); keeping stronger '$( if($survA){$bA}else{$bB})'" }
        }
        return [pscustomobject]@{ Relationship='IDENTICAL'; SurvivingIsA=$true
            Explanation="same dimension, same value, same basis; folding '$($B.RuleId)' into '$($A.RuleId)'" }
    }

    # Set containment
    if ($valA.Kind -eq 'set' -and $valB.Kind -eq 'set') {
        if (_TcpkIsProperSubset -Candidate $valA.Members -Superset $valB.Members) {
            # A is subset of B -> B is the superset, survives
            return [pscustomobject]@{ Relationship='CONTAINED'; SurvivingIsA=$false
                Explanation="'$($A.RuleId)' set ($($valA.Members.Count)) is proper subset of '$($B.RuleId)' set ($($valB.Members.Count)); superset '$($B.RuleId)' survives" }
        }
        if (_TcpkIsProperSubset -Candidate $valB.Members -Superset $valA.Members) {
            return [pscustomobject]@{ Relationship='CONTAINED'; SurvivingIsA=$true
                Explanation="'$($B.RuleId)' set ($($valB.Members.Count)) is proper subset of '$($A.RuleId)' set ($($valA.Members.Count)); superset '$($A.RuleId)' survives" }
        }
    }

    # DERIVED: one is a count whose value equals the cardinality of the other's set
    if ($valA.Kind -eq 'count' -and $valB.Kind -eq 'set' -and [int]$valA.Norm -eq $valB.Members.Count) {
        return [pscustomobject]@{ Relationship='DERIVED'; SurvivingIsA=$false
            Explanation="'$($A.RuleId)' count=$($valA.Norm) is an aggregate of '$($B.RuleId)' set ($($valB.Members.Count) members); count is context, set is the finding" }
    }
    if ($valB.Kind -eq 'count' -and $valA.Kind -eq 'set' -and [int]$valB.Norm -eq $valA.Members.Count) {
        return [pscustomobject]@{ Relationship='DERIVED'; SurvivingIsA=$true
            Explanation="'$($B.RuleId)' count=$($valB.Norm) is an aggregate of '$($A.RuleId)' set ($($valA.Members.Count) members); count is context, set is the finding" }
    }

    return [pscustomobject]@{ Relationship='INDEPENDENT'; SurvivingIsA=$true
        Explanation="same subject and dimension but different values: $(if($valA.Kind -eq 'set'){"$($valA.Members.Count) vs $($valB.Members.Count) members"}else{"'$($valA.Norm)' vs '$($valB.Norm)'"})" }
}

# --------------------------------------------------------------------------
# Correlation pass
# --------------------------------------------------------------------------

function Invoke-TcpkRedundancyCorrelation {
<#
.SYNOPSIS
    Correlation pass: run once over the full finding set at report assembly.

.DESCRIPTION
    Groups findings by normalized Subject, then classifies every pair within
    each group.  Returns the collapsed finding set.  Every fold is recorded in
    the surviving finding's AdjustmentLog.

    Findings without Subject or Dimension fields are treated as INDEPENDENT
    by construction and pass through unchanged.

    Use -NoCollapse to skip the pass entirely (for reproducible past reports).

.OUTPUTS
    [TcpkFinding] collapsed finding stream
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)][object[]]$Findings,
        [switch]$NoCollapse
    )
    begin { $buf = [System.Collections.Generic.List[object]]::new() }
    process { foreach ($f in $Findings) { if ($f) { $buf.Add($f) } } }
    end {
        if ($NoCollapse -or $buf.Count -le 1) {
            foreach ($f in $buf) { $f }
            return
        }

        $all = $buf.ToArray()
        # foldedIdx[i] = @{ SurvivorIdx=j; Relationship; Explanation }
        $foldedIdx = @{}

        # Group indices by normalized subject
        $groups = [ordered]@{}
        for ($k = 0; $k -lt $all.Count; $k++) {
            $subj = Get-TcpkNormalizedSubject "$($all[$k].Subject)"
            if (-not $subj) { continue }   # no subject -> not correlated
            if (-not $groups.ContainsKey($subj)) { $groups[$subj] = [System.Collections.Generic.List[int]]::new() }
            $groups[$subj].Add($k)
        }

        foreach ($grpEntry in $groups.GetEnumerator()) {
            $idxList = @($grpEntry.Value)
            if ($idxList.Count -le 1) { continue }

            for ($i = 0; $i -lt $idxList.Count; $i++) {
                for ($j = $i + 1; $j -lt $idxList.Count; $j++) {
                    $idxA = $idxList[$i]; $idxB = $idxList[$j]
                    if ($foldedIdx.ContainsKey($idxA) -or $foldedIdx.ContainsKey($idxB)) { continue }

                    $rel = Get-TcpkFindingRelationship -A $all[$idxA] -B $all[$idxB]
                    $relationship = $rel.Relationship

                    if ($relationship -eq 'INDEPENDENT') { continue }

                    switch ($relationship) {
                        'IDENTICAL' {
                            $foldedIdx[$idxB] = @{ SurvivorIdx=$idxA; Relationship='IDENTICAL'; Explanation=$rel.Explanation }
                        }
                        'CONTAINED' {
                            # SurvivingIsA: $true -> A survives, fold B; $false -> B survives, fold A
                            if ($rel.SurvivingIsA) {
                                $foldedIdx[$idxB] = @{ SurvivorIdx=$idxA; Relationship='CONTAINED'; Explanation=$rel.Explanation }
                            } else {
                                $foldedIdx[$idxA] = @{ SurvivorIdx=$idxB; Relationship='CONTAINED'; Explanation=$rel.Explanation }
                            }
                        }
                        'REFINED' {
                            if ($rel.SurvivingIsA) {
                                $foldedIdx[$idxB] = @{ SurvivorIdx=$idxA; Relationship='REFINED'; Explanation=$rel.Explanation }
                            } else {
                                $foldedIdx[$idxA] = @{ SurvivorIdx=$idxB; Relationship='REFINED'; Explanation=$rel.Explanation }
                            }
                        }
                        'DERIVED' {
                            # SurvivingIsA: $true -> A is the set (source), fold B (the count)
                            if ($rel.SurvivingIsA) {
                                $foldedIdx[$idxB] = @{ SurvivorIdx=$idxA; Relationship='DERIVED'; Explanation=$rel.Explanation }
                            } else {
                                $foldedIdx[$idxA] = @{ SurvivorIdx=$idxB; Relationship='DERIVED'; Explanation=$rel.Explanation }
                            }
                        }
                        'COMPOSED' {
                            # Composer survives only if it adds an emergent condition AND all
                            # inputs are Measured.  If any input is Inferred or measures empty,
                            # suppress the Composed finding and say why.
                            $composerIdx = if ($rel.SurvivingIsA) { $idxA } else { $idxB }
                            $sourceIdx   = if ($rel.SurvivingIsA) { $idxB } else { $idxA }
                            $composer    = $all[$composerIdx]
                            $source      = $all[$sourceIdx]
                            $srcBasis    = "$($source.Basis)"
                            if ($srcBasis -eq 'Inferred' -or "$($source.ObsValue)" -match '^0?$') {
                                $reason = if ($srcBasis -eq 'Inferred') {
                                    "input '$($source.RuleId)' is Inferred; Composed finding may not exceed weakest input"
                                } else {
                                    "input '$($source.RuleId)' measures empty (ObsValue='$($source.ObsValue)')"
                                }
                                $foldedIdx[$composerIdx] = @{ SurvivorIdx=$sourceIdx; Relationship='COMPOSED'; Explanation="Composed suppressed: $reason" }
                            }
                            # Otherwise both survive (Composed adds emergent value)
                        }
                    }
                }
            }
        }

        # Chase transitive folds to the ultimate survivor
        function _ChaseToUltimate {
            param([int]$idx)
            $visited = [System.Collections.Generic.HashSet[int]]::new()
            $cur = $idx
            while ($foldedIdx.ContainsKey($cur) -and $visited.Add($cur)) {
                $cur = $foldedIdx[$cur].SurvivorIdx
            }
            return $cur
        }

        # Emit survivors, record fold in AdjustmentLog
        for ($k = 0; $k -lt $all.Count; $k++) {
            if ($foldedIdx.ContainsKey($k)) {
                $rec         = $foldedIdx[$k]
                $ultimateIdx = _ChaseToUltimate $k
                $survivor    = $all[$ultimateIdx]
                $entry = "REDUNDANCY: '$($all[$k].RuleId)' ($($rec.Relationship)) folded into '$($survivor.RuleId)'; $($rec.Explanation)"
                if ($survivor.AdjustmentLog -isnot [System.Collections.Generic.List[string]]) {
                    $newLog = [System.Collections.Generic.List[string]]::new()
                    if ($survivor.AdjustmentLog) { foreach ($e in $survivor.AdjustmentLog) { $newLog.Add($e) } }
                    $survivor.AdjustmentLog = $newLog.ToArray()
                }
                $survivor.AdjustmentLog = @($survivor.AdjustmentLog) + @($entry)
            } else {
                $all[$k]
            }
        }
    }
}

# --------------------------------------------------------------------------
# Observation counts (raw vs distinct)
# --------------------------------------------------------------------------

function Get-TcpkObservationCounts {
<#
.SYNOPSIS
    Report raw vs distinct (post-correlation) severity counts.

.DESCRIPTION
    Takes two finding arrays (raw = all findings before correlation; distinct =
    after Invoke-TcpkRedundancyCorrelation) and returns a comparison object.
    Reports both so the reader sees the reduction the correlation pass applied.

.OUTPUTS
    [PSCustomObject] with RawCounts, DistinctCounts, RawTotal, DistinctTotal,
    Folded (int), and a per-relationship breakdown of what was collapsed.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Raw,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Distinct
    )

    $sevLevels = @('INFO','LOW','MEDIUM','HIGH','CRITICAL')
    $rawC = @{}; $distC = @{}
    foreach ($s in $sevLevels) { $rawC[$s] = 0; $distC[$s] = 0 }
    foreach ($f in $Raw)      { if ($f.Severity) { $rawC["$($f.Severity)"]++ } }
    foreach ($f in $Distinct) { if ($f.Severity) { $distC["$($f.Severity)"]++ } }

    # Parse AdjustmentLog of survivors to build relationship breakdown
    $relCounts = @{ IDENTICAL=0; CONTAINED=0; REFINED=0; DERIVED=0; COMPOSED=0 }
    foreach ($f in $Distinct) {
        foreach ($entry in @($f.AdjustmentLog)) {
            if ($entry -match 'REDUNDANCY:.*\((\w+)\)') {
                $rel = $Matches[1]
                if ($relCounts.ContainsKey($rel)) { $relCounts[$rel]++ }
            }
        }
    }

    return [pscustomobject]@{
        RawTotal       = $Raw.Count
        DistinctTotal  = $Distinct.Count
        Folded         = $Raw.Count - $Distinct.Count
        RawCounts      = $rawC
        DistinctCounts = $distC
        RelationshipBreakdown = $relCounts
    }
}
