# CAP5 - Precondition state machine.
#
# Many findings are only exploitable if some condition holds: the artifact is
# readable, a certificate chain validates, an endpoint is reachable, a store is
# populated.  Rules currently assume these conditions and embed the assumption in
# prose.  This module encodes them as tested fields with three states:
#
#   CONFIRMED - the rule verified the condition is true
#   REFUTED   - the rule verified the condition is false  (caps severity at INFO)
#   UNTESTED  - the rule did not check                    (caps severity at MEDIUM,
#               forces confidence to Inferred)
#
# Severity cap table (weakest state wins when multiple preconditions exist):
#   CONFIRMED  ->  no additional cap (rule's own SevCap applies)
#   UNTESTED   ->  max MEDIUM, confidence Inferred
#   REFUTED    ->  max INFO,   confidence Inferred
#
# Usage:
#   $pc = @(
#       New-TcpkPrecondition -Name 'store-readable' -State 'CONFIRMED' -Evidence 'opened ok'
#       New-TcpkPrecondition -Name 'store-populated' -State 'REFUTED'   -Evidence 'cookie_row_count=0'
#   )
#   $r = Resolve-TcpkPreconditions -Preconditions $pc -Candidate 'HIGH'
#   # $r.Severity  -> 'INFO'
#   # Append $r.AdjustmentEntry to finding.AdjustmentLog
#   # Append $r.RenderedPreconditions to finding.Preconditions

$script:TcpkPreconditionStateCap = @{
    'CONFIRMED' = @{ SevRank = 99; ConfidenceCap = $null }
    'UNTESTED'  = @{ SevRank = 2;  ConfidenceCap = 'Inferred' }   # rank 2 = MEDIUM
    'REFUTED'   = @{ SevRank = 0;  ConfidenceCap = 'Inferred' }   # rank 0 = INFO
}

$script:TcpkSeverityRankPc = @{ INFO=0; LOW=1; MEDIUM=2; HIGH=3; CRITICAL=4 }
$script:TcpkRankSeverityPc = @{ 0='INFO'; 1='LOW'; 2='MEDIUM'; 3='HIGH'; 4='CRITICAL' }

function New-TcpkPrecondition {
<#
.SYNOPSIS
    CAP5 - Create a precondition record with a tested state.

.PARAMETER Name
    Short label for this precondition (e.g. 'store-readable', 'chain-valid').

.PARAMETER State
    CONFIRMED - condition is verified true.
    REFUTED   - condition is verified false; the impact cannot materialise.
    UNTESTED  - the rule did not check; severity is capped at MEDIUM.

.PARAMETER Evidence
    What was observed or why the state was determined.

.PARAMETER SevCap
    Maximum severity this precondition allows when CONFIRMED (default HIGH).
    Use this when a confirmed precondition still limits the maximum claim
    (e.g. a chain that built but the cert is not a CA -> MEDIUM at most).
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][ValidateSet('CONFIRMED','REFUTED','UNTESTED')][string]$State,
        [string]$Evidence = '',
        [ValidateSet('CRITICAL','HIGH','MEDIUM','LOW','INFO')][string]$SevCap = 'HIGH'
    )
    return [pscustomobject]@{
        Name      = $Name
        State     = $State
        Evidence  = $Evidence
        SevCap    = $SevCap
    }
}

function Resolve-TcpkPreconditions {
<#
.SYNOPSIS
    CAP5 - Compute the effective severity and confidence from a set of preconditions.

.DESCRIPTION
    Walks every precondition and finds the weakest state (REFUTED wins over
    UNTESTED wins over CONFIRMED).  The final severity is the minimum of:
      - $Candidate
      - the state-based cap of the weakest precondition
      - the SevCap of every CONFIRMED precondition

    Returns a result object whose fields are ready to merge into a TcpkFinding.

.OUTPUTS
    [PSCustomObject] with Severity, Confidence, WeakestState, AdjustmentEntry,
    RenderedPreconditions
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Preconditions,
        [Parameter(Mandatory)]
        [ValidateSet('CRITICAL','HIGH','MEDIUM','LOW','INFO')][string]$Candidate,
        [string]$CandidateConf = 'Confirmed'
    )

    if (-not $Preconditions) {
        return [pscustomobject]@{
            Severity             = $Candidate
            Confidence           = $CandidateConf
            WeakestState         = 'CONFIRMED'
            AdjustmentEntry      = ''
            RenderedPreconditions = @()
        }
    }

    $stateOrder   = @{ CONFIRMED=2; UNTESTED=1; REFUTED=0 }
    $worstOrder   = 2
    $worstPc      = $null
    $effectiveRank = $script:TcpkSeverityRankPc[$Candidate]
    $effectiveConf = $CandidateConf

    $rendered = [System.Collections.Generic.List[string]]::new()

    foreach ($pc in $Preconditions) {
        if (-not $pc) { continue }
        $order = $stateOrder["$($pc.State)"]
        if ($order -lt $worstOrder) {
            $worstOrder = $order
            $worstPc    = $pc
        }
        # Apply CONFIRMED SevCap
        if ($pc.State -eq 'CONFIRMED') {
            $capRank = $script:TcpkSeverityRankPc[$pc.SevCap]
            if ($capRank -lt $effectiveRank) { $effectiveRank = $capRank }
        }
        $rendered.Add("$($pc.State) $($pc.Name): $($pc.Evidence)")
    }

    # Apply weakest-state cap
    $worstState = if ($worstPc) { "$($worstPc.State)" } else { 'CONFIRMED' }
    if ($worstState -ne 'CONFIRMED') {
        $stCap = $script:TcpkPreconditionStateCap[$worstState]
        if ($stCap.SevRank -lt $effectiveRank) { $effectiveRank = $stCap.SevRank }
        if ($stCap.ConfidenceCap) { $effectiveConf = $stCap.ConfidenceCap }
    }

    $finalSev = $script:TcpkRankSeverityPc[$effectiveRank]
    $adjEntry = ''
    if ($finalSev -ne $Candidate -or $effectiveConf -ne $CandidateConf) {
        $pcName  = if ($worstPc) { $worstPc.Name } else { 'n/a' }
        $adjEntry = "CAP5: ${Candidate}->${finalSev}; weakest precondition '$pcName' is $worstState ($($worstPc.Evidence))"
    }

    return [pscustomobject]@{
        Severity              = $finalSev
        Confidence            = $effectiveConf
        WeakestState          = $worstState
        AdjustmentEntry       = $adjEntry
        RenderedPreconditions = $rendered.ToArray()
    }
}
