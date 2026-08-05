# C10 - A sink is not a vulnerability without a reachable, unsanitized path.
#
# Pattern-matching dangerous APIs finds every use, not every misuse.
# Observed: four sink findings where the sink was real but the risk was not:
#   - values escaped by a correct serializer before reaching the sink
#   - input was a static asset shipped inside the application
#   - argument was an application-internal path with no external influence
#   - genuine remote-influenced value constrained by an enforced allowlist
#
# Three elements must be established for a sink finding; each is a tested field:
#
#   SOURCE    - can the value be influenced by something outside the trust boundary?
#               A constant, shipped asset, or app-derived path is NOT a source.
#               absent -> at most INFO ("dangerous-API inventory")
#               established -> proceed; untested -> Inferred confidence, cap MEDIUM
#
#   PATH      - does the value reach the sink AND is there a NEUTRALIZER between them?
#               Neutralizers: correct serializer/encoding, validation, allowlist, guard.
#               established -> proceed; neutralized -> downgrade + name it; untested -> Inferred
#
#   BOUNDARY  - does reaching the sink cross a privilege or context boundary?
#               absent -> max LOW; established -> proceed; untested -> Inferred
#
# Severity mapping (integrates with CAP5 Resolve-TcpkPreconditions):
#   Source=absent      -> REFUTED  -> INFO
#   Source=untested    -> UNTESTED -> MEDIUM, Inferred
#   Path=neutralized   -> REFUTED  -> INFO
#   Path=untested      -> UNTESTED -> MEDIUM, Inferred
#   Boundary=absent    -> REFUTED  -> INFO
#   Boundary=untested  -> UNTESTED -> MEDIUM, Inferred
#   All=established    -> full candidate severity

function New-TcpkSinkAnalysis {
<#
.SYNOPSIS
    C10 - Create a taint analysis record for a sink finding.

.DESCRIPTION
    Rules call this when emitting a sink finding (callsites.*, deser.*, xxe.*,
    injection.*, etc.).  The three elements are each a tested field with an
    explanatory detail string.

.PARAMETER Source
    established - confirmed external influence (remote data / user input / IPC from lower trust)
    absent      - no external influence; value is constant, shipped asset, or app-derived
    untested    - the rule did not check

.PARAMETER PathDetail
    What was observed on the path (function calls, data flow hops, encoding steps).

.PARAMETER Neutralizer
    Name/description of the neutralizer when Path='neutralized'.
    E.g. 'JsonSerializer.Serialize', 'validateInput(allowlist)', 'HttpUtility.HtmlEncode'.

.PARAMETER Boundary
    established - reaching the sink crosses a privilege or context boundary
    absent      - no privilege boundary is crossed (e.g. same-process, same-user)
    untested    - not checked
#>
    [CmdletBinding()]
    param(
        [ValidateSet('established','absent','untested')][string]$Source   = 'untested',
        [string]$SourceDetail   = '',
        [ValidateSet('established','neutralized','untested')][string]$Path = 'untested',
        [string]$PathDetail     = '',
        [string]$Neutralizer    = '',   # set when Path='neutralized'
        [ValidateSet('established','absent','untested')][string]$Boundary = 'untested',
        [string]$BoundaryDetail = ''
    )
    [pscustomobject]@{
        Source         = $Source
        SourceDetail   = $SourceDetail
        Path           = $Path
        PathDetail     = $PathDetail
        Neutralizer    = $Neutralizer
        Boundary       = $Boundary
        BoundaryDetail = $BoundaryDetail
    }
}

function Get-TcpkSinkPreconditions {
<#
.SYNOPSIS
    C10 - Convert a SinkAnalysis into CAP5 precondition objects.

.DESCRIPTION
    Maps the three C10 elements onto Resolve-TcpkPreconditions (CAP5) so the
    same severity-capping and AdjustmentLog machinery handles both.

    Source=absent    -> REFUTED  (no external influence; finding is API inventory)
    Path=neutralized -> REFUTED  (value is sanitized before reaching the sink)
    Boundary=absent  -> REFUTED  (no privilege boundary; severity capped to INFO)

.OUTPUTS
    [PSCustomObject[]] preconditions for Resolve-TcpkPreconditions
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$SinkAnalysis)

    $srcState = switch ($SinkAnalysis.Source) {
        'established' { 'CONFIRMED' }
        'absent'      { 'REFUTED'  }
        default       { 'UNTESTED' }
    }

    $pathState = switch ($SinkAnalysis.Path) {
        'established' { 'CONFIRMED' }
        'neutralized' { 'REFUTED'  }
        default       { 'UNTESTED' }
    }
    $pathEvidence = if ($SinkAnalysis.Path -eq 'neutralized' -and $SinkAnalysis.Neutralizer) {
        "Neutralized by: $($SinkAnalysis.Neutralizer). $($SinkAnalysis.PathDetail)".TrimEnd('. ')
    } else { $SinkAnalysis.PathDetail }

    $bndState = switch ($SinkAnalysis.Boundary) {
        'established' { 'CONFIRMED' }
        'absent'      { 'REFUTED'  }
        default       { 'UNTESTED' }
    }

    @(
        New-TcpkPrecondition -Name 'sink-source-external'   -State $srcState  -Evidence $SinkAnalysis.SourceDetail
        New-TcpkPrecondition -Name 'sink-path-unobstructed' -State $pathState  -Evidence $pathEvidence
        New-TcpkPrecondition -Name 'sink-boundary-crossed'  -State $bndState   -Evidence $SinkAnalysis.BoundaryDetail
    )
}

function Resolve-TcpkSinkSeverity {
<#
.SYNOPSIS
    C10 - Map a SinkAnalysis to a severity/confidence verdict.

.DESCRIPTION
    Delegates to Resolve-TcpkPreconditions (CAP5) via Get-TcpkSinkPreconditions,
    then appends C10-specific SOURCE|PATH|BOUNDARY annotation entries.

    Optional -Log parameter accepts a [ref] to a List[string] that will receive
    the annotation entries (for attachment to finding.AdjustmentLog).

.OUTPUTS
    PSCustomObject {Severity, Confidence, WeakestState, RenderedPreconditions, AdjustmentEntries}
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$SinkAnalysis,
        [Parameter(Mandatory)]
        [ValidateSet('CRITICAL','HIGH','MEDIUM','LOW','INFO')][string]$Candidate,
        [string]$CandidateConf = 'Confirmed',
        [ref]$Log = $null
    )

    $preconds = Get-TcpkSinkPreconditions -SinkAnalysis $SinkAnalysis
    $r = Resolve-TcpkPreconditions -Preconditions $preconds -Candidate $Candidate -CandidateConf $CandidateConf

    $srcStr  = "SOURCE=$($SinkAnalysis.Source)$(if($SinkAnalysis.SourceDetail){": $($SinkAnalysis.SourceDetail)"})"
    $pathStr = if ($SinkAnalysis.Path -eq 'neutralized' -and $SinkAnalysis.Neutralizer) {
        "PATH=neutralized (by $($SinkAnalysis.Neutralizer))"
    } else { "PATH=$($SinkAnalysis.Path)$(if($SinkAnalysis.PathDetail){": $($SinkAnalysis.PathDetail)"})" }
    $bndStr  = "BOUNDARY=$($SinkAnalysis.Boundary)$(if($SinkAnalysis.BoundaryDetail){": $($SinkAnalysis.BoundaryDetail)"})"

    $entries = @("C10: $srcStr | $pathStr | $bndStr")
    if ($r.AdjustmentEntry) { $entries += $r.AdjustmentEntry }

    if ($Log -and $null -ne $Log.Value) {
        foreach ($e in $entries) { $Log.Value.Add($e) }
    }

    return [pscustomobject]@{
        Severity              = $r.Severity
        Confidence            = $r.Confidence
        WeakestState          = $r.WeakestState
        RenderedPreconditions = $r.RenderedPreconditions
        AdjustmentEntries     = $entries
    }
}

function Format-TcpkSinkSummary {
<#
.SYNOPSIS
    C10 - Render a human-readable summary of which taint elements were established vs assumed.

.DESCRIPTION
    Returns a single string suitable for the finding's Evidence or Description field.
    "A correct verdict reached by wrong reasoning must fail the test" -- this summary
    makes the reasoning visible, not just the verdict.
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$SinkAnalysis)

    $established = [System.Collections.Generic.List[string]]::new()
    $assumed     = [System.Collections.Generic.List[string]]::new()
    $negated     = [System.Collections.Generic.List[string]]::new()

    switch ($SinkAnalysis.Source) {
        'established' { $established.Add('SOURCE') }
        'absent'      { $negated.Add('SOURCE (no external influence)') }
        default       { $assumed.Add('SOURCE (not checked)') }
    }
    switch ($SinkAnalysis.Path) {
        'established' { $established.Add('PATH') }
        'neutralized' { $negated.Add("PATH (neutralized by $($SinkAnalysis.Neutralizer))") }
        default       { $assumed.Add('PATH (not checked)') }
    }
    switch ($SinkAnalysis.Boundary) {
        'established' { $established.Add('BOUNDARY') }
        'absent'      { $negated.Add('BOUNDARY (no privilege crossing)') }
        default       { $assumed.Add('BOUNDARY (not checked)') }
    }

    $parts = [System.Collections.Generic.List[string]]::new()
    if ($established.Count) { $parts.Add("Established: $($established -join ', ')") }
    if ($negated.Count)     { $parts.Add("Refuted/absent: $($negated -join '; ')") }
    if ($assumed.Count)     { $parts.Add("Assumed/untested: $($assumed -join '; ')") }
    return $parts -join ' | '
}
