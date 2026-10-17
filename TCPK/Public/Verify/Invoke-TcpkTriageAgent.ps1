function Invoke-TcpkTriageAgent {
<#
.SYNOPSIS
    Autonomous lead-triage agent: for every LEAD finding, choose and run the matching
    confirmation tool, read the verdict, and classify it promote / drop / hold.

.DESCRIPTION
    This is the control loop the "agentic" UI was missing. Today a human drives every step
    (pick target -> run audit -> review each lead by hand). This cmdlet makes the TRIAGE phase
    autonomous: it takes the findings, isolates the leads (Confidence 'Inferred'/'Unverified'),
    and for each one decides which confirmer applies, runs it, and records why.

    The agent NEVER produces a finding or evidence. Those come only from the deterministic
    confirmers it calls and, optionally, the adversarial LLM skeptic. The agent's only jobs are:
    choose the next tool per lead, run it, read the verdict it returns, and narrate the step.
    Proven findings (Confidence 'Confirmed*') pass straight through, untouched. Read-only.

    Stages, cheapest-first (a lead stops at the first stage that resolves it):
      1. IL confirmer  Confirm-TcpkCallsiteUsage -- deterministic data-flow proof on managed
                       call sites. Promotes to 'Confirmed (IL)' or drops to 'Likely-FP (IL)'.
      2. LLM skeptic   Invoke-TcpkLlmCodeJudgment (only with -EnableLlm) -- an adversarial
                       N-vote that defaults to "not-real"; a majority 'real' promotes to
                       'Confirmed (LLM)', otherwise drops to 'Likely-FP (LLM)'.
    A lead neither stage resolves is HELD -- it needs dynamic or manual confirmation and is
    reported as a lead, never silently promoted. That is the no-hallucination contract: a
    finding becomes PROVEN only because a tool proved it.

.PARAMETER Findings
    The findings to triage (the finding set an audit produced). Proven findings are returned
    untouched; only leads are worked.

.PARAMETER EnableLlm
    Run the LLM skeptic (stage 2) on leads the IL stage leaves unresolved. Requires a configured
    provider (Ollama offline, or GitHub Models via Enable-TcpkLlmCloud). Without it the agent is
    fully deterministic and offline: stage 1 only.

.PARAMETER Votes
    Skeptic votes per lead (default 3). A majority of 'real' verdicts is required to promote.

.PARAMETER MaxSteps
    Budget: the maximum number of confirmer invocations before remaining leads are HELD. Keeps
    a large finding set bounded. Default 1000.

.OUTPUTS
    [pscustomobject] with:
      Promoted   - leads a tool proved (now Confirmed*)
      Dropped    - leads a tool refuted (now Likely-FP*)
      Held       - leads no tool could resolve (still Inferred/Unverified)
      Transcript - the agent's step log (per lead: stage, before/after confidence, verdict, reason)
      Findings   - the full refined set (proven passthrough + triaged leads)
      Summary    - counts

.EXAMPLE
    $r = $all | Invoke-TcpkTriageAgent
    $r.Summary
    $r.Transcript | Format-Table Step, Verdict, RuleId, Reason -AutoSize

.EXAMPLE
    $r = $all | Invoke-TcpkTriageAgent -EnableLlm -Votes 5
    $r.Promoted   # only the leads a tool actually proved
#>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)][object[]]$Findings,
        [switch]$EnableLlm,
        [int]$Votes = 3,
        [int]$MaxSteps = 1000
    )

    begin { $all = New-Object 'System.Collections.Generic.List[object]' }
    process { foreach ($f in $Findings) { if ($null -ne $f) { $all.Add($f) } } }
    end {
        $split  = Get-TcpkAssuranceSplit -Findings $all.ToArray()
        $proven = @($split.Proven)
        $leads  = @($split.Leads)

        $promoted = New-Object 'System.Collections.Generic.List[object]'
        $dropped  = New-Object 'System.Collections.Generic.List[object]'
        $held     = New-Object 'System.Collections.Generic.List[object]'
        $resolved = New-Object 'System.Collections.Generic.List[object]'
        $transcript = New-Object 'System.Collections.Generic.List[object]'
        $steps = 0

        Write-Information -MessageData ("[agent] triage start: {0} leads, {1} already proven" -f $leads.Count, $proven.Count) -InformationAction Continue

        foreach ($lead in $leads) {
            $cur       = $lead
            $beforeConf = "$($cur.Confidence)"
            $stageUsed  = 'none'

            if ($steps -lt $MaxSteps) {
                # Stage 1 -- deterministic IL confirmer. It self-selects: a lead with no call-site
                # sink spec (or no readable managed body) is returned unchanged, so this safely
                # no-ops on non-IL leads and they fall through to the skeptic or HOLD. A confirmer
                # error holds the lead rather than crashing the whole run.
                try {
                    $out = @($cur | Confirm-TcpkCallsiteUsage)
                    if ($out.Count) { $cur = $out[0] }
                } catch { Write-Verbose "IL confirmer failed on $($cur.RuleId): $($_.Exception.Message)" }
                $steps++
                if ("$($cur.Confidence)" -ne $beforeConf) { $stageUsed = 'IL' }
            }

            if ($stageUsed -eq 'none' -and $EnableLlm -and (Test-TcpkIsLead $cur) -and $steps -lt $MaxSteps) {
                # Stage 2 -- adversarial LLM skeptic on what the IL stage could not resolve.
                try {
                    $out2 = @($cur | Invoke-TcpkLlmCodeJudgment -Votes $Votes)
                    if ($out2.Count) { $cur = $out2[0] }
                } catch { Write-Verbose "LLM skeptic failed on $($cur.RuleId): $($_.Exception.Message)" }
                $steps++
                if ("$($cur.Confidence)" -ne $beforeConf) { $stageUsed = 'LLM' }
            }

            $afterConf = "$($cur.Confidence)"
            $verdict = if ($afterConf -match '^Confirmed') { 'PROMOTE' }
                       elseif ($afterConf -match '^Likely-FP') { 'DROP' }
                       else { 'HOLD' }
            switch ($verdict) {
                'PROMOTE' { $promoted.Add($cur) }
                'DROP'    { $dropped.Add($cur) }
                default   { $held.Add($cur) }
            }
            $resolved.Add($cur)

            $reason = Get-TcpkTriageReason -Finding $cur
            $transcript.Add([pscustomobject]@{
                Step    = $transcript.Count + 1
                RuleId  = "$($cur.RuleId)"
                Title   = "$($cur.Title)"
                File    = "$($cur.File)"
                Stage   = $stageUsed
                Before  = $beforeConf
                After   = $afterConf
                Verdict = $verdict
                Reason  = $reason
            })
            Write-Information -MessageData ("[agent] {0} {1} ({2}->{3}) via {4}" -f $verdict, "$($cur.RuleId)", $beforeConf, $afterConf, $stageUsed) -InformationAction Continue
        }

        # Proven findings pass through untouched; the triaged leads follow.
        $final = New-Object 'System.Collections.Generic.List[object]'
        foreach ($p in $proven)   { $final.Add($p) }
        foreach ($r in $resolved) { $final.Add($r) }

        Write-Information -MessageData ("[agent] triage done: {0} promoted, {1} dropped, {2} held ({3} steps)" -f $promoted.Count, $dropped.Count, $held.Count, $steps) -InformationAction Continue

        [pscustomobject]@{
            Promoted   = $promoted.ToArray()
            Dropped    = $dropped.ToArray()
            Held       = $held.ToArray()
            Transcript = $transcript.ToArray()
            Findings   = $final.ToArray()
            Summary    = [pscustomobject]@{
                Leads         = $leads.Count
                AlreadyProven = $proven.Count
                Promoted      = $promoted.Count
                Dropped       = $dropped.Count
                Held          = $held.Count
                Steps         = $steps
                LlmUsed       = [bool]$EnableLlm
            }
        }
    }
}
