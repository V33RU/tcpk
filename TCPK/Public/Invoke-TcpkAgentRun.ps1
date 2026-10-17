function Invoke-TcpkAgentRun {
<#
.SYNOPSIS
    One autonomous flow: recon -> plan -> run -> triage -> report. The human sets a target and a
    goal; the agent does every stage hands-off and narrates each into a single transcript.

.DESCRIPTION
    This is the unified agentic entry point. It does not replace any engine -- it ORCHESTRATES the
    verified pieces and narrates the reasoning, so "agentic" is the whole experience rather than a
    hidden mode:

      1. OBSERVE  Get-TcpkAppIdentity        -- recon the target (app type, runtime, managed/native, UI)
      2. PLAN     (deterministic)            -- from the profile, state which check families matter
      3. RUN      Invoke-TcpkAudit           -- the full deterministic audit (every applicable check,
                                                its own IL confirm + reports). The breadth stays
                                                deterministic; the agent never decides a finding exists.
      4. TRIAGE   Invoke-TcpkTriageAgent     -- autonomously resolve each lead (IL confirmer, then the
                                                optional LLM skeptic), visibly: promote / drop / hold.
      5. REPORT   Get-TcpkRiskLine           -- the proven-first risk verdict.

    The no-hallucination contract holds end to end: the deterministic audit finds and the confirmers
    prove; the agent only plans, triages, and narrates. With no LLM configured it is fully
    deterministic and offline (stage 4 uses the IL confirmer only).

    Report files in OutDir reflect the deterministic audit (stage 3). The agent's triage decisions
    (stage 4) are in the returned object and, when -OutDir is given, in agent-triage.json beside them.

.PARAMETER Target
    Install dir, EXE/DLL, or an MSIX/MSI/ZIP (auto-unwrapped), same as Invoke-TcpkAudit.

.PARAMETER Goal
    A one-line goal for the run. Recorded in the transcript and used to frame the report. Default is
    a proven-findings audit.

.PARAMETER Acknowledge
    Required, forwarded to Invoke-TcpkAudit: you confirm this is an authorized target.

.PARAMETER EnableLlm
    Let the triage stage use the LLM skeptic (needs a configured provider). Without it, triage is
    deterministic (IL confirmer only).

.PARAMETER Votes
    Skeptic votes per lead (default 3).

.PARAMETER OutDir
    Where Invoke-TcpkAudit writes its reports; agent-triage.json is written here too.

.OUTPUTS
    [pscustomobject] Target, Goal, Profile, Plan, RunSummary, Triage, Risk, Transcript, Findings, OutDir

.EXAMPLE
    Invoke-TcpkAgentRun -Target 'C:\Apps\Thick' -Acknowledge
    # deterministic, offline: recon -> plan -> audit -> IL-triage -> risk

.EXAMPLE
    $r = Invoke-TcpkAgentRun -Target 'C:\Apps\Thick' -Acknowledge -EnableLlm
    $r.Transcript | Format-Table Phase, Message -AutoSize -Wrap
#>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][string]$Target,
        [string]$Goal = 'Audit this target and report only proven findings.',
        [switch]$Acknowledge,
        [switch]$EnableLlm,
        [int]$Votes = 3,
        [string]$OutDir
    )

    $transcript = New-Object 'System.Collections.Generic.List[object]'
    $say = {
        param([string]$Phase, [string]$Message)
        $transcript.Add([pscustomobject]@{ Phase = $Phase; Message = $Message })
        Write-Information -MessageData ("[agent:{0}] {1}" -f $Phase, $Message) -InformationAction Continue
    }

    # ---- 1. OBSERVE -----------------------------------------------------------
    # NB: $prof, not $profile -- $profile is a PowerShell automatic variable (the profile path).
    $prof = $null
    try { $prof = Get-TcpkAppIdentity -Path $Target } catch { }
    if ($prof) {
        $cls = "$($prof.AppType) / $($prof.Runtime)"
        if ($prof.Managed)    { $cls += ' (managed .NET)' }
        if ($prof.IsElectron) { $cls += ' (Electron)' }
        & $say 'observe' ("recon: {0} {1} -- {2} {3}" -f "$($prof.Name)", "$($prof.Version)", $cls, "$($prof.Architecture)")
    } else {
        & $say 'observe' ("recon: could not profile '{0}' -- auditing anyway" -f $Target)
    }

    # ---- 2. PLAN (deterministic) ----------------------------------------------
    $planNotes = New-Object 'System.Collections.Generic.List[string]'
    if ($prof -and $prof.Managed)    { $planNotes.Add('managed .NET: IL/decompile, callsite taint, crypto and credential-literal checks apply') }
    if ($prof -and $prof.IsElectron) { $planNotes.Add('Electron: asar/JS, nodeIntegration and protocol-handler checks apply') }
    if (-not $prof -or (-not $prof.Managed -and -not $prof.IsElectron)) { $planNotes.Add('native/other: PE hardening, signing, strings and DLL-search checks apply') }
    $planNotes.Add('running the full deterministic audit, then AI-triage on the leads')
    $plan = $planNotes.ToArray()
    & $say 'plan' ($plan -join '; ')

    # ---- 3. RUN (deterministic breadth) ---------------------------------------
    if (-not $Acknowledge) {
        & $say 'run' 'SKIPPED: pass -Acknowledge to confirm this is an authorized target.'
        return [pscustomobject]@{
            Target = $Target; Goal = $Goal; Profile = $prof; Plan = $plan
            RunSummary = $null; Triage = $null; Risk = $null
            Transcript = $transcript.ToArray(); Findings = @(); OutDir = $OutDir
        }
    }
    $auditArgs = @{ Target = $Target; Acknowledge = $true }
    if ($OutDir) { $auditArgs['OutDir'] = $OutDir }
    $findings = @(Invoke-TcpkAudit @auditArgs)
    $split0 = Get-TcpkAssuranceSplit -Findings $findings
    $runSummary = [pscustomobject]@{
        Findings = $findings.Count; Proven = $split0.ProvenCount; Leads = $split0.LeadCount
    }
    & $say 'run' ("audit complete: {0} findings ({1} proven, {2} leads)" -f $findings.Count, $split0.ProvenCount, $split0.LeadCount)

    # ---- 4. TRIAGE (agentic, visible) -----------------------------------------
    $triage = $findings | Invoke-TcpkTriageAgent -EnableLlm:$EnableLlm -Votes $Votes 6>$null
    foreach ($t in @($triage.Transcript)) {
        & $say 'triage' ("{0} {1} ({2}->{3}) via {4}" -f $t.Verdict, $t.RuleId, $t.Before, $t.After, $t.Stage)
    }
    & $say 'triage' ("resolved: {0} promoted, {1} dropped, {2} held" -f $triage.Summary.Promoted, $triage.Summary.Dropped, $triage.Summary.Held)

    # ---- 5. REPORT ------------------------------------------------------------
    $risk = Get-TcpkRiskLine -Findings $triage.Findings
    & $say 'report' $risk.Text
    if ($OutDir -and (Test-Path -LiteralPath $OutDir)) {
        try {
            $triagePath = Join-Path $OutDir 'agent-triage.json'
            $triage | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $triagePath -Encoding UTF8
            & $say 'report' ("agent triage written: {0}" -f $triagePath)
        } catch { Write-Verbose "agent-triage.json write failed: $($_.Exception.Message)" }
    }

    [pscustomobject]@{
        Target     = $Target
        Goal       = $Goal
        Profile    = $prof
        Plan       = $plan
        RunSummary = $runSummary
        Triage     = $triage
        Risk       = $risk
        Transcript = $transcript.ToArray()
        Findings   = $triage.Findings
        OutDir     = $OutDir
    }
}
