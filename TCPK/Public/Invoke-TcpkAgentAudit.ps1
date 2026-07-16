function Invoke-TcpkAgentAudit {
<#
.SYNOPSIS
    Run the autonomous TCPK security agent over a target -- a REAL tool-using agent
    (reason -> call read-only tool -> observe -> repeat), bounded by the deterministic
    IL prover. The model DECIDES each step; the Cecil/IL engine grounds every finding.

.DESCRIPTION
    Drives Invoke-TcpkAgentLoop. The agent's toolset is read/analyze ONLY
    (list_sink_methods / inspect_method / submit_finding / finish) -- the exploit bucket
    is NEVER exposed. A step budget caps the loop; submitted findings are re-checked
    against the deterministic reachability engine (agent proposes, IL prover disposes).

    Local-first: talks to ollama (/api/chat) via the JSON-action protocol, so it works
    with any chat model (no native tool-calling required). Use a capable code model
    (qwen2.5-coder:7b+) for reliable multi-step behaviour; a 1.5b model can drive the
    loop but follows the submit-finding protocol unreliably.

.PARAMETER Target
    Install dir, EXE, or DLL to audit.

.PARAMETER Goal
    Natural-language objective for the agent.

.PARAMETER Model
    ollama model tag (default qwen2.5-coder:1.5b).

.PARAMETER MaxSteps
    Hard cap on agent iterations (default 20). The per-candidate flow
    (inspect -> taint -> callers -> submit) needs room; below ~20 the agent
    often runs out of budget mid-investigation.

.PARAMETER StreamTagged
    Emit AGS<tab>json per step and AGR<tab>json for the final result (used by the web
    workbench's background job to stream live). Without it, returns the result object.

.OUTPUTS
    [hashtable] the run result (goal/target/model/steps/findings/summary/done), unless
    -StreamTagged (then writes tagged lines to the output stream).
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Target,
        [string]$Goal = 'Find the most serious vulnerabilities in this .NET target.',
        [string]$Model = 'qwen2.5-coder:7b',
        [int]$MaxSteps = 20,
        [switch]$StreamTagged
    )
    $emit = if ($StreamTagged) { { param($e) Write-Output ("AGS`t" + ($e | ConvertTo-Json -Depth 6 -Compress)) } } else { $null }
    $result = Invoke-TcpkAgentLoop -Target $Target -Goal $Goal -Model $Model -MaxSteps $MaxSteps -Emit $emit
    if ($StreamTagged) { Write-Output ("AGR`t" + ($result | ConvertTo-Json -Depth 8 -Compress)) }
    else { $result }
}
