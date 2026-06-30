# TCPK autonomous agent loop -- a REAL tool-using agent, bounded by the deterministic
# IL prover. The MODEL decides which read-only tool to call each step (reason -> act ->
# observe -> repeat) toward a goal; the Cecil/IL engine grounds every claim.
#
# SAFETY: the toolset is read/analyze ONLY (list / inspect / submit / finish). The
# exploit bucket is NEVER exposed to the agent. A step budget caps the loop. Findings
# the agent submits are re-checked against the deterministic reachability engine -- the
# agent PROPOSES, the IL prover DISPOSES.
#
# Transport: a portable JSON-action protocol -- the model replies with ONE JSON object
# {"thought":..,"tool":..,"args":..} or {"thought":..,"final":..}. We do NOT rely on
# native ollama tool_calls (small local models don't populate that field reliably).

# ---- tool registry (read-only) -----------------------------------------------
function Get-TcpkAgentTools {
    @(
        @{ name='list_sink_methods'; desc='List candidate sink-bearing methods across the target modules. No args. Returns method names + the dangerous APIs each calls.' }
        @{ name='inspect_method';   desc='Decompile ONE method to IL and get its deterministic reachability + sinks. args: {"method":"Namespace.Type::Method"}' }
        @{ name='submit_finding';   desc='Record a vulnerability you have evidence for. args: {"method":"..","severity":"critical|high|medium|low","title":"..","rationale":".."}' }
        @{ name='finish';           desc='End the investigation with a short summary. args: {"summary":".."}' }
    )
}

# Execute a tool against the agent context. $Ctx carries Target / PrimaryDll / a sink
# cache / the findings accumulator / Done+Summary. ($ToolArgs, never $Args -- $args is
# an automatic variable.)
function Invoke-TcpkAgentTool {
    [CmdletBinding()] param([string]$Name, $ToolArgs, $Ctx)
    switch ($Name) {
        'list_sink_methods' {
            if (-not $Ctx.SinkCache) {
                $list = New-Object 'System.Collections.Generic.List[object]'
                foreach ($mod in (Get-TcpkAgentModules -Target $Ctx.Target)) {
                    $dec = Get-TcpkAgentDecompile -Dll $mod.path
                    foreach ($im in @($dec.interesting)) { $list.Add([ordered]@{ module=$mod.name; dll=$mod.path; method=$im.name; sinks=$im.sinks }) }
                }
                $Ctx.SinkCache = $list
            }
            $methods = @($Ctx.SinkCache | Select-Object -First 25 | ForEach-Object {
                @{ method=$_.method; sinks=$_.sinks; status=$(if($Ctx.Submitted.Contains($_.method)){'submitted'}elseif($Ctx.Inspected.Contains($_.method)){'inspected'}else{'new'}) } })
            $remaining = @($methods | Where-Object { $_.status -eq 'new' }).Count
            $hint = if ($remaining -eq 0) { 'all candidate methods have been inspected or submitted -- call finish now' } else { "$remaining still new -- inspect a method whose status is new; do not repeat one" }
            return @{ count = $Ctx.SinkCache.Count; remaining_new = $remaining; hint = $hint; methods = $methods }
        }
        'inspect_method' {
            $mm = "$($ToolArgs.method)"; if (-not $mm) { return @{ error='method arg required' } }
            $dll = $Ctx.PrimaryDll
            if ($Ctx.SinkCache) { $hit = @($Ctx.SinkCache | Where-Object { $_.method -eq $mm })[0]; if ($hit) { $dll = $hit.dll } }
            $dec = Get-TcpkAgentDecompile -Dll $dll -Method $mm
            if ($dec.error) { return @{ error=$dec.error } }
            [void]$Ctx.Inspected.Add($mm)
            $reach = Get-TcpkAgentMethodReachable -Dll $dll -Method $mm
            $sinks = @($dec.il | Where-Object { $_.sink } | ForEach-Object { ($_.arg -split '::')[-1] } | Select-Object -Unique)
            $ilsum = (@($dec.il | ForEach-Object { "$($_.op) $((($_.arg -split '::')[-1]))" }) -join '; ')
            if ($ilsum.Length -gt 700) { $ilsum = $ilsum.Substring(0,700)+'...' }
            return @{ method=$mm; reachable=$reach; sinks=$sinks; il_summary=$ilsum }
        }
        'submit_finding' {
            $mm = "$($ToolArgs.method)"
            if ($Ctx.Submitted.Contains($mm)) { return @{ recorded=$false; note='you ALREADY recorded this method -- do NOT repeat it. Inspect a different method whose status is new, or call finish.' } }
            [void]$Ctx.Submitted.Add($mm)
            $dll = $Ctx.PrimaryDll; $hasSink = $false
            if ($Ctx.SinkCache) { $hit = @($Ctx.SinkCache | Where-Object { $_.method -eq $mm })[0]; if ($hit) { $dll=$hit.dll; $hasSink=$true } }
            $reach = Get-TcpkAgentMethodReachable -Dll $dll -Method $mm
            $Ctx.Findings.Add([ordered]@{ method=$mm; severity="$($ToolArgs.severity)"; title="$($ToolArgs.title)"; rationale="$($ToolArgs.rationale)"; il_reachable=$reach; has_sink=$hasSink })
            $note = if ($reach -and $hasSink) { 'IL cross-check: reachable + real sink -- backed by evidence' }
                    elseif (-not $hasSink) { 'WARNING: no known sink in this method -- this finding is weak, reconsider' }
                    else { 'IL cross-check: NOT reachable -- lower priority' }
            return @{ recorded=$true; il_reachable=$reach; has_sink=$hasSink; note=$note }
        }
        'finish' { $Ctx.Done=$true; $Ctx.Summary="$($ToolArgs.summary)"; return @{ done=$true } }
        default  { return @{ error="unknown tool: $Name" } }
    }
}

# Deterministic reachability for "Type::Method" in a dll (locates the method, reuses the
# cached caller-scan). Returns $true/$false, or $null if not found.
function Get-TcpkAgentMethodReachable {
    param([string]$Dll, [string]$Method)
    try {
        $asm = Get-TcpkCecilAssembly $Dll; if (-not $asm) { return $null }
        $md = $null
        foreach ($t in $asm.MainModule.GetTypes()) { foreach ($x in $t.Methods) { if ("$($t.FullName)::$($x.Name)" -eq $Method) { $md=$x; break } }; if ($md) { break } }
        if (-not $md) { return $null }
        return [bool](Get-TcpkAgentReachable -Asm $asm -Method $md)
    } catch { return $null }
}

# ---- transport: one chat turn over ollama /api/chat (JSON-action protocol) -----
function Invoke-TcpkAgentChat {
    [CmdletBinding()] param([array]$Messages, [string]$Model, [string]$BaseUrl='http://localhost:11434')
    $body = @{ model=$Model; stream=$false; messages=$Messages; options=@{ temperature=0.1 } } | ConvertTo-Json -Depth 12
    $r = Invoke-RestMethod "$BaseUrl/api/chat" -Method POST -Body $body -ContentType 'application/json' -TimeoutSec 120
    return "$($r.message.content)"
}

# Pull the first JSON object out of a model reply (strips ``` fences / surrounding prose).
function ConvertFrom-TcpkAgentAction {
    param([string]$Content)
    $c = "$Content".Trim()
    $c = [regex]::Replace($c, '(?s)^```[a-zA-Z]*\s*', '')
    $c = [regex]::Replace($c, '(?s)\s*```$', '')
    $mt = [regex]::Match($c, '(?s)\{.*\}')
    if (-not $mt.Success) { return $null }
    try { return ($mt.Value | ConvertFrom-Json) } catch { return $null }
}

# ---- the agent loop -----------------------------------------------------------
function Invoke-TcpkAgentLoop {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Target,
        [string]$Goal = 'Find the most serious vulnerabilities in this .NET target.',
        [string]$Model = 'qwen2.5-coder:7b',
        [int]$MaxSteps = 14,
        [scriptblock]$Emit,
        [string]$BaseUrl = 'http://localhost:11434'
    )
    $p = Resolve-TcpkWebTarget $Target
    if (-not $p) { return @{ error='target not found' } }
    $primary = $p
    if (Test-Path -LiteralPath $p -PathType Container) { $mods = Get-TcpkAgentModules -Target $p; if ($mods.Count) { $primary = $mods[0].path } }

    $ctx = @{ Target=$p; PrimaryDll=$primary; Findings=(New-Object 'System.Collections.Generic.List[object]'); SinkCache=$null; Done=$false; Summary='';
              Inspected=(New-Object 'System.Collections.Generic.HashSet[string]'); Submitted=(New-Object 'System.Collections.Generic.HashSet[string]') }
    $tools = Get-TcpkAgentTools
    $toolDesc = (@($tools | ForEach-Object { "- $($_.name): $($_.desc)" }) -join "`n")
    $sys = @(
        'You are an autonomous application-security agent auditing a .NET binary by calling READ-ONLY tools and reasoning over what they return.',
        'Reply with EXACTLY ONE JSON object and NOTHING else -- either a tool call or a finish:',
        '  {"thought":"brief reasoning","tool":"<name>","args":{...}}',
        '  {"thought":"brief reasoning","final":{"summary":"..."}}',
        'Tools:',
        $toolDesc,
        'Process: call list_sink_methods ONCE to get the candidate list -- each method shows a status (new / inspected / submitted). Then inspect_method on a method whose status is NEW. When inspect_method shows reachable=true AND a real dangerous sink, call submit_finding for it (a vulnerability mentioned only in your summary does NOT count). NEVER inspect or submit the same method twice, and do NOT keep re-calling list_sink_methods. When remaining_new is 0 (every promising method reviewed), call finish. Be conservative: never invent a vulnerability.',
        'The tool results are the source of truth. Ground every finding in the reachability/sinks the tools report, not in assumptions.'
    ) -join "`n"
    $messages = @(
        @{ role='system'; content=$sys },
        @{ role='user';   content="Goal: $Goal`nTarget: $(Split-Path $primary -Leaf)`nBegin your investigation." }
    )
    $steps = New-Object 'System.Collections.Generic.List[object]'
    $nudged = $false

    for ($i=1; $i -le $MaxSteps; $i++) {
        if ($ctx.Done) { break }
        $content = $null
        try { $content = Invoke-TcpkAgentChat -Messages $messages -Model $Model -BaseUrl $BaseUrl }
        catch { if ($Emit) { & $Emit @{ step=$i; type='error'; text="LLM call failed: $($_.Exception.Message)" } }; break }

        $act = ConvertFrom-TcpkAgentAction $content
        if (-not $act) {
            if ($Emit) { & $Emit @{ step=$i; type='parse'; text='reply was not valid JSON; re-prompting' } }
            $messages += @{ role='assistant'; content=$content }
            $messages += @{ role='user'; content='Reply with ONLY one JSON object: {"thought":..,"tool":..,"args":..} or {"thought":..,"final":..}.' }
            continue
        }
        $thought = "$($act.thought)"
        if ($act.final) {
            if ($ctx.Findings.Count -eq 0 -and -not $nudged) {
                $nudged = $true
                if ($Emit) { & $Emit @{ step=$i; type='nudge'; text='finishing with 0 findings recorded -- asking the agent to submit any real ones first' } }
                $messages += @{ role='assistant'; content=$content }
                $messages += @{ role='user'; content='You are about to finish with NO findings recorded. If your investigation found any reachable sink vulnerability, call submit_finding for EACH one NOW (one JSON action per turn). If there are genuinely none, reply with finish again.' }
                continue
            }
            $ctx.Done=$true; $ctx.Summary="$($act.final.summary)"
            if ($Emit) { & $Emit @{ step=$i; type='final'; thought=$thought; text=$ctx.Summary } }
            break
        }
        $tool = "$($act.tool)"
        if ($Emit) { & $Emit @{ step=$i; type='tool'; tool=$tool; thought=$thought; args=$act.args } }
        $obs = Invoke-TcpkAgentTool -Name $tool -ToolArgs $act.args -Ctx $ctx
        $obsJson = ($obs | ConvertTo-Json -Depth 6 -Compress)
        if ($obsJson.Length -gt 1500) { $obsJson = $obsJson.Substring(0,1500)+'...' }
        if ($Emit) { & $Emit @{ step=$i; type='observation'; tool=$tool; text=$obsJson } }
        $steps.Add([ordered]@{ step=$i; thought=$thought; tool=$tool; observation=$obs })
        $messages += @{ role='assistant'; content=$content }
        $messages += @{ role='user'; content="Observation: $obsJson" }
    }

    return @{ goal=$Goal; target=(Split-Path $primary -Leaf); model=$Model; steps=@($steps.ToArray()); findings=@($ctx.Findings.ToArray()); summary=$ctx.Summary; done=$ctx.Done }
}
