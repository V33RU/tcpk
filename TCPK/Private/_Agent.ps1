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
        @{ name='get_taint_trace';  desc='Deterministic source->sink taint verdict for a method, from the SAME IL prover the audit uses. verdict=tainted-reachable means external input reaches a reachable sink (strongest evidence); constant-only means not injectable. Call this BEFORE submit_finding to ground it. args: {"method":"Namespace.Type::Method"}' }
        @{ name='get_callers';      desc='List methods that CALL this method, each with its own reachability -- walk UP toward an entry point / event handler to prove attacker reachability. args: {"method":"Namespace.Type::Method"}' }
        @{ name='get_callees';      desc='List the methods this method calls (sinks flagged) -- drill DOWN into what it does. args: {"method":"Namespace.Type::Method"}' }
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
        'get_taint_trace' {
            $mm = "$($ToolArgs.method)"; if (-not $mm) { return @{ error='method arg required' } }
            return (Get-TcpkAgentTaintTrace -Dll (Get-TcpkAgentDllFor -Ctx $Ctx -Method $mm) -Method $mm)
        }
        'get_callers' {
            $mm = "$($ToolArgs.method)"; if (-not $mm) { return @{ error='method arg required' } }
            return (Get-TcpkAgentCallers -Dll (Get-TcpkAgentDllFor -Ctx $Ctx -Method $mm) -Method $mm)
        }
        'get_callees' {
            $mm = "$($ToolArgs.method)"; if (-not $mm) { return @{ error='method arg required' } }
            return (Get-TcpkAgentCallees -Dll (Get-TcpkAgentDllFor -Ctx $Ctx -Method $mm) -Method $mm)
        }
        'submit_finding' {
            $mm = "$($ToolArgs.method)"
            if ($Ctx.Submitted.Contains($mm)) { return @{ recorded=$false; note='you ALREADY recorded this method -- do NOT repeat it. Inspect a different method whose status is new, or call finish.' } }
            [void]$Ctx.Submitted.Add($mm)
            $dll = $Ctx.PrimaryDll; $hasSink = $false
            if ($Ctx.SinkCache) { $hit = @($Ctx.SinkCache | Where-Object { $_.method -eq $mm })[0]; if ($hit) { $dll=$hit.dll; $hasSink=$true } }
            $reach = Get-TcpkAgentMethodReachable -Dll $dll -Method $mm
            # agent proposes, IL prover disposes: attach the deterministic taint verdict.
            $tv = 'unknown'; try { $tt = Get-TcpkAgentTaintTrace -Dll $dll -Method $mm; if ($tt) { $tv = "$($tt.verdict)" } } catch { }
            $Ctx.Findings.Add([ordered]@{ method=$mm; severity="$($ToolArgs.severity)"; title="$($ToolArgs.title)"; rationale="$($ToolArgs.rationale)"; il_reachable=$reach; has_sink=$hasSink; taint_verdict=$tv })
            $note = if ($tv -eq 'tainted-reachable') { 'IL prover: external input reaches a reachable sink -- CONFIRMED-class evidence' }
                    elseif ($tv -eq 'constant-only') { 'IL prover: sink called with constant argument(s) only -- NOT injectable here; this finding is weak, reconsider' }
                    elseif (-not $hasSink) { 'WARNING: no known sink in this method -- this finding is weak, reconsider' }
                    elseif ($reach) { 'IL prover: reachable sink but no external-input source proven -- state the assumption in your rationale' }
                    else { 'IL cross-check: NOT reachable -- lower priority' }
            return @{ recorded=$true; il_reachable=$reach; has_sink=$hasSink; taint_verdict=$tv; note=$note }
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

# ---- call-graph + taint tools (read-only) -------------------------------------
# These turn the agent from a sink-lister into an investigator: walk the call graph UP
# toward an attacker-reachable entry point (get_callers) and DOWN into a method
# (get_callees), and pull the SAME deterministic source->sink taint verdict the audit's
# IL prover uses (get_taint_trace via Get-TcpkCallsiteUsage), so a submission is grounded
# in proven data flow, not a guess. All read-only; the exploit bucket is never exposed.

# Resolve which module a method lives in: the SinkCache records a per-method dll; anything
# else (e.g. a caller discovered mid-investigation) falls back to the primary module.
function Get-TcpkAgentDllFor {
    param($Ctx, [string]$Method)
    if ($Ctx.SinkCache) { $hit = @($Ctx.SinkCache | Where-Object { $_.method -eq $Method })[0]; if ($hit) { return $hit.dll } }
    return $Ctx.PrimaryDll
}

# Locate a MethodDefinition by the agent's "Type::Method" identity (overloads collapse to
# one, matching the identity scheme used everywhere else in the agent). $null if absent.
function Get-TcpkAgentFindMethod {
    param($Asm, [string]$Method)
    foreach ($t in $Asm.MainModule.GetTypes()) {
        foreach ($m in $t.Methods) { if ("$($t.FullName)::$($m.Name)" -eq $Method) { return $m } }
    }
    return $null
}

# Callers of a method: every method whose body invokes it. Each caller carries its own
# reachability so the model can walk UP toward an entry point / event handler (an
# attacker-reachable root). Bounded.
function Get-TcpkAgentCallers {
    param([string]$Dll, [string]$Method, [int]$Max = 40)
    $asm = Get-TcpkCecilAssembly $Dll; if (-not $asm) { return @{ error='not a managed .NET assembly' } }
    $refOps = @('call','callvirt','newobj','ldftn','ldvirtftn')
    $callers = New-Object 'System.Collections.Generic.List[object]'
    $seen = New-Object 'System.Collections.Generic.HashSet[string]'
    try {
        foreach ($t in $asm.MainModule.GetTypes()) {
            foreach ($m in $t.Methods) {
                if (-not $m.HasBody) { continue }
                $id = "$($t.FullName)::$($m.Name)"
                if ($id -eq $Method -or $seen.Contains($id)) { continue }
                foreach ($ins in $m.Body.Instructions) {
                    if ($refOps -notcontains $ins.OpCode.Name) { continue }
                    $r = $ins.Operand -as [Mono.Cecil.MethodReference]
                    if ($r -and "$($r.DeclaringType.FullName)::$($r.Name)" -eq $Method) {
                        [void]$seen.Add($id)
                        $callers.Add([ordered]@{ method=$id; reachable=[bool](Get-TcpkAgentReachable -Asm $asm -Method $m) })
                        break
                    }
                }
                if ($callers.Count -ge $Max) { break }
            }
            if ($callers.Count -ge $Max) { break }
        }
    } catch { }
    $anyReach = @($callers | Where-Object { $_.reachable }).Count
    $hint = if ($callers.Count -eq 0) { 'no in-assembly callers -- reachable only if this is itself an entry point / event handler / public surface' }
            elseif ($anyReach) { 'at least one caller is reachable -- trace UP from it toward an entry point to establish attacker reachability' }
            else { 'callers exist but none are reachable yet -- keep walking up with get_callers' }
    return @{ method=$Method; callerCount=$callers.Count; callers=@($callers.ToArray()); hint=$hint }
}

# Callees of a method: the distinct methods it invokes, sinks flagged. Lets the model
# drill DOWN into what a method actually does. Bounded.
function Get-TcpkAgentCallees {
    param([string]$Dll, [string]$Method, [int]$Max = 60)
    $asm = Get-TcpkCecilAssembly $Dll; if (-not $asm) { return @{ error='not a managed .NET assembly' } }
    $md = Get-TcpkAgentFindMethod -Asm $asm -Method $Method
    if (-not $md) { return @{ error='method not found' } }
    if (-not $md.HasBody) { return @{ method=$Method; callees=@(); note='method has no body (abstract / P-Invoke / interface)' } }
    $refOps = @('call','callvirt','newobj','ldftn','ldvirtftn')
    $callees = New-Object 'System.Collections.Generic.List[object]'
    $seen = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($ins in $md.Body.Instructions) {
        if ($refOps -notcontains $ins.OpCode.Name) { continue }
        $r = $ins.Operand -as [Mono.Cecil.MethodReference]; if (-not $r) { continue }
        $id = "$($r.DeclaringType.FullName)::$($r.Name)"
        if ($seen.Contains($id)) { continue }
        [void]$seen.Add($id)
        $sink = Get-TcpkAgentSinkHit $r
        $callees.Add([ordered]@{ target=$id; sink=[bool]$sink; sinkLabel="$sink" })
        if ($callees.Count -ge $Max) { break }
    }
    return @{ method=$Method; calleeCount=$callees.Count; sinkCallees=@($callees | Where-Object { $_.sink }).Count; callees=@($callees.ToArray()) }
}

# The deterministic source->sink taint verdict for one method, straight from the SAME
# engine the audit's IL prover (Confirm-TcpkCallsiteUsage) uses. For each injection /
# capability sink family the method actually invokes, run Get-TcpkCallsiteUsage and keep
# the call sites whose ENCLOSING method is this one. ArgKind is ground truth:
# 'tainted' == external input reaches the sink (Confirmed-IL class), 'constant' == not
# injectable here. Note: bounded by Get-TcpkCallsiteUsage -Max, like the audit itself.
function Get-TcpkAgentTaintTrace {
    param([string]$Dll, [string]$Method)
    $asm = Get-TcpkCecilAssembly $Dll; if (-not $asm) { return @{ error='not a managed .NET assembly' } }
    $md = Get-TcpkAgentFindMethod -Asm $asm -Method $Method
    if (-not $md) { return @{ error='method not found' } }
    if (-not $md.HasBody) { return @{ method=$Method; verdict='no-body'; sites=@(); note='method has no body to analyze' } }

    # which sink families does THIS method invoke? (one pass over its own instructions;
    # -like is case-insensitive, matching Get-TcpkCallsiteUsage's own matching intent)
    $map = Get-TcpkCallsiteSinkMap
    $callOps = @('call','callvirt','newobj')
    $hitFamilies = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($ins in $md.Body.Instructions) {
        if ($callOps -notcontains $ins.OpCode.Name) { continue }
        $r = $ins.Operand -as [Mono.Cecil.MethodReference]; if (-not $r) { continue }
        $declFull = "$($r.DeclaringType.FullName)"; $nm = "$($r.Name)"
        foreach ($fam in $map.Keys) {
            if ($hitFamilies.Contains($fam)) { continue }
            foreach ($s in $map[$fam].Sinks) {
                $hit = if ($s.Mo) { $nm -like "*$($s.T)*" }
                       elseif ($s.M) { ($declFull -like "*$($s.T)*") -and ($nm -eq $s.M) }
                       else { $declFull -like "*$($s.T)*" }
                if ($hit) { [void]$hitFamilies.Add($fam); break }
            }
        }
    }
    if ($hitFamilies.Count -eq 0) { return @{ method=$Method; verdict='no-sink'; sites=@(); note='this method invokes no known dangerous sink -- a finding here would be weak' } }

    # ask the prover engine per hit family and keep only sites enclosed by THIS method
    $sites = New-Object 'System.Collections.Generic.List[object]'
    foreach ($fam in $hitFamilies) {
        $spec = $map[$fam]
        foreach ($sink in $spec.Sinks) {
            $gp = @{ DllPath=$Dll; TypeFragment=$sink.T; Injection=[bool]$spec.Inj; Max=200 }
            if ($sink.M)  { $gp.MethodName = $sink.M }
            if ($sink.Mo) { $gp.MethodOnly = $true }
            $u = $null; try { $u = Get-TcpkCallsiteUsage @gp } catch { }
            if (-not $u) { continue }
            foreach ($st in @($u.Sites)) {
                if ("$($st.Enclosing)" -ne $Method) { continue }
                $sites.Add([ordered]@{ family=$fam; injection=[bool]$spec.Inj; sink="$($st.Target)"; reachable=[bool]$st.Reachable; argKind="$($st.ArgKind)" })
            }
        }
    }
    $tainted   = @($sites | Where-Object { $_.argKind -eq 'tainted'  -and $_.reachable }).Count
    $reachDyn  = @($sites | Where-Object { $_.argKind -eq 'dynamic'  -and $_.reachable }).Count
    $constOnly = @($sites | Where-Object { $_.argKind -eq 'constant' }).Count
    $verdict = if ($tainted) { 'tainted-reachable' } elseif ($reachDyn) { 'reachable-nonconstant-no-source' } elseif ($constOnly) { 'constant-only' } else { 'inconclusive' }
    $note = switch ($verdict) {
        'tainted-reachable'               { 'CONFIRMED-class: external input reaches a reachable sink -- the strongest deterministic signal; a submit_finding here is well grounded.' }
        'reachable-nonconstant-no-source' { 'reachable with a non-constant argument but NO external source proven -- possible injectable path; state the assumption in your rationale.' }
        'constant-only'                   { 'called with constant argument(s) only -- not injectable here; do NOT submit unless you can show attacker-controlled input.' }
        default                           { 'no conclusive taint signal from the deterministic engine.' }
    }
    return @{ method=$Method; verdict=$verdict; taintedSites=$tainted; siteCount=$sites.Count; sites=@($sites.ToArray()); note=$note }
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
        [int]$MaxSteps = 20,   # richer per-candidate flow (inspect -> taint -> callers -> submit) needs more room than the old 14
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
        'Process: (1) call list_sink_methods ONCE to get the candidate list -- each method shows a status (new / inspected / submitted). (2) inspect_method on a method whose status is NEW to read its IL and sinks. (3) GROUND it before submitting: call get_taint_trace for the deterministic verdict -- "tainted-reachable" means external input reaches a reachable sink (strongest evidence), "constant-only" means NOT injectable (do not submit); use get_callers to walk UP toward an entry point / event handler (attacker reachability) and get_callees to drill DOWN. (4) call submit_finding ONLY when the evidence supports it -- prefer methods whose get_taint_trace verdict is tainted-reachable (a vulnerability mentioned only in your summary does NOT count). NEVER inspect or submit the same method twice, and do NOT keep re-calling list_sink_methods. When remaining_new is 0 (every promising method reviewed), call finish. Be conservative: never invent a vulnerability.',
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
