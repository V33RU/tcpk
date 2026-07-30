function Get-TcpkAttackGraph {
<#
.SYNOPSIS
    R13. Build an ATTACK-PATH GRAPH from the findings: attacker -> entry point -> primitive(s)
    -> goal (RCE / SYSTEM / credential theft / data access). Emits the reachable goals as
    findings plus a Mermaid diagram of the whole graph.

.DESCRIPTION
    Where Get-TcpkExploitChains raises a few fixed 2-3 step correlations, this reasons over the
    full finding set as a graph. Each finding is bucketed into a node category by RuleId --
    ENTRY points (attacker-reachable input: URI/file handlers, exposed pipe/RPC/COM, WebView2
    navigation, network, weak renderer), PRIMITIVES (code-exec sinks, writable privileged
    binaries or load dirs, impactful token privileges, unsigned update, weak isolation, auth
    bypass, exposed secrets, weak crypto, and GhostTree scanner EVASION), and GOALS. A goal is
    REACHABLE when any of its recipes (sets of categories) are all present; the graph draws
    attacker -> entry -> primitive -> goal for each satisfied recipe.

    Output: one attackgraph.reachable-goal finding per reachable goal (at the goal's severity,
    Confidence Inferred -- a correlation to confirm), and one attackgraph.render INFO carrying
    a Mermaid flowchart of the graph. Reads no disk and runs nothing.

.PARAMETER Findings
    The audit findings ([TcpkFinding]).

.OUTPUTS
    [TcpkFinding] -- attackgraph.* findings.
#>
    [CmdletBinding()]
    param([Parameter(Mandatory, ValueFromPipeline)][TcpkFinding[]]$Findings)

    begin { $all = New-Object 'System.Collections.Generic.List[object]' }
    process { foreach ($f in $Findings) { if ($f) { $all.Add($f) } } }
    end {
        # node categories: role (entry|prim|evasion), a RuleId regex, a display label
        $cats = @(
            @{ Id = 'entry.protocol'; Role = 'entry'; Label = 'URI / file-type handler'; Rx = '^(msix\.protocol-handler|protocol-handler|protocol\.|msix\.file-type-association|deeplink)' }
            @{ Id = 'entry.web'; Role = 'entry'; Label = 'WebView2 loads external content'; Rx = '^webview2\.(nav-target|virtual-host-mapping|resource-request-filter)' }
            @{ Id = 'entry.renderer'; Role = 'entry'; Label = 'Weak renderer isolation'; Rx = '^electron\.(nodeIntegration|contextIsolation|insecure-default|webviewTag|bridge-exposes)' }
            @{ Id = 'entry.ipc'; Role = 'entry'; Label = 'Locally reachable IPC'; Rx = '^(pipe\.exists|pipe-dacl\.weak|rpc\.(server-interface|local-endpoint)|com\.(instantiable|method-surface))' }
            @{ Id = 'entry.network'; Role = 'entry'; Label = 'Network / backend reachable'; Rx = '^(intercept\.(endpoint-confirmed|cleartext)|pcap\.(cleartext-http|http-basic-cleartext|weak-tls)|endpoints\.|backend\.|tls\.)' }
            @{ Id = 'prim.codeexec'; Role = 'prim'; Label = 'Code-execution sink'; Rx = '^(callsites\.(command-execution|xaml-objectdataprovider-rce|path-traversal-build)|deser\.|reflection\.dynamic-load|electron\.ipc-handler-sink|protocol\.sink-reachable|api-trace\.(command-exec|process-launch))' }
            @{ Id = 'prim.privbin'; Role = 'prim'; Label = 'Writable privileged binary'; Rx = '^(service\.(writable-binary|weak-dacl|unquoted-path)|scheduled-task\.user-writable)' }
            @{ Id = 'prim.loaddir'; Role = 'prim'; Label = 'Writable load / trust dir'; Rx = '^(acl\.(programdata-user-writable|user-writable)|install-dir\.user-writable|path\.writable|dll-search|comhijack\.)' }
            @{ Id = 'prim.priv'; Role = 'prim'; Label = 'Impactful token privilege'; Rx = '^(process\.impactful-privileges|process\.running-as-system)' }
            @{ Id = 'prim.unsigned'; Role = 'prim'; Label = 'Unsigned update accepted'; Rx = '^update\.no-signature-verification' }
            @{ Id = 'prim.isolation'; Role = 'prim'; Label = 'Native<->web bridge exposed'; Rx = '^(webview2\.(add-host-object|are-host-objects-allowed|web-message-handler|script-injection)|electron\.(cert-validation-bypass|bridge-exposes))' }
            @{ Id = 'prim.authbypass'; Role = 'prim'; Label = 'Auth / authorization bypass'; Rx = '^(authflags|guiunlock|flagflip|jwt\.[a-z0-9-]*-accepted|jwt\.(alg-none-issued|weak-secret)|replay\.missing-authz|idor\.horizontal)' }
            @{ Id = 'prim.secret'; Role = 'prim'; Label = 'Exposed secret / key'; Rx = '^(jwt\.(embedded-token|weak-secret)|entropy\.|dpapi\.|browser\.master-key-recovered|token-cache\.|credman\.|exploit\.secret-recovered|api-trace\.(plaintext-secret-write|registry-secret-write))' }
            @{ Id = 'prim.evasion'; Role = 'evasion'; Label = 'GhostTree scanner evasion'; Rx = '^reparse\.recursive-junction' }
        )

        # which categories are present (>=1 finding, ignoring LIKELY-FP demotions)
        $present = @{}
        foreach ($cat in $cats) {
            foreach ($f in $all) {
                if ("$($f.Confidence)" -match 'Likely-FP') { continue }
                if ("$($f.RuleId)" -match $cat.Rx) { $present[$cat.Id] = $f; break }
            }
        }
        $catById = @{}; foreach ($c in $cats) { $catById[$c.Id] = $c }

        # goals: recipes are category-id sets; a goal is reachable if ANY recipe is fully present
        $goals = @(
            @{ Id = 'goal.rce'; Label = 'Code execution in the app'; Sev = 'CRITICAL'; Cwe = @('CWE-94'); Recipes = @(
                    @('entry.protocol', 'prim.codeexec'), @('entry.web', 'prim.codeexec'), @('entry.renderer', 'prim.codeexec'),
                    @('entry.network', 'prim.codeexec'), @('entry.ipc', 'prim.codeexec'),
                    @('prim.loaddir', 'prim.unsigned'), @('prim.loaddir', 'prim.evasion'), @('prim.isolation', 'prim.codeexec')
                ) }
            @{ Id = 'goal.system'; Label = 'Local privilege escalation to SYSTEM'; Sev = 'CRITICAL'; Cwe = @('CWE-269'); Recipes = @(
                    @('prim.privbin'), @('prim.priv', 'prim.codeexec'), @('prim.priv', 'entry.ipc'), @('prim.privbin', 'prim.priv')
                ) }
            @{ Id = 'goal.credtheft'; Label = 'Credential / session theft'; Sev = 'HIGH'; Cwe = @('CWE-522'); Recipes = @(
                    @('prim.secret', 'entry.network'), @('prim.authbypass', 'entry.network')
                ) }
            @{ Id = 'goal.data'; Label = "Access another user's data"; Sev = 'HIGH'; Cwe = @('CWE-639'); Recipes = @(
                    @('prim.authbypass', 'entry.network')
                ) }
        )

        $edges = New-Object System.Collections.Generic.List[string]
        $edgeSet = New-Object 'System.Collections.Generic.HashSet[string]'
        $nodes = @{}
        function _nid([string]$id) { 'n_' + ($id -replace '[^A-Za-z0-9]', '_') }
        $addEdge = {
            param($from, $to, $dashed, $label)
            $key = "$from>$to"
            if (-not $edgeSet.Add($key)) { return }
            $arrow = if ($dashed) { '-.->|' + $label + '|' } elseif ($label) { '-->|' + $label + '|' } else { '-->' }
            $edges.Add("  $(_nid $from) $arrow $(_nid $to)")
        }

        $out = New-Object System.Collections.Generic.List[object]
        $anyGoal = $false
        foreach ($g in $goals) {
            $satisfied = @($g.Recipes | Where-Object { $r = $_; @($r | Where-Object { $present.ContainsKey($_) }).Count -eq @($r).Count })
            if (-not $satisfied.Count) { continue }
            $anyGoal = $true
            $nodes['ATTACKER'] = @{ Shape = 'stadium'; Label = 'Attacker' }
            $nodes[$g.Id] = @{ Shape = 'hex'; Label = $g.Label }
            $contrib = New-Object 'System.Collections.Generic.HashSet[string]'
            foreach ($r in $satisfied) {
                $entries = @($r | Where-Object { $catById[$_].Role -eq 'entry' })
                $prims = @($r | Where-Object { $catById[$_].Role -eq 'prim' })
                $evas = @($r | Where-Object { $catById[$_].Role -eq 'evasion' })
                foreach ($c in $r) {
                    [void]$contrib.Add($c)
                    $shape = if ($catById[$c].Role -eq 'evasion') { 'evasion' } else { 'rect' }
                    $nodes[$c] = @{ Shape = $shape; Label = $catById[$c].Label }
                }
                if ($entries.Count) {
                    foreach ($e in $entries) { & $addEdge 'ATTACKER' $e $false $null; foreach ($p in $prims) { & $addEdge $e $p $false $null } }
                } else {
                    foreach ($p in $prims) { & $addEdge 'ATTACKER' $p $false 'local' }
                }
                foreach ($p in $prims) { & $addEdge $p $g.Id $false $null }
                foreach ($ev in $evas) { foreach ($p in $prims) { & $addEdge $ev $p $true 'hides' } }
            }
            $names = @($contrib | ForEach-Object { $catById[$_].Label })
            $out.Add((New-TcpkFinding -Module 'chain' -RuleId 'attackgraph.reachable-goal' -Severity $g.Sev `
                    -Confidence 'Inferred' -Cwe ([string[]]$g.Cwe) `
                    -Title "Attack path reaches: $($g.Label)" `
                    -Evidence ("via " + ($names -join ' + ')) `
                    -Description ("The findings form a path to '$($g.Label)': " + ($names -join ' -> ') + ".`r`nThis is a correlation across the finding set (attack-path graph); confirm each link end to end. See the attackgraph.render diagram for the full graph.")))
        }

        if (-not $anyGoal) {
            $out.Add((New-TcpkFinding -Module 'chain' -RuleId 'attackgraph.no-path' -Severity 'INFO' -Confidence 'Inferred' `
                    -Title 'No end-to-end attack path correlated' `
                    -Description 'No goal recipe was fully satisfied by the current findings. Individual findings may still matter; this only means no complete entry->primitive->goal path was assembled.'))
            return $out.ToArray()
        }

        # render Mermaid
        $lines = New-Object System.Collections.Generic.List[string]
        $lines.Add('flowchart LR')
        foreach ($k in $nodes.Keys) {
            $n = $nodes[$k]; $id = _nid $k; $lbl = ($n.Label -replace '"', "'")
            switch ($n.Shape) {
                'stadium' { $lines.Add("  $id([`"$lbl`"])") }
                'hex' { $lines.Add("  $id{{`"$lbl`"}}") }
                'evasion' { $lines.Add("  $id[/`"$lbl`"/]") }
                default { $lines.Add("  $id[`"$lbl`"]") }
            }
        }
        foreach ($e in $edges) { $lines.Add($e) }
        $mermaid = ($lines -join "`r`n")

        $out.Add((New-TcpkFinding -Module 'chain' -RuleId 'attackgraph.render' -Severity 'INFO' -Confidence 'Inferred' `
                -Title 'Attack-path graph (Mermaid)' `
                -Evidence "$($nodes.Count) node(s), $($edges.Count) edge(s)" `
                -Description ("Attack-path graph as a Mermaid flowchart (paste into any Mermaid renderer):`r`n`r`n``````mermaid`r`n$mermaid`r`n``````")))

        return $out.ToArray()
    }
}
