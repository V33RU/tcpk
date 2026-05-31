function Get-TcpkAttackSurface {
<#
.SYNOPSIS
    R11. Synthesize a ranked attack-surface map from audit findings.

.DESCRIPTION
    Aggregates the full finding set into entry-point CATEGORIES (the ways an
    attacker can reach the app: URI/protocol handlers, file associations, IPC
    pipes/COM/RPC, network listeners, inbound firewall, web bridges, native
    exports, command-line, auth/trust surface). Each category is scored by a
    base weight x the worst severity it contains, and the categories are ranked.

    This is a triage artifact: one view of "where can I knock on this app", with
    the count and worst severity per door. Returned as an object; the audit also
    writes it to attack-surface.json.

.PARAMETER Findings
    The [TcpkFinding] set from an audit.

.OUTPUTS
    [pscustomobject] with TotalEntryPoints + ranked Categories.
#>
    [CmdletBinding()]
    param([Parameter(Mandatory, ValueFromPipeline)][TcpkFinding[]]$Findings)

    begin { $all = New-Object 'System.Collections.Generic.List[object]' }
    process { foreach ($f in $Findings) { $all.Add($f) } }
    end {
        $cats = @(
            @{ Key='uri-protocols';   Label='URI / protocol handlers';   Rx='protocol|uri[-.]scheme|msixprotocol';            W=8 }
            @{ Key='file-assoc';      Label='File associations';         Rx='fileassoc|file-assoc|msixfileassoc';              W=5 }
            @{ Key='ipc-pipes';       Label='Named pipes';               Rx='namedpipe|^.*\bpipe';                             W=7 }
            @{ Key='ipc-com';         Label='COM / DCOM servers';        Rx='comobject|comserver|comhijack|msixcom';           W=7 }
            @{ Key='ipc-rpc';         Label='RPC surface';               Rx='rpcsurface|rpc\.';                                W=7 }
            @{ Key='ipc-other';       Label='Mailslots / ALPC / objects';Rx='mailslot|alpc|namedobject';                       W=5 }
            @{ Key='net-listen';      Label='Network listeners';         Rx='listeningport|selfhost';                          W=9 }
            @{ Key='net-firewall';    Label='Inbound firewall rules';    Rx='firewall.inbound';                                W=8 }
            @{ Key='web-bridge';      Label='WebView2 / web bridges';    Rx='wv2|webview';                                     W=7 }
            @{ Key='native-exports';  Label='Native export surface';     Rx='pe-exports';                                      W=4 }
            @{ Key='cmdline';         Label='Command-line / debug flags';Rx='debugflags|commandline';                          W=6 }
            @{ Key='auth-trust';      Label='Auth / trust surface';      Rx='authflags|truststore|uac';                        W=6 }
            @{ Key='update';          Label='Update / supply chain';     Rx='updateflow|poisonedupdate';                       W=8 }
        )
        $sevRank = @{ INFO=0; LOW=1; MEDIUM=2; HIGH=3; CRITICAL=4 }

        $result = @()
        $total = 0
        foreach ($c in $cats) {
            $items = @()
            $seen = @{}
            foreach ($f in $all) {
                if ($f.RuleId -notmatch $c.Rx) { continue }
                $k = "$($f.RuleId)::$($f.File)"
                if ($seen.ContainsKey($k)) { continue }
                $seen[$k] = $true
                $items += [pscustomobject]@{ Title=$f.Title; File=$f.File; Severity=$f.Severity; RuleId=$f.RuleId }
            }
            if ($items.Count -eq 0) { continue }
            $worst = ($items | ForEach-Object { $sevRank[$_.Severity] } | Measure-Object -Maximum).Maximum
            $worstSev = ($sevRank.GetEnumerator() | Where-Object { $_.Value -eq $worst } | Select-Object -First 1).Key
            $risk = $c.W * (1 + $worst)
            $total += $items.Count
            $result += [pscustomobject]@{
                Key         = $c.Key
                Label       = $c.Label
                Count       = $items.Count
                WorstSeverity = $worstSev
                Risk        = $risk
                Items       = @($items | Sort-Object @{E={$sevRank[$_.Severity]};Descending=$true} | Select-Object -First 12)
            }
        }
        $result = @($result | Sort-Object Risk -Descending)

        [pscustomobject]@{
            GeneratedUtc     = (Get-Date).ToUniversalTime().ToString('u')
            TotalEntryPoints = $total
            CategoryCount    = $result.Count
            Categories       = $result
        }
    }
}
