function Export-TcpkReportHtml {
<#
.SYNOPSIS
    Export TCPK findings as a self-contained, interactive HTML report.

.DESCRIPTION
    Single-file HTML report. No external resources, no CDN, works offline.
    Features:
      - Target / tech-stack / attack-surface header card (from -Profile)
      - Severity bar chart + summary
      - Live search box, severity filter chips, expand/collapse all
      - Rule-summary table (group-by-rule) with click-to-filter
      - Collapsible per-severity sections; each finding numbered (#001..)
      - CVE-match table (NVD links + KEV badges) -- parity with Excel CVEs sheet
      - DLL exploit-mitigation matrix -- parity with Excel DLL Hardening sheet
      - SBOM component inventory (name, version, publisher, SHA-256, full path)
      - Print stylesheet

.PARAMETER Findings
    Pipeline of [TcpkFinding] objects.

.PARAMETER OutFile
    Path to write to.

.PARAMETER Target
    Optional target string for the report header (fallback if no -Profile).

.PARAMETER Profile
    Optional [pscustomobject] from Get-TcpkTargetProfile. Drives the header card.

.PARAMETER Scope
    Optional [hashtable]/[pscustomobject] with audit-scope info:
    Buckets, Llm, Timing (all strings). Rendered in the card footer.

.PARAMETER CveMatches
    Optional Get-TcpkCveMatches output. Rendered as a dedicated CVE table so the
    HTML report carries the same component-CVE data as the Excel CVEs sheet.

.PARAMETER Hardening
    Optional Get-TcpkPeHardening output (per-DLL ASLR/DEP/CFG/... matrix).
    Rendered as a hardening matrix so the HTML matches the Excel DLL Hardening sheet.

.PARAMETER Sbom
    Optional Get-TcpkSbomComponents output (shipped PE inventory). Rendered as a
    software bill-of-materials table (name, version, publisher, SHA-256, full path)
    so the HTML carries the same component inventory as the sbom.cdx.json / Excel.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)][TcpkFinding[]]$Findings,
        [Parameter(Mandatory)][string]$OutFile,
        [string]$Target = '',
        [object]$Profile = $null,
        [object]$Scope = $null,
        [object[]]$CveMatches = @(),
        [object[]]$Hardening = @(),
        [object[]]$Signing = @(),
        [object[]]$Sbom = @(),
        # whether the online CVE lookup actually ran (so the empty state can say "checked, 0 found"
        # vs "not checked"). CVE matching is online-only, so a 0-result run must be distinguishable.
        [bool]$CveChecked = $true
    )

    begin { $all = New-Object 'System.Collections.Generic.List[object]' }
    process { foreach ($f in $Findings) { $all.Add($f) } }
    end {
        $sevOrder = @('CRITICAL','HIGH','MEDIUM','LOW','INFO')
        $sevColor = @{ CRITICAL='#f85149'; HIGH='#db6d28'; MEDIUM='#d29922'; LOW='#3fb950'; INFO='#6a7585' }
        # Confidence colours. The proven tiers (IL / dynamic / Confirmed) get strong green/blue so
        # they POP; Inferred is amber (means: verify manually); Likely-FP / Uncertain / Skipped are
        # muted grey/red. NOTE: 'Confirmed (IL)', 'Confirmed (dynamic)' and 'Likely-FP (IL)' were
        # MISSING here and fell through to the default grey -- so the flagship IL-proven findings
        # were visually indistinguishable from INFO/Skipped. That is fixed below.
        $confColor = @{
            'Confirmed (exploit)'='#f85149'; 'Confirmed (IL)'='#2ea043'; 'Confirmed (dynamic)'='#1f9c8a'; 'Confirmed'='#388bfd'; 'Confirmed (LLM)'='#58a6ff'
            'Inferred'='#d29922'; 'Unverified'='#bb8009'
            'Likely-FP (IL)'='#6a7585'; 'Likely-FP (LLM)'='#da3633'; 'Uncertain (LLM)'='#a371f7'
            'Skipped'='#6a7585'
        }
        $esc = { param($t) ConvertTo-TcpkHtmlSafe $t }

        # Split internal process/meta notes ([TCPK ...] / [LLM ...]) out of a Description so
        # the card shows a clean explanation and the meta-noise drops to a muted footer
        # instead of polluting the "What" text (the #013 complaint).
        function _SplitNotes {
            param([string]$Desc)
            $d = "$Desc"
            $rx = '\s*\[(?:TCPK|LLM)\b[^\]]*\]'
            $notes = @([regex]::Matches($d, $rx) | ForEach-Object { $_.Value.Trim() })
            $clean = ([regex]::Replace($d, $rx, '')).Trim()
            return [pscustomobject]@{ Clean = $clean; Notes = $notes }
        }
        # One honest sentence on WHY this finding sits at its confidence tier (proof vs lead).
        function _WhyHere {
            param([string]$Confidence)
            switch -Regex ("$Confidence") {
                'Confirmed \(IL\)'      { 'Proven by IL analysis: the flagged sink is reachable and, where applicable, reached by tainted/external input.'; break }
                'Confirmed \(dynamic\)' { 'Proven dynamically: TCPK observed the behaviour at runtime against a controlled harness.'; break }
                'Confirmed \(LLM\)'     { 'An LLM reviewed the decompiled method and judged this a real issue (model-assisted -- still verify).'; break }
                'Likely-FP'             { 'A verifier judged this a likely false positive; kept for transparency at reduced confidence.'; break }
                'Uncertain'             { 'A verifier could not decide; treat this as a lead and confirm manually.'; break }
                '^Confirmed$'           { 'Deterministically confirmed by the check (no heuristic).'; break }
                default                 { 'Pattern/heuristic match in a first-party binary; not proven by IL or dynamic analysis -- verify manually.'; break }
            }
        }

        $generatedAt = (Get-Date).ToUniversalTime().ToString('u')

        # severity counts
        $sevCounts = @{}
        foreach ($s in $sevOrder) { $sevCounts[$s] = ($all | Where-Object Severity -eq $s).Count }
        $maxCount = ($sevCounts.Values | Measure-Object -Maximum).Maximum
        if (-not $maxCount -or $maxCount -lt 1) { $maxCount = 1 }

        # evidence-tier rollup (honest confidence summary -- so a reader does not treat an Inferred
        # string-scan hit the same as an IL-proven one). Proven = IL or dynamic; Confirmed = other
        # Confirmed tiers; Inferred = unverified heuristic; Weak = Likely-FP / Uncertain.
        $confProven    = @($all | Where-Object { "$($_.Confidence)" -like 'Confirmed (IL)*' -or "$($_.Confidence)" -like 'Confirmed (dynamic)*' -or "$($_.Confidence)" -like 'Confirmed (exploit)*' }).Count
        $confConfirmed = @($all | Where-Object { "$($_.Confidence)" -like 'Confirmed*' -and "$($_.Confidence)" -notlike 'Confirmed (IL)*' -and "$($_.Confidence)" -notlike 'Confirmed (dynamic)*' -and "$($_.Confidence)" -notlike 'Confirmed (exploit)*' }).Count
        $confInferred  = @($all | Where-Object { "$($_.Confidence)" -eq 'Inferred' -or "$($_.Confidence)" -eq 'Unverified' }).Count
        $confWeak      = @($all | Where-Object { "$($_.Confidence)" -like 'Likely-FP*' -or "$($_.Confidence)" -like 'Uncertain*' }).Count
        $confSummaryHtml = @"
<section class='card confsum'>
  <div class='confgrid'>
    <div class='cmetric'><span class='cmlabel'>Proven (IL/dynamic)</span><span class='cmval' style='color:#3fb950'>$confProven</span></div>
    <div class='cmetric'><span class='cmlabel'>Confirmed</span><span class='cmval' style='color:#58a6ff'>$confConfirmed</span></div>
    <div class='cmetric'><span class='cmlabel'>Inferred -- verify</span><span class='cmval' style='color:#d29922'>$confInferred</span></div>
    <div class='cmetric'><span class='cmlabel'>Likely-FP / Uncertain</span><span class='cmval' style='color:#8b949e'>$confWeak</span></div>
  </div>
</section>
"@

        # ---------------- executive summary narrative (always-on) ----------------
        # Lead the report with the story, not a table: what was audited, the severity shape,
        # how much is proven vs needs manual verification, whether correlated attack paths
        # exist, and the few findings that matter most.
        $execTarget = if ($Profile -and $Profile.Name) { ConvertTo-TcpkHtmlSafe ([string]$Profile.Name) } elseif ($Target) { ConvertTo-TcpkHtmlSafe ([string]$Target) } else { 'the target' }
        $sevPhrase = (@(foreach ($s in $sevOrder) { if ($sevCounts[$s] -gt 0) { "$($sevCounts[$s]) $($s.ToLower())" } }) -join ', ')
        if (-not $sevPhrase) { $sevPhrase = 'no' }
        $evidBits = @()
        if ($confProven    -gt 0) { $evidBits += "$confProven proven by IL/dynamic analysis" }
        if ($confConfirmed -gt 0) { $evidBits += "$confConfirmed confirmed" }
        if ($confInferred  -gt 0) { $evidBits += "$confInferred to verify manually" }
        $evidPhrase = if ($evidBits.Count) { ' Evidence grade: ' + ($evidBits -join '; ') + '.' } else { '' }
        $chainCount = @($all | Where-Object { "$($_.RuleId)" -like 'chain.*' -or "$($_.Module)" -eq 'chain' }).Count
        $chainPhrase = if ($chainCount -gt 0) { " $chainCount correlated attack path$(if ($chainCount -ne 1){'s'}) identified (see Likely attack paths below)." } else { '' }
        $topF = @($all | Where-Object { "$($_.Severity)" -in 'CRITICAL','HIGH' } | Sort-Object @{ E = { Get-TcpkSeverityRank $_.Severity }; Descending = $true } | Select-Object -First 3)
        $topPhrase = if ($topF.Count) { ' Most significant: ' + (($topF | ForEach-Object { ConvertTo-TcpkHtmlSafe ([string]$_.Title) }) -join '; ') + '.' } else { '' }
        $execSummaryHtml = "<section class='card execsum'><h3 class='exechead'>Executive summary</h3><p class='exectext'>This audit of <b>$execTarget</b> produced <b>$($all.Count)</b> finding$(if ($all.Count -ne 1){'s'}) ($sevPhrase).$evidPhrase$chainPhrase$topPhrase</p></section>"

        # ---------------- header card ----------------
        $cardHtml = ''
        if ($Profile) {
            $p = $Profile
            $sig = $p.Signature
            $rowsKv = New-Object 'System.Collections.Generic.List[string]'
            function _kv($k,$v) { if ($v) { return ("<div class='kvi'><span class='k'>{0}</span><span class='v'>{1}</span></div>" -f (ConvertTo-TcpkHtmlSafe $k), (ConvertTo-TcpkHtmlSafe ([string]$v))) } return '' }
            $rowsKv.Add( (_kv 'Application'  $p.Name) )
            $rowsKv.Add( (_kv 'Version'      $p.Version) )
            $rowsKv.Add( (_kv 'Publisher'    $p.Publisher) )
            $rowsKv.Add( (_kv 'Architecture' $p.Architecture) )
            $rowsKv.Add( (_kv 'Type'         $p.AppType) )
            $rowsKv.Add( (_kv 'Main exe'     $p.MainExecutable) )
            $rowsKv.Add( (_kv 'Runtime'      ($p.Runtime + $(if ($p.RuntimeDetail) { "  ($($p.RuntimeDetail))" } else { '' }))) )
            $rowsKv.Add( (_kv 'Privilege'    $p.PrivilegeModel) )
            if ($p.PackageFullName) { $rowsKv.Add( (_kv 'Package' $p.PackageFullName) ) }
            $rowsKv.Add( (_kv 'Install'      $p.InstallPath) )
            # signature line
            $sigText = "$($sig.Status)"
            if ($sig.Subject)  { $sigText += " -- $($sig.Subject)" }
            if ($sig.NotAfter) { $sigText += " (expires $($sig.NotAfter)" + $(if ($sig.KeySize) { ", $($sig.KeySize)-bit" } else { '' }) + ")" }
            $rowsKv.Add( (_kv 'Signing'      $sigText) )

            # stack badges
            function _badges($label,$arr,$cls) {
                if (-not $arr -or @($arr).Count -eq 0) { return '' }
                $b = ($arr | ForEach-Object { "<span class='tag $cls'>" + (ConvertTo-TcpkHtmlSafe ([string]$_)) + "</span>" }) -join ''
                return "<div class='stackrow'><span class='stacklabel'>$label</span>$b</div>"
            }
            $stackHtml = (_badges 'UI'       $p.UiFrameworks    'tag-ui') +
                         (_badges 'Network'  $p.NetworkProtocols 'tag-net') +
                         (_badges 'Update'   $p.UpdateMechanism  'tag-upd')
            if ($p.ThirdPartySdks -and @($p.ThirdPartySdks).Count -gt 0) {
                $sdkTags = ($p.ThirdPartySdks | ForEach-Object {
                    $t = $_.Name
                    if ($_.Version) { $t = "$($_.Name) $($_.Version)" }
                    "<span class='tag tag-sdk'>" + (ConvertTo-TcpkHtmlSafe ([string]$t)) + "</span>"
                }) -join ''
                $stackHtml += "<div class='stackrow'><span class='stacklabel'>SDKs</span>$sdkTags</div>"
            }

            # attack-surface tiles
            $c = $p.Counts
            $tiles = @(
                @('DLLs',$c.Dll), @('EXEs',$c.Exe), @('Drivers',$c.Sys),
                @('Endpoints',$c.Endpoint), @('Ports',$c.Port), @('COM',$c.Com),
                @('Pipes',$c.Pipe), @('Services',$c.Service),
                @('Handlers',$c.ProtocolHandler), @('File-assoc',$c.FileAssoc)
            )
            $surfHtml = ($tiles | ForEach-Object {
                "<div class='surf'><b>$($_[1])</b><span>$($_[0])</span></div>"
            }) -join ''

            # scope footer
            $scopeHtml = ''
            if ($Scope) {
                $parts = New-Object 'System.Collections.Generic.List[string]'
                if ($Scope.Llm)     { $parts.Add("<b>LLM:</b> "     + (ConvertTo-TcpkHtmlSafe ([string]$Scope.Llm))) }
                if ($Scope.Timing)  { $parts.Add("<b>Time:</b> "    + (ConvertTo-TcpkHtmlSafe ([string]$Scope.Timing))) }
                if ($Scope.PSObject.Properties['Coverage'] -and $Scope.Coverage) {
                    $parts.Add("<b>Coverage:</b> " + (ConvertTo-TcpkHtmlSafe ([string]$Scope.Coverage)))
                }
                if ($parts.Count) { $scopeHtml = "<div class='scope'>" + ($parts -join '  &middot;  ') + "</div>" }
            }

            $cardHtml = @"
<section class='card target'>
  <div class='kvgrid'>
$($rowsKv -join "`n")
  </div>
  <div class='stack'>$stackHtml</div>
  <div class='surfrow'>$surfHtml</div>
  $scopeHtml
</section>
"@
        } else {
            $cardHtml = "<section class='card target'><div class='kvgrid'><div class='kvi'><span class='k'>Target</span><span class='v'>$(ConvertTo-TcpkHtmlSafe $Target)</span></div></div></section>"
        }

        # ---------------- detailed recon section ----------------
        $reconHtml = ''
        if ($Profile) {
            $p = $Profile
            # helper: build a sub-table; $rows is array of html <tr>..., $cols is header cells
            function _reconTable($title, $headerCells, $rows, $emptyNote) {
                $body = if ($rows -and @($rows).Count -gt 0) {
                    "<table class='recontab'><thead><tr>$headerCells</tr></thead><tbody>" + ($rows -join "`n") + "</tbody></table>"
                } else {
                    "<div class='emptynote'>$([string](ConvertTo-TcpkHtmlSafe $emptyNote))</div>"
                }
                return "<div class='reconblock'><h4>$([string](ConvertTo-TcpkHtmlSafe $title))</h4>$body</div>"
            }

            # Network endpoints
            $epRows = foreach ($e in $p.Endpoints) {
                "<tr><td><code>$(ConvertTo-TcpkHtmlSafe $e.Host)</code></td><td>$(ConvertTo-TcpkHtmlSafe $e.Detail)</td><td>$(ConvertTo-TcpkHtmlSafe $e.File)</td></tr>"
            }
            $epTable = _reconTable 'Network endpoints (backend hosts)' '<th>Host</th><th>Sample URL / auth markers</th><th>First seen in</th>' $epRows 'No outbound backend hosts found in first-party binaries.'

            # Listening ports
            $portRows = foreach ($lp in $p.ListeningPorts) {
                $sc = $sevColor[$lp.Severity]
                "<tr><td>$(ConvertTo-TcpkHtmlSafe $lp.Proto)</td><td><code>$(ConvertTo-TcpkHtmlSafe $lp.Endpoint)</code></td><td>$(ConvertTo-TcpkHtmlSafe $lp.Scope)</td><td><span class='badge' style='background:$sc'>$($lp.Severity)</span></td></tr>"
            }
            $portTable = _reconTable 'Listening ports (live process)' '<th>Proto</th><th>Bind</th><th>Scope</th><th>Severity</th>' $portRows 'No listening ports observed. (Live-port scan only runs when a ProcessName is supplied AND the app is running.)'

            # Protocol handlers
            $phRows = foreach ($h in $p.ProtocolHandlers) { "<tr><td>$(ConvertTo-TcpkHtmlSafe $h.Title)</td><td><code>$(ConvertTo-TcpkHtmlSafe $h.Detail)</code></td></tr>" }
            $phTable = if (@($p.ProtocolHandlers).Count) { _reconTable 'Custom protocol handlers (URI schemes)' '<th>Handler</th><th>Detail</th>' $phRows '' } else { '' }

            # COM servers
            $comRows = foreach ($cS in $p.ComServers) { "<tr><td>$(ConvertTo-TcpkHtmlSafe $cS.Title)</td><td><code>$(ConvertTo-TcpkHtmlSafe $cS.Detail)</code></td></tr>" }
            $comTable = if (@($p.ComServers).Count) { _reconTable 'COM servers (cross-process activation)' '<th>CLSID / server</th><th>Detail</th>' $comRows '' } else { '' }

            # Named pipes
            $pipeRows = foreach ($pp in $p.NamedPipes) { "<tr><td>$(ConvertTo-TcpkHtmlSafe $pp.Title)</td><td><code>$(ConvertTo-TcpkHtmlSafe $pp.Detail)</code></td></tr>" }
            $pipeTable = if (@($p.NamedPipes).Count) { _reconTable 'Named pipes (local IPC)' '<th>Pipe</th><th>Detail</th>' $pipeRows '' } else { '' }

            # File associations
            $faRows = foreach ($fa in $p.FileAssociations) { "<tr><td>$(ConvertTo-TcpkHtmlSafe $fa.Title)</td><td><code>$(ConvertTo-TcpkHtmlSafe $fa.Detail)</code></td></tr>" }
            $faTable = if (@($p.FileAssociations).Count) { _reconTable 'File-type associations' '<th>Association</th><th>Detail</th>' $faRows '' } else { '' }

            # Update URLs + non-prod + TLS posture as bullet lists
            $extraBlocks = ''
            if (@($p.UpdateUrls).Count) {
                $items = ($p.UpdateUrls | ForEach-Object { "<li><code>$(ConvertTo-TcpkHtmlSafe ([string]$_))</code></li>" }) -join ''
                $extraBlocks += "<div class='reconblock'><h4>Update URLs</h4><ul class='reconlist'>$items</ul></div>"
            }
            if (@($p.NonProdEndpoints).Count) {
                $items = ($p.NonProdEndpoints | ForEach-Object { "<li><code>$(ConvertTo-TcpkHtmlSafe ([string]$_))</code></li>" }) -join ''
                $extraBlocks += "<div class='reconblock'><h4>Non-production / environment-specific endpoint markers</h4><ul class='reconlist'>$items</ul></div>"
            }
            if (@($p.TlsPosture).Count) {
                $items = ($p.TlsPosture | ForEach-Object { "<li>$(ConvertTo-TcpkHtmlSafe ([string]$_))</li>" }) -join ''
                $extraBlocks += "<div class='reconblock'><h4>Transport security posture</h4><ul class='reconlist'>$items</ul></div>"
            }

            $reconHtml = @"
<section class='card recon'>
  <h3 class='reconhead'><span class='caret'>&#9662;</span>Reconnaissance -- Network &amp; Attack Surface</h3>
  <div class='reconbody'>
    $epTable
    $portTable
    $phTable
    $comTable
    $pipeTable
    $faTable
    $extraBlocks
  </div>
</section>
"@
        }

        # ---------------- dashboard: risk gauge + severity donut ----------------
        # The flat bar chart is replaced by an SVG risk gauge + severity donut (computed from the
        # real counts). Risk is a transparent weighted aggregate of finding severities (0-100).
        $risk = [int][math]::Min(100, ($sevCounts['CRITICAL']*45 + $sevCounts['HIGH']*18 + $sevCounts['MEDIUM']*6 + $sevCounts['LOW']*2))
        if     ($risk -ge 80) { $gaugeColor = $sevColor['CRITICAL']; $bandLabel = 'CRITICAL' }
        elseif ($risk -ge 55) { $gaugeColor = $sevColor['HIGH'];     $bandLabel = 'HIGH' }
        elseif ($risk -ge 30) { $gaugeColor = $sevColor['MEDIUM'];   $bandLabel = 'MEDIUM' }
        elseif ($risk -ge 10) { $gaugeColor = $sevColor['LOW'];      $bandLabel = 'LOW' }
        else                  { $gaugeColor = $sevColor['INFO'];     $bandLabel = 'MINIMAL' }
        $rc = 314.159
        $gaugeDash = '{0:0.0} {1:0.0}' -f (($risk / 100.0) * $rc), $rc

        $C = 263.894; $total = [double]$all.Count
        $donutSegs = ''
        if ($total -gt 0) {
            $cum = 0.0
            foreach ($s in $sevOrder) {
                $cnt = $sevCounts[$s]; if ($cnt -le 0) { continue }
                $len = ($cnt / $total) * $C
                $donutSegs += ("<circle cx='60' cy='60' r='42' fill='none' stroke='$($sevColor[$s])' stroke-width='16' stroke-dasharray='{0:0.00} {1:0.00}' stroke-dashoffset='{2:0.00}'/>" -f $len, ($C - $len), (-$cum))
                $cum += $len
            }
        } else {
            $donutSegs = "<circle cx='60' cy='60' r='42' fill='none' stroke='#242c3a' stroke-width='16'/>"
        }
        $legendParts = foreach ($s in $sevOrder) { if ($sevCounts[$s] -gt 0) { "<span><i style='background:$($sevColor[$s])'></i>$($s.Substring(0,1))$($s.Substring(1).ToLower()) <b>$($sevCounts[$s])</b></span>" } }
        $donutLegend = ($legendParts -join '')
        if (-not $donutLegend) { $donutLegend = "<span class='muted'>no findings</span>" }

        $chartHtml = @"
<section class='card dash'>
  <div class='dashgrid'>
    <div class='dcell'>
      <h4>RISK INDEX</h4>
      <div class='gaugewrap'>
        <svg width='128' height='128' viewBox='0 0 120 120'>
          <defs><linearGradient id='tcpkrg' x1='0' y1='0' x2='1' y2='1'><stop offset='0' stop-color='#3fb950'/><stop offset='.55' stop-color='#d29922'/><stop offset='1' stop-color='#f85149'/></linearGradient></defs>
          <circle cx='60' cy='60' r='50' fill='none' stroke='#1b2230' stroke-width='11'/>
          <circle cx='60' cy='60' r='50' fill='none' stroke='url(#tcpkrg)' stroke-width='11' stroke-linecap='round' stroke-dasharray='$gaugeDash' transform='rotate(-90 60 60)'/>
          <text x='60' y='56' text-anchor='middle' fill='#e6edf3' style='font:700 30px "Cascadia Code","Fira Code",Consolas,monospace'>$risk</text>
          <text x='60' y='77' text-anchor='middle' fill='$gaugeColor' style='font:700 10px "Cascadia Code","Fira Code",Consolas,monospace'>$bandLabel</text>
        </svg>
      </div>
    </div>
    <div class='dcell'>
      <h4>SEVERITY ($($all.Count))</h4>
      <div class='donutwrap'>
        <svg width='118' height='118' viewBox='0 0 120 120'>
          <g transform='rotate(-90 60 60)'>$donutSegs</g>
          <text x='60' y='57' text-anchor='middle' fill='#e6edf3' style='font:700 24px "Cascadia Code","Fira Code",Consolas,monospace'>$($all.Count)</text>
          <text x='60' y='75' text-anchor='middle' fill='#8b949e' style='font:9px "Cascadia Code","Fira Code",Consolas,monospace'>findings</text>
        </svg>
      </div>
      <div class='dleg'>$donutLegend</div>
    </div>
  </div>
</section>
"@ + $confSummaryHtml

        # ---------------- attack-path callout (correlated exploit chains) ----------------
        # chain.* findings (from Get-TcpkExploitChains) are already raised above their parts;
        # surface them as a prominent banner so the report LEADS with the attack narrative
        # instead of leaving the reader to correlate scattered findings by hand.
        $attackPathHtml = ''
        $chainF = @($all | Where-Object { "$($_.RuleId)" -like 'chain.*' -or "$($_.Module)" -eq 'chain' })
        if ($chainF.Count) {
            $apItems = foreach ($cf in ($chainF | Sort-Object @{ E = { Get-TcpkSeverityRank $_.Severity }; Descending = $true })) {
                $sc = if ($sevColor.ContainsKey("$($cf.Severity)")) { $sevColor["$($cf.Severity)"] } else { '#566573' }
                $fixLine = if ($cf.Fix) { "<div class='apath-fix'>" + (ConvertTo-TcpkHtmlSafe ([string]$cf.Fix)) + "</div>" } else { '' }
                "<div class='apath-item'><div class='apath-top'><span class='badge' style='background:$sc'>$($cf.Severity)</span> <span class='apath-title'>$(ConvertTo-TcpkHtmlSafe ([string]$cf.Title))</span></div>$fixLine</div>"
            }
            $attackPathHtml = @"
<section class='card apath'>
  <h3 class='apathhead'><span class='caret'>&#9662;</span>Likely attack paths <span class='seccount'>($($chainF.Count) correlated $(if ($chainF.Count -eq 1) { 'chain' } else { 'chains' }))</span></h3>
  <div class='apathbody'>
$($apItems -join "`n")
  </div>
</section>
"@
        }

        # ---------------- CVE matches (parity with Excel CVEs sheet) ----------------
        $cveHtml = ''
        if ($CveMatches -and @($CveMatches).Count) {
            $statusColor = @{
                'Vulnerable'='#9b0000'; 'Present'='#d68910'; 'PossiblyEmbedded'='#b9770e'
                'Patched'='#117a65'
            }
            $cveSorted = @($CveMatches)
            $cveRows = foreach ($c in $cveSorted) {
                $sc   = if ($c.Severity -and $sevColor.ContainsKey("$($c.Severity)")) { $sevColor["$($c.Severity)"] } else { '#566573' }
                $stc  = if ($c.Status -and $statusColor.ContainsKey("$($c.Status)")) { $statusColor["$($c.Status)"] } else { '#566573' }
                $cveId = ConvertTo-TcpkHtmlSafe ([string]$c.Cve)
                # link out to NVD for real CVE ids; leave plain otherwise
                $cveCell = if ([string]$c.Cve -match '^(?i)CVE-\d{4}-\d+$') {
                    "<a href='https://nvd.nist.gov/vuln/detail/$cveId' target='_blank' rel='noopener'><code>$cveId</code></a>"
                } else { "<code>$cveId</code>" }
                $kevBadge = if ($c.Kev) { " <span class='badge' style='background:#7b241c'>KEV</span>" } else { '' }
                $cweCell = if ($c.Cwe) { ConvertTo-TcpkHtmlSafe (@($c.Cwe) -join ', ') } else { '' }
                $refCell = ''
                if ($c.References -and @($c.References).Count) {
                    $refCell = (@($c.References) | Select-Object -First 3 | ForEach-Object {
                        $r = ConvertTo-TcpkHtmlSafe ([string]$_)
                        "<a href='$r' target='_blank' rel='noopener'>ref</a>"
                    }) -join ' '
                }
                $title = ConvertTo-TcpkHtmlSafe ([string]$c.Title)
                $summary = if ($c.Summary) { "<div class='cvesum'>" + (ConvertTo-TcpkHtmlSafe ([string]$c.Summary)) + "</div>" } else { '' }
                @"
<tr>
  <td><span class='badge' style='background:$stc'>$(ConvertTo-TcpkHtmlSafe ([string]$c.Status))</span></td>
  <td><span class='badge' style='background:$sc'>$(ConvertTo-TcpkHtmlSafe ([string]$c.Severity))</span></td>
  <td>$cveCell$kevBadge</td>
  <td>$(ConvertTo-TcpkHtmlSafe ([string]$c.Package))</td>
  <td><code>$(ConvertTo-TcpkHtmlSafe ([string]$c.ShippedVersion))</code></td>
  <td><code>$(if ("$($c.FixedVersion)") { '&ge; ' + (ConvertTo-TcpkHtmlSafe ([string]$c.FixedVersion)) } else { '-' })</code></td>
  <td>$(ConvertTo-TcpkHtmlSafe ([string]$c.Area))</td>
  <td>$title$summary</td>
  <td><code>$(ConvertTo-TcpkHtmlSafe ([string]$c.File))</code></td>
  <td>$refCell</td>
</tr>
"@
            }
            $vulnCount = @($CveMatches | Where-Object { "$($_.Status)" -eq 'Vulnerable' }).Count
            $cveHtml = @"
<section class='card cve'>
  <h3 class='cvehead'><span class='caret'>&#9662;</span>Known-vulnerability matches (live: OSV + NVD) <span class='seccount'>($(@($CveMatches).Count) match$(if (@($CveMatches).Count -ne 1){'es'}), $vulnCount vulnerable)</span></h3>
  <div class='cvebody'>
    <table class='recontab cvetab'>
      <thead><tr><th>Status</th><th>Severity</th><th>CVE</th><th>Package</th><th>Shipped</th><th>Fixed in</th><th>Area</th><th>Title</th><th>Source file</th><th>Refs</th></tr></thead>
      <tbody>
$($cveRows -join "`n")
      </tbody>
    </table>
    <div class='cvenote'><b>Reading this table:</b> matches are queried LIVE -- NuGet / npm / Maven / PyPI / Go / crates.io via OSV (api.osv.dev) and native C libraries via NVD (services.nvd.nist.gov) by CPE. <b>Fixed in</b> is the version where the fix FIRST landed (a floor, not a downgrade); the shipped version is below it, so the component is affected -- upgrade to that version or later (ideally the latest supported release).</div>
  </div>
</section>
"@
        }
        else {
            # ALWAYS render a CVE section, even at zero matches -- silence reads as "not checked".
            $cveN = @($Sbom).Count
            $emptyNote = if ($CveChecked) {
                "<b>No known vulnerabilities.</b> The shipped components ($cveN inventoried in the SBOM below) were matched <b>live</b> against OSV (NuGet / npm / Maven / PyPI / Go / crates.io) and NVD (native C libraries, by CPE). None are affected by a known CVE for their shipped version. Note: a vendor's own proprietary binaries have no CVE identity anywhere (they are covered by the findings above), and an up-to-date component can still be on an end-of-life branch -- check any <b>library-currency</b> findings."
            } else {
                "<b>CVE not checked this run.</b> Online CVE lookup was not enabled and there is no offline catalog. Re-run with online CVE (needs network) to match shipped components against OSV + NVD."
            }
            $cveHtml = @"
<section class='card cve'>
  <h3 class='cvehead'><span class='caret'>&#9662;</span>Known-vulnerability matches (live: OSV + NVD) <span class='seccount'>($(if ($CveChecked) { '0 vulnerable' } else { 'not checked' }))</span></h3>
  <div class='cvebody'>
    <div class='cvenote'>$emptyNote</div>
  </div>
</section>
"@
        }

        # ---------------- rule summary ----------------
        $ruleGroups = $all | Group-Object RuleId | ForEach-Object {
            $g = $_
            $worst = ($g.Group | ForEach-Object { Get-TcpkSeverityRank $_.Severity } | Measure-Object -Maximum).Maximum
            $worstSev = ($sevOrder | Where-Object { (Get-TcpkSeverityRank $_) -eq $worst } | Select-Object -First 1)
            [pscustomobject]@{ Rule=$g.Name; Count=$g.Count; Sev=$worstSev; Rank=$worst }
        } | Sort-Object -Property @{e='Rank';Descending=$true}, @{e='Count';Descending=$true}
        $ruleRows = foreach ($r in $ruleGroups) {
            "<tr class='rulerow' data-rule='$(ConvertTo-TcpkHtmlSafe $r.Rule)'><td><span class='badge' style='background:$($sevColor[$r.Sev])'>$($r.Sev)</span></td><td><code>$(ConvertTo-TcpkHtmlSafe $r.Rule)</code></td><td class='num'>$($r.Count)</td></tr>"
        }
        $ruleSummaryHtml = @"
<section id='ruleSummary' class='card' hidden>
  <h3>Findings grouped by rule (click a row to filter)</h3>
  <table class='ruletable'>
    <thead><tr><th>Max severity</th><th>Rule</th><th class='num'>Count</th></tr></thead>
    <tbody>
$($ruleRows -join "`n")
    </tbody>
  </table>
</section>
"@

        # ---------------- findings ----------------
        $idx = 0
        $sectionHtml = foreach ($sev in $sevOrder) {
            # Within a severity, show PROVEN findings first (IL > dynamic > Confirmed > Confirmed(LLM)),
            # then Inferred, then Likely-FP / Uncertain last -- so the reader's eye lands on what is
            # actually proven, not on raw string-scan guesses. Secondary keys keep it deterministic.
            $group = $all | Where-Object Severity -eq $sev | Sort-Object `
                @{ E = {
                    $c = "$($_.Confidence)"
                    if     ($c -like 'Confirmed (exploit)*') { 0 }
                    elseif ($c -like 'Confirmed (IL)*')      { 0 }
                    elseif ($c -like 'Confirmed (dynamic)*') { 1 }
                    elseif ($c -eq   'Confirmed')            { 2 }
                    elseif ($c -like 'Confirmed*')           { 3 }
                    elseif ($c -eq   'Inferred' -or $c -eq 'Unverified') { 5 }
                    elseif ($c -like 'Uncertain*')           { 6 }
                    elseif ($c -like 'Likely-FP*')           { 8 }
                    else { 7 }
                } }, @{ E = { "$($_.RuleId)" } }, @{ E = { "$($_.Title)" } }
            if (-not $group) { continue }
            $cards = foreach ($f in $group) {
                $idx++
                $fid = '{0:D3}' -f $idx
                $sevHex  = $sevColor[$f.Severity]
                $confHex = if ($confColor.ContainsKey($f.Confidence)) { $confColor[$f.Confidence] } else { '#566573' }
                $title   = ConvertTo-TcpkHtmlSafe $f.Title
                $rule    = ConvertTo-TcpkHtmlSafe $f.RuleId
                $file    = ConvertTo-TcpkHtmlSafe $f.File
                $evid    = ConvertTo-TcpkHtmlSafe $f.Evidence
                $fix     = ConvertTo-TcpkHtmlSafe $f.Fix
                $searchText = ConvertTo-TcpkHtmlSafe (("$($f.Title) $($f.RuleId) $($f.File) $($f.Evidence) $($f.Description)").ToLowerInvariant())

                # Standards mapping as compact tags under the header (CWE + MITRE ATT&CK
                # techniques + OWASP TASVS / Desktop Top 10) -- kept, not dropped, just tighter.
                $tagItems = New-Object 'System.Collections.Generic.List[string]'
                foreach ($cw in @($f.Cwe))                              { if ($cw) { $tagItems.Add("<span class='ftag ftag-cwe'>$(ConvertTo-TcpkHtmlSafe ([string]$cw))</span>") } }
                foreach ($at in @(Get-TcpkAttackTechnique -RuleId $f.RuleId)) { if ($at) { $tagItems.Add("<span class='ftag ftag-attack' title='MITRE ATT&amp;CK'>$(ConvertTo-TcpkHtmlSafe ([string]$at))</span>") } }
                # TASVS tags show ONLY TASVS-* categories; the Desktop Top 10 (DA*) now comes
                # solely from Get-TcpkOwaspDa below, so the two no longer disagree on a card.
                foreach ($tv in @(Get-TcpkTasvsControl -RuleId $f.RuleId | Where-Object { $_ -notmatch '^DA\d' })) { if ($tv) { $tagItems.Add("<span class='ftag ftag-tasvs' title='OWASP TASVS'>$(ConvertTo-TcpkHtmlSafe ([string]$tv))</span>") } }
                $oda = Get-TcpkOwaspDa -RuleId $f.RuleId; if ($oda) { $tagItems.Add("<span class='ftag ftag-owasp' title='OWASP Desktop Application Top 10 (2021)'>$(ConvertTo-TcpkHtmlSafe ([string]$oda))</span>") }
                $tagRow = if ($tagItems.Count) { "<div class='ftags'>" + ($tagItems -join '') + "</div>" } else { '' }

                $kv = New-Object 'System.Collections.Generic.List[string]'

                # CVSS v4.0: score + vector only -- the severity band already lives on the badge.
                $cvss = Get-TcpkCvssVector $f
                if ($cvss.Vector) {
                    $scoreTxt = if ($null -ne $cvss.Score) { ('{0:0.0} &middot; ' -f $cvss.Score) } else { '' }
                    $kv.Add("<tr><th>CVSS v4.0</th><td>$scoreTxt<code>$(ConvertTo-TcpkHtmlSafe $cvss.Vector)</code></td></tr>")
                } elseif ($cvss.Source -ne 'info' -and $cvss.Display) {
                    $kv.Add("<tr><th>CVSS v4.0</th><td><span class='muted'>$(ConvertTo-TcpkHtmlSafe $cvss.Display)</span></td></tr>")
                }

                # What: the real explanation, with internal [TCPK]/[LLM] notes split off to a footer.
                $split = _SplitNotes $f.Description
                if ($split.Clean) { $kv.Add("<tr><th>What</th><td>$(ConvertTo-TcpkHtmlSafe $split.Clean)</td></tr>") }

                # Impact (the consequence) -- distinct from Why-here (why it applies here).
                $impact = ConvertTo-TcpkHtmlSafe (Get-TcpkImpactText $f)
                if ($impact) { $kv.Add("<tr><th>Impact</th><td>$impact</td></tr>") }

                $why = ConvertTo-TcpkHtmlSafe (_WhyHere $f.Confidence)
                if ($why) { $kv.Add("<tr><th>Why here</th><td>$why</td></tr>") }

                if ($file) { $kv.Add("<tr><th>File</th><td><code class='path'>$file</code></td></tr>") }

                # Affected: full path (or URL/param) per occurrence when this finding aggregates many.
                if ($f.Affected -and @($f.Affected).Count) {
                    $affItems = (@($f.Affected) | ForEach-Object { "<li><code class='path'>$(ConvertTo-TcpkHtmlSafe ([string]$_))</code></li>" }) -join ''
                    $kv.Add("<tr><th>Affected ($(@($f.Affected).Count))</th><td><ul class='afflist'>$affItems</ul></td></tr>")
                }

                if ($evid) {
                    $rawEv = "$($f.Evidence)"
                    if ($rawEv.Length -gt 160) {
                        # Long evidence (a decoded certificate, a big secret value, a long
                        # affected list) is collapsed behind a toggle so the card stays compact;
                        # the summary shows the first chunk, click to expand the full value.
                        $evSum = ConvertTo-TcpkHtmlSafe ($rawEv.Substring(0, 80).TrimEnd() + ' ...')
                        $kv.Add("<tr><th>Evidence</th><td><details class='evtoggle'><summary><code class='evidence'>$evSum</code> <span class='evmore'>show full</span></summary><code class='evidence evfull'>$evid</code></details></td></tr>")
                    } else {
                        $kv.Add("<tr><th>Evidence</th><td><code class='evidence'>$evid</code></td></tr>")
                    }
                }

                # Verify: use a REAL path. After aggregation File is 'N files', so reach into the
                # Affected list for the first concrete path; otherwise use File. (Fixes the old
                # broken "Test-TcpkCallsites -Path '3 files'".)
                $verifyFile = "$($f.File)"
                if ($f.Affected -and @($f.Affected).Count -and $verifyFile -match '^\d+\s+(files|occurrences)') {
                    $vp = @($f.Affected | Where-Object { "$_" -match '[\\/]' } | Select-Object -First 1)
                    if ($vp) { $verifyFile = "$vp" }
                }
                $verifyRaw = Get-TcpkVerifyHint -RuleId $f.RuleId -File $verifyFile -Evidence $f.Evidence
                if ($verifyRaw) {
                    # Render the playbook as a terminal card: comment lines (# ...) are muted, the
                    # paste-and-run command line(s) are highlighted, and a Copy button copies just
                    # the command. The whole block stays copy-paste-safe (comments are # in PS).
                    $vLines   = $verifyRaw -split "\r?\n"
                    $cmdLines = @($vLines | Where-Object { $_.Trim() -ne '' -and $_ -notmatch '^\s*#' })
                    $vBodyParts = foreach ($vl in $vLines) {
                        if ($vl -match '^\s*#') { "<span class='vc'>$(ConvertTo-TcpkHtmlSafe $vl)</span>" }
                        else                    { "<span class='vcmd'>$(ConvertTo-TcpkHtmlSafe $vl)</span>" }
                    }
                    $vCopy = ''
                    if ($cmdLines.Count) {
                        $cmdB64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes(($cmdLines -join "`r`n")))
                        $vCopy  = "<button type='button' class='vcopy' data-cmd='$cmdB64'>Copy</button>"
                    }
                    $vBox = "<div class='vbox'><div class='vbar'><span class='vdots'><i></i><i></i><i></i></span><span class='vlabel'>verify</span>$vCopy</div><pre class='vbody'>$($vBodyParts -join "`n")</pre></div>"
                    $kv.Add("<tr><th>Verify</th><td>$vBox</td></tr>")
                }

                if ($fix)  { $kv.Add("<tr><th>Fix</th><td>$fix</td></tr>") }

                # Audit notes footer: the TCPK/LLM process notes pulled out of the description above.
                $notesHtml = ''
                if (@($split.Notes).Count) {
                    $notesHtml = "<div class='auditnotes'><span class='anlabel'>Audit notes</span> " + (ConvertTo-TcpkHtmlSafe (($split.Notes -join ' '))) + "</div>"
                }
@"
<article class='finding' data-sev='$($f.Severity)' data-proven='$(if ("$($f.Confidence)" -like 'Confirmed*') { '1' } else { '0' })' data-rule='$rule' data-text='$searchText'>
  <div class='fhead'>
    <span class='fid'>#$fid</span>
    <span class='badge' style='background:$sevHex'>$($f.Severity)</span>
    <span class='badge' style='background:$confHex'>$($f.Confidence)</span>
    <span class='ftitle'>$title</span>
    <span class='frule'>$rule</span>
  </div>
  <div class='fbody'>
    $tagRow
    <table class='kv'>
$($kv -join "`n")
    </table>
    $notesHtml
  </div>
</article>
"@
            }
            $open = if ($sev -in 'CRITICAL','HIGH') { '' } else { 'collapsed' }
@"
<section class='sevsection $open' data-sev='$sev'>
  <h2 class='sevhead' style='color:$($sevColor[$sev])'><span class='caret'>&#9662;</span>$sev <span class='seccount'>($(@($group).Count))</span></h2>
  <div class='sevbody'>
$($cards -join "`n")
  </div>
</section>
"@
        }

        # ---------------- DLL hardening matrix (parity with Excel DLL Hardening sheet) ----------------
        $hardeningHtml = ''
        if ($Hardening -and @($Hardening).Count) {
            $hwStatusColor = @{ 'WEAK'='#c0392b'; 'PARTIAL'='#d68910'; 'HARDENED'='#117a65' }
            $flagColor = { param($v) if ("$v" -in 'True','Yes','ON','Enabled') { '#117a65' } elseif ("$v" -in 'False','No','OFF','Disabled') { '#c0392b' } else { '#566573' } }
            $hwSorted = $Hardening | Sort-Object @{ E = { switch ("$($_.Status)") { 'WEAK' {0} 'PARTIAL' {1} default {2} } } }, DLL
            $hwRows = foreach ($h in $hwSorted) {
                $stc = if ($hwStatusColor.ContainsKey("$($h.Status)")) { $hwStatusColor["$($h.Status)"] } else { '#566573' }
                $cell = { param($v) "<td style='color:$(& $flagColor $v);font-weight:600'>$(ConvertTo-TcpkHtmlSafe ([string]$v))</td>" }
                @"
<tr>
  <td><code>$(ConvertTo-TcpkHtmlSafe ([string]$h.DLL))</code></td>
  <td>$(ConvertTo-TcpkHtmlSafe ([string]$h.Arch))</td>
  $(& $cell $h.ASLR)
  $(& $cell $h.DEP)
  $(& $cell $h.CFG)
  $(& $cell $h.HighEntropyVA)
  $(& $cell $h.SafeSEH)
  $(& $cell $h.GS)
  $(& $cell $h.ForceIntegrity)
  <td><span class='badge' style='background:$stc'>$(ConvertTo-TcpkHtmlSafe ([string]$h.Status))</span></td>
  <td>$(ConvertTo-TcpkHtmlSafe ([string]$h.Missing))</td>
</tr>
"@
            }
            $weakN = @($Hardening | Where-Object { "$($_.Status)" -eq 'WEAK' }).Count
            $partN = @($Hardening | Where-Object { "$($_.Status)" -eq 'PARTIAL' }).Count
            $hardeningHtml = @"
<section class='card hardening collapsed'>
  <h3 class='hardhead'><span class='caret'>&#9662;</span>DLL exploit-mitigation matrix <span class='seccount'>($(@($Hardening).Count) binaries &middot; $weakN weak &middot; $partN partial)</span></h3>
  <div class='hardbody'>
    <div class='filterbar'><input class='tabfilter' data-target='hardtab' type='text' placeholder='Filter DLLs by name / status / missing mitigation...'><span class='filtcount'></span></div>
    <table class='recontab hardtab'>
      <thead><tr><th>DLL</th><th>Arch</th><th>ASLR</th><th>DEP</th><th>CFG</th><th>HighEntropyVA</th><th>SafeSEH</th><th>GS</th><th>ForceIntegrity</th><th>Status</th><th>Missing</th></tr></thead>
      <tbody>
$($hwRows -join "`n")
      </tbody>
    </table>
  </div>
</section>
"@
        }

        # ---------------- DLL signing matrix (signed / not signed -- information only) ----------------
        $signingHtml = ''
        if ($Signing -and @($Signing).Count) {
            $sgColor = { param($v) switch ("$v") { 'SIGNED' {'#117a65'} 'CATALOG' {'#117a65'} 'EXPIRED-TS' {'#d68910'} 'EXPIRED' {'#c0392b'} 'UNSIGNED' {'#c0392b'} 'TAMPERED' {'#c0392b'} 'UNTRUSTED' {'#c0392b'} default {'#566573'} } }
            $sgSorted = $Signing | Sort-Object @{ E = { switch ("$($_.Status)") { 'TAMPERED' {0} 'UNTRUSTED' {1} 'UNSIGNED' {2} 'EXPIRED' {3} 'EXPIRED-TS' {4} 'UNKNOWN' {5} default {6} } } }, DLL
            $sgRows = foreach ($s in $sgSorted) {
                $stc = & $sgColor $s.Status
                $issCn = if ("$($s.Issuer)" -match 'CN=([^,]+)') { $matches[1].Trim('"').Trim() } else { "$($s.Issuer)" }
                $certTip = (("Subject: $($s.Subject)  |  Issuer: $($s.Issuer)  |  Serial: $($s.Serial)  |  EKU: $($s.Eku)") -replace '"', "'")
                @"
<tr title="$(ConvertTo-TcpkHtmlSafe $certTip)">
  <td><code>$(ConvertTo-TcpkHtmlSafe ([string]$s.DLL))</code></td>
  <td style='color:$stc;font-weight:600'>$(ConvertTo-TcpkHtmlSafe ([string]$s.Signed))</td>
  <td><span class='badge' style='background:$stc'>$(ConvertTo-TcpkHtmlSafe ([string]$s.Status))</span></td>
  <td>$(ConvertTo-TcpkHtmlSafe ([string]$s.Signer))</td>
  <td>$(ConvertTo-TcpkHtmlSafe ([string]$issCn))</td>
  <td>$(ConvertTo-TcpkHtmlSafe ([string]$s.Algorithm))</td>
  <td>$(ConvertTo-TcpkHtmlSafe ([string]$s.KeySize))</td>
  <td>$(ConvertTo-TcpkHtmlSafe ([string]$s.ValidFrom))</td>
  <td>$(ConvertTo-TcpkHtmlSafe ([string]$s.Expires))</td>
  <td><code style='font-size:12px'>$(ConvertTo-TcpkHtmlSafe ([string]$s.Thumbprint))</code></td>
  <td>$(ConvertTo-TcpkHtmlSafe ([string]$s.Type))</td>
</tr>
"@
            }
            $unsN = @($Signing | Where-Object { "$($_.Signed)" -eq 'NO' }).Count
            $sgnN = @($Signing | Where-Object { "$($_.Signed)" -in 'YES','CATALOG' }).Count
            $signingHtml = @"
<section class='card signing collapsed'>
  <h3 class='signhead'><span class='caret'>&#9662;</span>DLL signing matrix (signed / not signed) <span class='seccount'>($(@($Signing).Count) binaries &middot; $sgnN signed &middot; $unsN unsigned)</span></h3>
  <div class='signbody'>
    <div class='filterbar'><input class='tabfilter' data-target='signtab' type='text' placeholder='Filter DLLs by name / signer / status...'><span class='filtcount'></span></div>
    <div class='emptynote'>Hover a row for the full subject, issuer, serial and EKU. The complete certificate for every binary is also in signing.json and the Excel "DLL Signing" sheet.</div>
    <table class='recontab hardtab signtab'>
      <thead><tr><th>DLL</th><th>Signed</th><th>Status</th><th>Signer</th><th>Issuer</th><th>Algorithm</th><th>Key bits</th><th>Valid From</th><th>Expires</th><th>Thumbprint</th><th>Type</th></tr></thead>
      <tbody>
$($sgRows -join "`n")
      </tbody>
    </table>
  </div>
</section>
"@
        }

        # ---------------- SBOM / component inventory (parity with sbom.cdx.json + Excel) ----------------
        $sbomHtml = ''
        if ($Sbom -and @($Sbom).Count) {
            $sbomRows = foreach ($s in @($Sbom)) {
                $typeTag = if ($s.Managed) { "<span class='tag tag-sdk'>nuget</span>" } else { "<span class='tag tag-net'>native</span>" }
                @"
<tr>
  <td>$(ConvertTo-TcpkHtmlSafe ([string]$s.Name))</td>
  <td><code>$(ConvertTo-TcpkHtmlSafe ([string]$s.Version))</code></td>
  <td>$(ConvertTo-TcpkHtmlSafe ([string]$s.Publisher))</td>
  <td>$typeTag</td>
  <td><code class='sha'>$(ConvertTo-TcpkHtmlSafe ([string]$s.Sha256))</code></td>
  <td><code class='path'>$(ConvertTo-TcpkHtmlSafe ([string]$s.Path))</code></td>
</tr>
"@
            }
            $managedN = @($Sbom | Where-Object { $_.Managed }).Count
            $nativeN = @($Sbom).Count - $managedN
            $sbomHtml = @"
<section class='card sbom collapsed'>
  <h3 class='sbomhead'><span class='caret'>&#9662;</span>Software bill of materials (SBOM) <span class='seccount'>($(@($Sbom).Count) components &middot; $nativeN native &middot; $managedN managed)</span></h3>
  <div class='sbombody'>
    <div class='filterbar'><input class='tabfilter' data-target='sbomtab' type='text' placeholder='Filter components by name / version / type / hash / path...'><span class='filtcount'></span></div>
    <table class='recontab sbomtab'>
      <thead><tr><th>Component</th><th>Version</th><th>Publisher</th><th>Type</th><th>SHA-256</th><th>Path</th></tr></thead>
      <tbody>
$($sbomRows -join "`n")
      </tbody>
    </table>
    <div class='cvenote' style='color:#9aa4b2;background:#0d1117;border-color:#242c3a'>Full CycloneDX 1.5 inventory (with hashes + purls) is also written to <code>sbom.cdx.json</code> alongside this report.</div>
  </div>
</section>
"@
        }

        # ---------------- standards coverage (OWASP Desktop Top 10 + MITRE ATT&CK) ----------------
        $daNames = [ordered]@{
            'DA1'='Injections'; 'DA2'='Broken Authentication'; 'DA3'='Sensitive Data Exposure'; 'DA4'='Improper Cryptography'
            'DA5'='Improper Authorization'; 'DA6'='Security Misconfiguration'; 'DA7'='Insecure Communication'
            'DA8'='Poor Code Quality'; 'DA9'='Components With Known Vulnerabilities'; 'DA10'='Insufficient Logging'
        }
        $daCount = @{}; $daWorst = @{}
        foreach ($ff in $all) {
            $da = Get-TcpkOwaspDa -RuleId $ff.RuleId
            if ("$da" -match '^(DA\d+)') {
                $k = $matches[1]
                $daCount[$k] = 1 + [int]$daCount[$k]
                $rk = Get-TcpkSeverityRank $ff.Severity
                if (-not $daWorst.ContainsKey($k) -or $rk -gt $daWorst[$k]) { $daWorst[$k] = $rk }
            }
        }
        $daCells = foreach ($k in $daNames.Keys) {
            $cnt = [int]$daCount[$k]
            if ($cnt -gt 0) {
                $ws  = ($sevOrder | Where-Object { (Get-TcpkSeverityRank $_) -eq $daWorst[$k] } | Select-Object -First 1)
                $col = $sevColor[$ws]
                "<div class='da' style='border-left-color:$col'><span class='dc' style='color:$col'>$cnt</span><div class='dn'>$k</div><div class='dt'>$(ConvertTo-TcpkHtmlSafe $daNames[$k])</div></div>"
            } else {
                "<div class='da clear'><span class='dc'>0</span><div class='dn'>$k</div><div class='dt'>$(ConvertTo-TcpkHtmlSafe $daNames[$k])</div></div>"
            }
        }
        $atkCount = @{}
        foreach ($ff in $all) { foreach ($t in @(Get-TcpkAttackTechnique -RuleId $ff.RuleId)) { if ($t) { $atkCount["$t"] = 1 + [int]$atkCount["$t"] } } }
        $atkTop = @($atkCount.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 6)
        $atkMax = ($atkTop | ForEach-Object { $_.Value } | Measure-Object -Maximum).Maximum; if (-not $atkMax -or $atkMax -lt 1) { $atkMax = 1 }
        $atkRows = foreach ($e in $atkTop) {
            $w = [int](100 * $e.Value / $atkMax)
            "<div class='arow'><span class='alabel'>$(ConvertTo-TcpkHtmlSafe $e.Key)</span><span class='atrack'><i style='width:${w}%'></i></span><span class='acnt'>$($e.Value)</span></div>"
        }
        $atkBlock = if ($atkTop.Count) { "<div class='atk'><div class='covsub'>by MITRE ATT&amp;CK technique</div>" + ($atkRows -join "`n") + "</div>" } else { '' }
        $coverageHtml = @"
<section class='card coverage'>
  <h3 class='covhead'><span class='caret'>&#9662;</span>Standards coverage <span class='seccount'>(OWASP Desktop App Top 10 + MITRE ATT&amp;CK)</span></h3>
  <div class='covbody'>
    <div class='covsub'>OWASP Desktop App Top 10 (2021) -- categories the findings map to (green = clear)</div>
    <div class='dagrid'>$($daCells -join "`n")</div>
    $atkBlock
  </div>
</section>
"@

        # ---------------- remediation plan (prioritized, de-duplicated fixes) ----------------
        $remediationHtml = ''
        $fixable = @($all | Where-Object { "$($_.Severity)" -ne 'INFO' -and "$($_.Fix)".Trim() -and "$($_.Fix)".Trim() -notmatch '^(n/?a|none|-)$' })
        if ($fixable.Count) {
            $remGroups = $fixable | Group-Object { "$($_.Fix)" } | ForEach-Object {
                $g = $_
                $worst = ($g.Group | ForEach-Object { Get-TcpkSeverityRank $_.Severity } | Measure-Object -Maximum).Maximum
                $worstSev = ($sevOrder | Where-Object { (Get-TcpkSeverityRank $_) -eq $worst } | Select-Object -First 1)
                $rules = (@($g.Group | ForEach-Object { "$($_.RuleId)" } | Sort-Object -Unique) -join ', ')
                $cweList = (@($g.Group | ForEach-Object { @($_.Cwe) } | Where-Object { $_ } | Sort-Object -Unique) -join ', ')
                [pscustomobject]@{ Fix=$g.Name; Sev=$worstSev; Rank=$worst; Count=$g.Count; Rules=$rules; Cwes=$cweList }
            } | Sort-Object -Property @{ e='Rank'; Descending=$true }, @{ e='Count'; Descending=$true }
            $remRows = foreach ($r in $remGroups) {
                $priClass = switch ("$($r.Sev)") { 'CRITICAL' { 'p1' } 'HIGH' { 'p2' } default { 'p3' } }
                $priLabel = switch ("$($r.Sev)") { 'CRITICAL' { 'P1' } 'HIGH' { 'P2' } default { 'P3' } }
                $meta = (@($r.Rules, $r.Cwes) | Where-Object { $_ }) -join ' &middot; '
                "<div class='rem'><div class='pri $priClass'>$priLabel</div><div class='rmid'><div class='rfix'>$(ConvertTo-TcpkHtmlSafe $r.Fix)</div><div class='rmeta'>$(ConvertTo-TcpkHtmlSafe $meta)</div></div><div class='rright'><span class='badge' style='background:$($sevColor[$r.Sev])'>$($r.Sev)</span><span class='cnt'>$($r.Count) finding$(if ($r.Count -ne 1){'s'})</span></div></div>"
            }
            $remediationHtml = @"
<section class='card remed collapsed'>
  <h3 class='remhead'><span class='caret'>&#9662;</span>Remediation plan <span class='seccount'>($(@($remGroups).Count) prioritized fix$(if (@($remGroups).Count -ne 1){'es'}) &middot; click to expand)</span></h3>
  <div class='rembody'>
    <div class='remnote'>De-duplicated, highest risk first -- one row per fix. P1 = critical, P2 = high, P3 = medium/low.</div>
$($remRows -join "`n")
  </div>
</section>
"@
        }

        # ---------------- static CSS ----------------
        $css = @'
*{box-sizing:border-box}
:root{--bg:#0a0d13;--panel:#11161f;--panel2:#161c27;--sub:#0d1117;--bd:#242c3a;--bd2:#2f3a4d;--tx:#e6edf3;--mut:#9aa4b2;--dim:#6a7585;--acc:#56d364;--acc2:#3fb950;--blue:#58a6ff;--amber:#d29922;--red:#f85149;--crit:#f85149;--high:#db6d28;--med:#d29922;--low:#3fb950;--info:#6a7585}
body{font-family:-apple-system,"Segoe UI",system-ui,sans-serif;margin:0;background:var(--bg);color:var(--tx);line-height:1.55}
.wrap{max-width:1180px;margin:0 auto;padding:26px 22px 100px}
h1{font-size:25px;margin:0;font-weight:700;letter-spacing:-.2px}
.sub{color:var(--dim);font-size:13.5px;margin:3px 0 20px;font-family:"Cascadia Code","Fira Code",Consolas,monospace}
.card{background:var(--panel);border:1px solid var(--bd);border-radius:12px;padding:16px 18px;margin:0 0 14px}
.target .kvgrid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:2px 26px}
.kvi{display:flex;gap:10px;font-size:14px;padding:5px 0;border-bottom:1px solid var(--bd)}
.kvi .k{color:var(--mut);min-width:96px;font-weight:600}
.kvi .v{color:var(--tx);word-break:break-word}
.stack{margin-top:14px}
.stackrow{display:flex;flex-wrap:wrap;align-items:center;gap:6px;margin:6px 0}
.stacklabel{font-size:11px;font-weight:700;color:var(--dim);text-transform:uppercase;letter-spacing:.06em;min-width:62px}
.tag{display:inline-block;font-size:13px;padding:3px 10px;border-radius:20px;background:var(--panel2);color:var(--tx);border:1px solid var(--bd2);font-family:"Cascadia Code","Fira Code",Consolas,monospace}
.tag-ui{color:#7cc0ff;border-color:#234a6e}
.tag-net{color:#5ad6a0;border-color:#1f5a45}
.tag-upd{color:#f0b65c;border-color:#6e5320}
.tag-sdk{color:#c4a3f5;border-color:#4a3a6e}
.surfrow{display:flex;flex-wrap:wrap;gap:8px;margin-top:16px}
.surf{flex:1 1 78px;min-width:78px;text-align:center;background:var(--sub);border:1px solid var(--bd);border-radius:9px;padding:9px 6px}
.surf b{display:block;font-size:20px;color:var(--tx);font-family:"Cascadia Code","Fira Code",Consolas,monospace}
.surf span{font-size:11px;color:var(--dim);text-transform:uppercase;letter-spacing:.05em}
.scope{margin-top:14px;padding-top:11px;border-top:1px solid var(--bd);font-size:13px;color:var(--mut)}
.covgaps{color:var(--amber)}
.chart{display:flex;flex-direction:column;gap:7px}
.bar{display:flex;align-items:center;gap:10px;font-size:14px}
.barlabel{min-width:74px;font-weight:600;color:var(--mut);font-size:13px}
.bartrack{flex:1;background:var(--sub);border:1px solid var(--bd);border-radius:5px;height:18px;overflow:hidden}
.barfill{display:block;height:100%;border-radius:4px}
.barcount{min-width:34px;text-align:right;font-weight:700;font-family:"Cascadia Code","Fira Code",Consolas,monospace}
.dash{padding:18px}
.dashgrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:18px;align-items:start}
.dcell{display:flex;flex-direction:column;gap:10px;min-width:0}
.dcell h4{margin:0;font:700 10px "Cascadia Code","Fira Code",Consolas,monospace;color:var(--mut);letter-spacing:.09em}
.gaugewrap,.donutwrap{display:flex;justify-content:center;padding:2px 0}
.dleg{font:12px "Cascadia Code","Fira Code",Consolas,monospace;color:var(--mut);display:flex;flex-direction:column;gap:5px}
.dleg span{display:flex;align-items:center;gap:7px}
.dleg i{width:10px;height:10px;border-radius:3px;flex:0 0 auto}
.dleg b{color:var(--tx);margin-left:auto;font-weight:700}
.remed .remhead,.coverage .covhead{cursor:pointer;user-select:none;margin:0 0 4px}
.remed.collapsed .rembody,.coverage.collapsed .covbody{display:none}
.remnote,.covsub{color:var(--dim);font:12px "Cascadia Code","Fira Code",Consolas,monospace;margin:0 0 12px}
.rem{display:flex;align-items:flex-start;gap:13px;padding:12px 0;border-bottom:1px solid var(--bd)}
.rem:last-child{border-bottom:none}
.pri{flex:0 0 auto;width:36px;height:36px;border-radius:9px;display:flex;align-items:center;justify-content:center;font:700 13px "Cascadia Code","Fira Code",Consolas,monospace;color:#08130a}
.pri.p1{background:var(--crit)}.pri.p2{background:var(--high)}.pri.p3{background:var(--med)}
.rmid{flex:1;min-width:0}
.rfix{font-weight:600;font-size:14px;color:var(--tx)}
.rmeta{font:11px "Cascadia Code","Fira Code",Consolas,monospace;color:var(--dim);margin-top:3px;word-break:break-word}
.rright{flex:0 0 auto;display:flex;flex-direction:column;gap:6px;align-items:flex-end}
.rright .cnt{font:11px "Cascadia Code","Fira Code",Consolas,monospace;color:var(--mut);white-space:nowrap}
.dagrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(165px,1fr));gap:9px;margin-bottom:4px}
.da{background:var(--sub);border:1px solid var(--bd);border-left-width:3px;border-radius:8px;padding:10px 12px;overflow:hidden}
.da .dc{float:right;font:700 15px "Cascadia Code","Fira Code",Consolas,monospace;color:var(--mut)}
.da .dn{font:700 11px "Cascadia Code","Fira Code",Consolas,monospace;color:var(--mut)}
.da .dt{font-size:13px;margin-top:2px;color:var(--tx)}
.da.clear{border-left-color:var(--low)}.da.clear .dc{color:var(--low)}
.atk{margin-top:16px}
.arow{display:flex;align-items:center;gap:11px;font:12px "Cascadia Code","Fira Code",Consolas,monospace;margin:8px 0}
.alabel{flex:0 0 220px;color:var(--tx);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.atrack{flex:1;height:9px;background:var(--sub);border:1px solid var(--bd);border-radius:5px;overflow:hidden}
.atrack i{display:block;height:100%;background:var(--blue);border-radius:4px}
.acnt{flex:0 0 auto;font-weight:700;color:var(--tx);min-width:20px;text-align:right}
.execsum{background:linear-gradient(180deg,rgba(86,211,100,.06),transparent);border-color:#23402b}
.exechead{margin:0 0 7px;font-size:12px;letter-spacing:.5px;text-transform:uppercase;color:var(--acc)}
.exectext{margin:0;line-height:1.65;color:var(--tx);font-size:15px}
.confsum .confgrid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px}
.cmetric{display:flex;flex-direction:column;gap:3px;background:var(--sub);border:1px solid var(--bd);border-radius:9px;padding:10px 12px}
.cmlabel{font-size:12px;color:var(--mut)}
.cmval{font-size:23px;font-weight:700;font-family:"Cascadia Code","Fira Code",Consolas,monospace}
.toolbar{position:sticky;top:0;z-index:20;display:flex;flex-wrap:wrap;gap:8px;align-items:center;background:rgba(10,13,19,.92);backdrop-filter:blur(6px);padding:12px 0;margin-bottom:12px;border-bottom:1px solid var(--bd)}
#search{flex:1;min-width:200px;padding:9px 13px;border:1px solid var(--bd2);border-radius:8px;font-size:15px;background:var(--sub);color:var(--tx)}
#search::placeholder{color:var(--dim)}
.filterbar{display:flex;align-items:center;gap:10px;margin:0 0 10px}
.tabfilter{flex:1;max-width:460px;padding:7px 11px;border:1px solid var(--bd2);border-radius:7px;font-size:14px;background:var(--sub);color:var(--tx)}
.filtcount{color:var(--dim);font-size:13px}
.chip{cursor:pointer;font-size:13px;font-weight:600;padding:6px 12px;border-radius:20px;border:1px solid var(--bd2);background:var(--panel2);color:var(--mut);user-select:none}
.chip:hover{border-color:var(--dim)}
.chip.active{background:var(--acc);color:#08130a;border-color:var(--acc)}
.btn{cursor:pointer;font-size:13px;padding:6px 12px;border-radius:7px;border:1px solid var(--bd2);background:var(--panel2);color:var(--tx)}
.btn:hover{background:var(--bd)}
.btn.active{border-color:var(--acc);color:var(--acc)}
.sevsection{margin:10px 0}
.sevhead{font-size:17px;margin:16px 0 8px;cursor:pointer;user-select:none;padding-bottom:7px;border-bottom:1px solid var(--bd);font-weight:700}
.caret{display:inline-block;width:16px;transition:transform .15s;color:var(--dim)}
.collapsed .caret{transform:rotate(-90deg)}
.sevsection.collapsed .sevbody{display:none}
.seccount{color:var(--dim);font-weight:400;font-size:15px}
.finding{background:var(--panel);border:1px solid var(--bd);border-left:3px solid var(--bd2);border-radius:9px;margin:8px 0;overflow:hidden}
.finding[data-sev="CRITICAL"]{border-left-color:var(--red)}
.finding[data-sev="HIGH"]{border-left-color:#db6d28}
.finding[data-sev="MEDIUM"]{border-left-color:var(--amber)}
.finding[data-sev="LOW"]{border-left-color:var(--acc2)}
.finding[data-sev="INFO"]{border-left-color:#6a7585}
.fhead{display:flex;flex-wrap:wrap;align-items:center;gap:8px;padding:11px 14px;cursor:pointer}
.fhead:hover{background:var(--panel2)}
.fid{font-family:"Cascadia Code","Fira Code",Consolas,monospace;font-size:13px;color:var(--dim);font-weight:700}
.badge{display:inline-block;font-size:11px;font-weight:700;letter-spacing:.04em;padding:3px 8px;border-radius:5px;color:#fff;text-transform:uppercase}
.ftitle{font-weight:600;font-size:15px;flex:1;min-width:160px;color:var(--tx)}
.frule{font-family:"Cascadia Code","Fira Code",Consolas,monospace;font-size:12px;color:var(--dim)}
.fbody{display:none;padding:2px 14px 13px;border-top:1px solid var(--bd)}
.finding.open .fbody{display:block}
.kv{width:100%;border-collapse:collapse;margin-top:10px}
.kv th{text-align:left;vertical-align:top;padding:5px 12px 5px 0;font-weight:600;font-size:12px;color:var(--mut);width:104px;text-transform:uppercase;letter-spacing:.03em}
.kv td{padding:5px 0;font-size:14px;vertical-align:top;color:var(--tx)}
code{font-family:"Cascadia Code","Fira Code",Consolas,Menlo,monospace;font-size:13px;background:var(--sub);color:#c9d1d9;padding:1px 6px;border-radius:4px;border:1px solid var(--bd);word-break:break-word}
code.evidence{background:rgba(210,153,34,.12);color:#f0b65c;font-weight:700;padding:2px 7px;border:1px solid #6e5320}
details.evtoggle{display:inline-block}
details.evtoggle summary{cursor:pointer;list-style:none;outline:none}
details.evtoggle summary::-webkit-details-marker{display:none}
details.evtoggle summary .evmore{font-size:11px;color:#8b95a3;margin-left:6px;text-decoration:underline}
details.evtoggle[open] summary .evmore{color:#6e7681}
code.evidence.evfull{display:block;margin-top:6px;white-space:pre-wrap;word-break:break-all;line-height:1.6}
code.verify{display:block;white-space:pre-wrap;padding:9px 11px;background:#010409;color:#7ce38b;line-height:1.5;border:1px solid var(--bd);border-left:3px solid var(--acc)}
.vbox{border:1px solid var(--bd);border-radius:10px;overflow:hidden;background:#010409;margin-top:6px}
.vbar{display:flex;align-items:center;gap:10px;padding:9px 15px;background:var(--panel2);border-bottom:1px solid var(--bd)}
.vdots{display:inline-flex;gap:6px;align-items:center}
.vdots i{width:9px;height:9px;border-radius:50%;background:#3a4250}
.vdots i:nth-child(1){background:#f85149}.vdots i:nth-child(2){background:#d29922}.vdots i:nth-child(3){background:#3fb950}
.vlabel{flex:1;font:700 10px "Cascadia Code","Fira Code",Consolas,monospace;color:var(--mut);letter-spacing:.18em;text-transform:uppercase}
.vcopy{cursor:pointer;font:600 11px "Cascadia Code","Fira Code",Consolas,monospace;color:var(--acc);background:transparent;border:1px solid var(--bd2);border-radius:6px;padding:4px 15px}
.vcopy:hover{background:var(--bd);border-color:var(--acc)}
.vcopy.copied{color:#08130a;background:var(--acc);border-color:var(--acc)}
.vbody{margin:0;padding:17px 19px;white-space:pre-wrap;word-break:break-word;font:14px "Cascadia Code","Fira Code",Consolas,monospace;line-height:1.9}
.vc{color:#737e8d}
.vcmd{color:#7ee787;font-weight:700}
code.path{font-size:12.5px;word-break:break-all;color:#9aa4b2}
.ruletable{width:100%;border-collapse:collapse;font-size:14px}
.ruletable th,.ruletable td{padding:7px 10px;border-bottom:1px solid var(--bd);text-align:left}
.ruletable .num{text-align:right}
.rulerow{cursor:pointer}
.rulerow:hover{background:var(--panel2)}
h3{font-size:15px;margin:0 0 11px;color:var(--tx)}
.recon .reconhead{cursor:pointer;user-select:none;margin:0 0 12px}
.recon.collapsed .reconbody{display:none}
.reconblock{margin:0 0 16px}
.reconblock h4{font-size:13px;margin:0 0 7px;color:var(--mut);text-transform:uppercase;letter-spacing:.04em;border-left:3px solid var(--blue);padding-left:9px}
.recontab{width:100%;border-collapse:collapse;font-size:13.5px;margin-bottom:4px}
.recontab th{text-align:left;background:var(--sub);padding:6px 9px;border-bottom:1px solid var(--bd2);font-size:11.5px;text-transform:uppercase;letter-spacing:.03em;color:var(--mut)}
.recontab td{padding:6px 9px;border-bottom:1px solid var(--bd);vertical-align:top;word-break:break-word;color:var(--tx)}
.recontab tr:hover{background:var(--panel2)}
.reconlist{margin:4px 0 4px 4px;padding-left:18px;font-size:14px}
.reconlist li{margin:2px 0}
.emptynote{font-size:13.5px;color:var(--dim);font-style:italic;padding:4px 0 4px 11px}
.cve .cvehead,.hardening .hardhead,.signing .signhead{cursor:pointer;user-select:none;margin:0 0 12px}
.cve.collapsed .cvebody,.hardening.collapsed .hardbody,.signing.collapsed .signbody{display:none}
.cvetab td,.hardtab td{vertical-align:top}
.cvetab a,.recontab a{color:var(--blue)}
.cvesum{font-size:12.5px;color:var(--mut);margin-top:3px;line-height:1.45}
.cvenote{font-size:12.5px;color:#f0a3a0;background:rgba(248,81,73,.08);border:1px solid #5c2b2b;border-radius:6px;padding:8px 11px;margin-top:9px}
.hardtab{font-size:13px}
.hardtab th{white-space:nowrap}
.sbom .sbomhead{cursor:pointer;user-select:none;margin:0 0 12px}
.sbom.collapsed .sbombody{display:none}
.sbomtab{font-size:13px}
.sbomtab code.sha{font-size:11.5px;color:var(--dim);word-break:break-all}
.sbomtab code.path{font-size:12px;word-break:break-all}
.nores{padding:22px;text-align:center;color:var(--dim);display:none}
.ftags{display:flex;flex-wrap:wrap;gap:6px;margin:11px 0 2px}
.ftag{display:inline-block;font-size:12px;padding:2px 9px;border-radius:11px;background:var(--panel2);color:var(--mut);border:1px solid var(--bd2);font-family:"Cascadia Code","Fira Code",Consolas,monospace}
.ftag-cwe{color:#f0908a;border-color:#5c2b2b}
.ftag-attack{color:#c4a3f5;border-color:#4a3a6e}
.ftag-tasvs{color:#7cc0ff;border-color:#234a6e}
.ftag-owasp{color:#5ad6a0;border-color:#1f5a45}
.afflist{margin:4px 0 0;padding-left:18px}
.afflist li{margin:2px 0}
.muted{color:var(--dim);font-style:italic}
.auditnotes{margin-top:11px;padding-top:9px;border-top:1px dashed var(--bd2);font-size:12.5px;color:var(--dim);line-height:1.5}
.auditnotes .anlabel{font-weight:700;color:var(--amber);text-transform:uppercase;letter-spacing:.04em;font-size:11px;margin-right:6px}
.apath{border-color:#5c2b2b;background:linear-gradient(180deg,rgba(248,81,73,.07),transparent)}
.apath .apathhead{cursor:pointer;user-select:none;margin:0 0 10px;color:var(--red)}
.apath.collapsed .apathbody{display:none}
.apath-item{padding:9px 0;border-bottom:1px solid rgba(248,81,73,.15)}
.apath-item:last-child{border-bottom:none}
.apath-top{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.apath-title{font-weight:600;font-size:13.5px;color:#f0a3a0}
.apath-fix{font-size:13px;color:var(--mut);margin:4px 0 0 2px}
.disclaimer{margin-top:44px;padding:14px 16px;border:1px solid #5c2b2b;background:rgba(248,81,73,.05);border-radius:8px;font-size:12.5px;line-height:1.6;color:#d8a3a0}
.disclaimer strong{color:var(--red)}
@media print{
  body{background:#fff;color:#000}
  .toolbar,.chip,.btn,#search,.filterbar{display:none!important}
  .sevsection.collapsed .sevbody{display:block!important}
  .fbody{display:block!important}
  .finding{break-inside:avoid;border:1px solid #ccc}
  .card{break-inside:avoid}
}
'@

        # ---------------- static JS ----------------
        $js = @'
(function(){
  var search=document.getElementById('search');
  var findings=Array.prototype.slice.call(document.querySelectorAll('.finding'));
  var sections=Array.prototype.slice.call(document.querySelectorAll('.sevsection'));
  var activeSev='ALL';
  var query='';
  var confOnly=false;
  var defaultOpen={CRITICAL:1,HIGH:1};   // sections open on load / on reset to "All"

  function apply(){
    var filtering=(activeSev!=='ALL'||query!==''||confOnly);
    findings.forEach(function(f){
      var okSev=(activeSev==='ALL'||f.getAttribute('data-sev')===activeSev);
      var okQ=(query===''||f.getAttribute('data-text').indexOf(query)>=0||f.getAttribute('data-rule').indexOf(query)>=0);
      var okConf=(!confOnly||f.getAttribute('data-proven')==='1');
      f.style.display=(okSev&&okQ&&okConf)?'':'none';
    });
    var totalVisible=0;
    sections.forEach(function(s){
      var vis=s.querySelectorAll('.finding:not([style*="display: none"])').length;
      var cnt=s.querySelector('.seccount');
      if(cnt) cnt.textContent='('+vis+')';
      s.style.display=vis>0?'':'none';
      // When filtering/searching, auto-expand any section that has matches (otherwise a
      // section that was collapsed by default -- MEDIUM/LOW/INFO -- would show its header
      // but hide every matching finding). With no filter, restore the default open state.
      if(filtering){
        if(vis>0) s.classList.remove('collapsed');
      } else {
        if(defaultOpen[s.getAttribute('data-sev')]) s.classList.remove('collapsed');
        else s.classList.add('collapsed');
      }
      totalVisible+=vis;
    });
    var nr=document.getElementById('nores');
    if(nr) nr.style.display=totalVisible===0?'block':'none';
  }

  if(search) search.addEventListener('input',function(){query=search.value.toLowerCase().trim();apply();});
  var confOnlyBox=document.getElementById('confOnly');
  if(confOnlyBox) confOnlyBox.addEventListener('change',function(){confOnly=confOnlyBox.checked;apply();});

  // per-table filters (SBOM + DLL hardening): hide non-matching tbody rows live
  document.querySelectorAll('.tabfilter').forEach(function(inp){
    inp.addEventListener('input',function(){
      var q=inp.value.toLowerCase().trim();
      var tbl=document.querySelector('table.'+inp.getAttribute('data-target'));
      if(!tbl)return;
      var shown=0;
      tbl.querySelectorAll('tbody tr').forEach(function(tr){
        var hit=(q===''||tr.textContent.toLowerCase().indexOf(q)!==-1);
        tr.style.display=hit?'':'none'; if(hit)shown++;
      });
      var cnt=inp.parentNode.querySelector('.filtcount'); if(cnt)cnt.textContent=shown+' shown';
    });
  });

  document.querySelectorAll('.chip').forEach(function(c){
    c.addEventListener('click',function(){
      document.querySelectorAll('.chip').forEach(function(x){x.classList.remove('active');});
      c.classList.add('active');
      activeSev=c.getAttribute('data-sev');
      apply();
    });
  });

  document.querySelectorAll('.fhead').forEach(function(h){
    h.addEventListener('click',function(){h.parentNode.classList.toggle('open');});
  });
  document.querySelectorAll('.vcopy').forEach(function(b){
    b.addEventListener('click',function(e){
      e.stopPropagation();
      var cmd=''; try{cmd=decodeURIComponent(escape(window.atob(b.getAttribute('data-cmd'))));}catch(err){try{cmd=window.atob(b.getAttribute('data-cmd'));}catch(e2){cmd='';}}
      var label=b.textContent;
      function done(){b.textContent='Copied';b.classList.add('copied');setTimeout(function(){b.textContent=label;b.classList.remove('copied');},1200);}
      function fallback(){var ta=document.createElement('textarea');ta.value=cmd;ta.style.position='fixed';ta.style.opacity='0';document.body.appendChild(ta);ta.focus();ta.select();try{document.execCommand('copy');done();}catch(err){}ta.remove();}
      if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(cmd).then(done,fallback);}else{fallback();}
    });
  });
  document.querySelectorAll('.sevhead').forEach(function(h){
    h.addEventListener('click',function(){h.parentNode.classList.toggle('collapsed');});
  });
  var rh=document.querySelector('.recon .reconhead');
  if(rh) rh.addEventListener('click',function(){rh.parentNode.classList.toggle('collapsed');});
  document.querySelectorAll('.cve .cvehead,.hardening .hardhead,.signing .signhead,.sbom .sbomhead,.apath .apathhead,.remed .remhead,.coverage .covhead').forEach(function(h){
    h.addEventListener('click',function(){h.parentNode.classList.toggle('collapsed');});
  });

  var ea=document.getElementById('expandAll');
  if(ea) ea.addEventListener('click',function(){findings.forEach(function(f){if(f.style.display!=='none')f.classList.add('open');});});
  var ca=document.getElementById('collapseAll');
  if(ca) ca.addEventListener('click',function(){findings.forEach(function(f){f.classList.remove('open');});});

  var rt=document.getElementById('ruleToggle');
  var rs=document.getElementById('ruleSummary');
  if(rt&&rs) rt.addEventListener('click',function(){rs.hidden=!rs.hidden;rt.classList.toggle('active');});
  document.querySelectorAll('.rulerow').forEach(function(r){
    r.addEventListener('click',function(){
      var rule=r.getAttribute('data-rule');
      if(search){search.value=rule;query=rule.toLowerCase();}
      document.querySelectorAll('.chip').forEach(function(x){x.classList.remove('active');});
      var allchip=document.querySelector('.chip[data-sev="ALL"]'); if(allchip) allchip.classList.add('active');
      activeSev='ALL';
      sections.forEach(function(s){s.classList.remove('collapsed');});
      apply();
      var tgt=document.querySelector('.finding[data-rule="'+rule+'"]');
      if(tgt) tgt.scrollIntoView({behavior:'smooth',block:'start'});
    });
  });
})();
'@

        # ---------------- toolbar ----------------
        $chips = "<span class='chip active' data-sev='ALL'>All ($($all.Count))</span>"
        foreach ($s in $sevOrder) {
            if ($sevCounts[$s] -gt 0) { $chips += "<span class='chip' data-sev='$s'>$s ($($sevCounts[$s]))</span>" }
        }
        $toolbarHtml = @"
<div class='toolbar'>
  <input id='search' type='text' placeholder='Filter findings by text, file, rule...'>
  $chips
  <button class='btn' id='expandAll'>Expand all</button>
  <button class='btn' id='collapseAll'>Collapse all</button>
  <button class='btn' id='ruleToggle'>Group by rule</button>
  <label class='cobtn' style='display:inline-flex;align-items:center;gap:5px;font-size:14px;opacity:.85;cursor:pointer' title='Show only IL/dynamic-proven and Confirmed findings; hide Inferred string-scan hits'><input type='checkbox' id='confOnly'> Confirmed only</label>
</div>
"@

        $titleApp = if ($Profile -and $Profile.Name) { ConvertTo-TcpkHtmlSafe $Profile.Name } else { 'target' }

        # Brand logo as an embedded data-URI (assets\tcpk-logo.png alongside the module). Optional.
        $logoTag = ''
        try {
            $assetLogo = Join-Path (Split-Path $script:TcpkRoot -Parent) 'assets\tcpk-logo.png'
            if (Test-Path $assetLogo) {
                $b64logo = [Convert]::ToBase64String([IO.File]::ReadAllBytes($assetLogo))
                $logoTag = "<img alt='TCPK' style='height:58px;display:block;margin:0 0 6px' src='data:image/png;base64,$b64logo'>"
            }
        } catch { $logoTag = '' }

        $html = @"
<!doctype html>
<html lang='en'>
<head>
<meta charset='utf-8'>
<meta name='viewport' content='width=device-width, initial-scale=1'>
<title>TCPK audit -- $titleApp</title>
<style>
$css
</style>
</head>
<body>
<div class='wrap'>
  $logoTag
  <h1>TCPK Security Audit Report</h1>
  <div class='sub'>Generated $generatedAt UTC &middot; $($all.Count) findings</div>

$execSummaryHtml
$cardHtml
$chartHtml
$coverageHtml
$attackPathHtml
$reconHtml
$cveHtml
$ruleSummaryHtml
$toolbarHtml

  <div id='findings'>
$($sectionHtml -join "`n")
  </div>
  <div id='nores' class='nores'>No findings match the current filter.</div>
$hardeningHtml
$signingHtml
$sbomHtml
$remediationHtml

  <footer class='disclaimer'>
    <strong>DISCLAIMER -- FOR AUTHORIZED TESTING ONLY.</strong>
    This report was produced by TCPK for authorized security testing. Use of TCPK and any
    proof-of-concept artifacts it generates is permitted ONLY against systems you own or are
    explicitly authorized to test. ANY MISUSE is solely the responsibility of the user. The
    author(s) and the open-source community accept NO liability for any damage, legal
    consequence, or misuse arising from this tool. Provided &quot;AS IS&quot;, without warranty of any kind.
  </footer>
</div>
<script>
$js
</script>
</body>
</html>
"@
        Confirm-TcpkParentDir -FilePath $OutFile
        Set-Content -LiteralPath $OutFile -Value $html -Encoding UTF8
        Write-TcpkInfo "HTML written: $OutFile ($($all.Count) findings)"
    }
}
