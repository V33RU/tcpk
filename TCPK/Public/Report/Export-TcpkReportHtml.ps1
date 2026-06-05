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
        [object[]]$Sbom = @()
    )

    begin { $all = New-Object 'System.Collections.Generic.List[object]' }
    process { foreach ($f in $Findings) { $all.Add($f) } }
    end {
        $sevOrder = @('CRITICAL','HIGH','MEDIUM','LOW','INFO')
        $sevColor = @{ CRITICAL='#9b0000'; HIGH='#c0392b'; MEDIUM='#d68910'; LOW='#117a65'; INFO='#566573' }
        $confColor = @{
            'Confirmed'='#1b4f72'; 'Inferred'='#7d6608'; 'Unverified'='#7e5109'; 'Skipped'='#566573'
            'Confirmed (LLM)'='#0e6655'; 'Likely-FP (LLM)'='#7b241c'; 'Uncertain (LLM)'='#5b2c6f'
        }
        $esc = { param($t) ConvertTo-TcpkHtmlSafe $t }

        $generatedAt = (Get-Date).ToUniversalTime().ToString('u')

        # severity counts
        $sevCounts = @{}
        foreach ($s in $sevOrder) { $sevCounts[$s] = ($all | Where-Object Severity -eq $s).Count }
        $maxCount = ($sevCounts.Values | Measure-Object -Maximum).Maximum
        if (-not $maxCount -or $maxCount -lt 1) { $maxCount = 1 }

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
                if ($Scope.Buckets) { $parts.Add("<b>Buckets:</b> " + (ConvertTo-TcpkHtmlSafe ([string]$Scope.Buckets))) }
                if ($Scope.Llm)     { $parts.Add("<b>LLM:</b> "     + (ConvertTo-TcpkHtmlSafe ([string]$Scope.Llm))) }
                if ($Scope.Timing)  { $parts.Add("<b>Time:</b> "    + (ConvertTo-TcpkHtmlSafe ([string]$Scope.Timing))) }
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

        # ---------------- severity chart ----------------
        $barRows = foreach ($s in $sevOrder) {
            $cnt = $sevCounts[$s]
            $pct = [int](100 * $cnt / $maxCount)
            "<div class='bar' data-sev='$s'><span class='barlabel'>$s</span><span class='bartrack'><span class='barfill' style='width:${pct}%;background:$($sevColor[$s])'></span></span><span class='barcount'>$cnt</span></div>"
        }
        $chartHtml = "<section class='card'><div class='chart'>" + ($barRows -join "`n") + "</div></section>"

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
  <td><code>$(ConvertTo-TcpkHtmlSafe ([string]$c.FixedVersion))</code></td>
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
  <h3 class='cvehead'><span class='caret'>&#9662;</span>Known-vulnerability matches (CVE catalog) <span class='seccount'>($(@($CveMatches).Count) match$(if (@($CveMatches).Count -ne 1){'es'}), $vulnCount vulnerable)</span></h3>
  <div class='cvebody'>
    <table class='recontab cvetab'>
      <thead><tr><th>Status</th><th>Severity</th><th>CVE</th><th>Package</th><th>Shipped</th><th>Fixed</th><th>Area</th><th>Title</th><th>Source file</th><th>Refs</th></tr></thead>
      <tbody>
$($cveRows -join "`n")
      </tbody>
    </table>
    <div class='cvenote'>Native (non-NuGet) matches are reported as <b>Present</b> / <b>PossiblyEmbedded</b> - verify the embedded build before treating them as confirmed. NuGet matches are version-compared and reliable.</div>
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
            $group = $all | Where-Object Severity -eq $sev
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
                $desc    = ConvertTo-TcpkHtmlSafe $f.Description
                $fix     = ConvertTo-TcpkHtmlSafe $f.Fix
                $cwe     = if ($f.Cwe) { ConvertTo-TcpkHtmlSafe ($f.Cwe -join ', ') } else { '' }
                $searchText = ConvertTo-TcpkHtmlSafe (("$($f.Title) $($f.RuleId) $($f.File) $($f.Evidence) $($f.Description)").ToLowerInvariant())
                $kv = New-Object 'System.Collections.Generic.List[string]'
                if ($file) { $kv.Add("<tr><th>File</th><td><code>$file</code></td></tr>") }
                if ($evid) { $kv.Add("<tr><th>Evidence</th><td><code>$evid</code></td></tr>") }
                $cvssDisp = (Get-TcpkCvssVector $f).Display
                if ($cvssDisp) { $kv.Add("<tr><th>CVSS v4.0 vector</th><td>$(ConvertTo-TcpkHtmlSafe $cvssDisp)</td></tr>") }
                if ($cwe)  { $kv.Add("<tr><th>CWE</th><td>$cwe</td></tr>") }
                $attack = ConvertTo-TcpkHtmlSafe (Get-TcpkAttackText $f.RuleId)
                if ($attack) { $kv.Add("<tr><th>ATT&amp;CK</th><td>$attack</td></tr>") }
                $tasvs = ConvertTo-TcpkHtmlSafe (Get-TcpkTasvsText $f.RuleId)
                if ($tasvs) { $kv.Add("<tr><th>OWASP TASVS / Desktop Top 10</th><td>$tasvs</td></tr>") }
                $impact = ConvertTo-TcpkHtmlSafe (Get-TcpkImpactText $f)
                if ($impact) { $kv.Add("<tr><th>Impact</th><td>$impact</td></tr>") }
                if ($desc) { $kv.Add("<tr><th>Description</th><td>$desc</td></tr>") }
                if ($fix)  { $kv.Add("<tr><th>Fix</th><td>$fix</td></tr>") }
                $verify = ConvertTo-TcpkHtmlSafe (Get-TcpkVerifyHint -RuleId $f.RuleId -File $f.File -Evidence $f.Evidence)
                if ($verify) { $kv.Add("<tr><th>Verify</th><td><code class='verify'>$verify</code></td></tr>") }
@"
<article class='finding' data-sev='$($f.Severity)' data-rule='$rule' data-text='$searchText'>
  <div class='fhead'>
    <span class='fid'>#$fid</span>
    <span class='badge' style='background:$sevHex'>$($f.Severity)</span>
    <span class='badge' style='background:$confHex'>$($f.Confidence)</span>
    <span class='ftitle'>$title</span>
    <span class='frule'>$rule</span>
  </div>
  <div class='fbody'>
    <table class='kv'>
$($kv -join "`n")
    </table>
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
      <thead><tr><th>DLL</th><th>Arch</th><th>ASLR</th><th>DEP</th><th>CFG</th><th>HighEntropyVA</th><th>SafeSEH</th><th>ForceIntegrity</th><th>Status</th><th>Missing</th></tr></thead>
      <tbody>
$($hwRows -join "`n")
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
    <div class='cvenote' style='color:#566573;background:#f7f8fa;border-color:#e1e1e1'>Full CycloneDX 1.5 inventory (with hashes + purls) is also written to <code>sbom.cdx.json</code> alongside this report.</div>
  </div>
</section>
"@
        }

        # ---------------- static CSS ----------------
        $css = @'
*{box-sizing:border-box}
body{font-family:-apple-system,"Segoe UI",system-ui,sans-serif;margin:0;background:#f4f5f7;color:#222;line-height:1.5}
.wrap{max-width:1140px;margin:0 auto;padding:24px 22px 96px}
h1{font-size:24px;margin:0}
.sub{color:#666;font-size:13px;margin:2px 0 18px}
.card{background:#fff;border:1px solid #e1e1e1;border-radius:8px;padding:16px 18px;margin:0 0 16px;box-shadow:0 1px 2px rgba(0,0,0,.03)}
.target .kvgrid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:4px 26px}
.kvi{display:flex;gap:10px;font-size:13px;padding:3px 0;border-bottom:1px solid #f0f0f0}
.kvi .k{color:#888;min-width:92px;font-weight:600}
.kvi .v{color:#222;word-break:break-word}
.stack{margin-top:12px}
.stackrow{display:flex;flex-wrap:wrap;align-items:center;gap:6px;margin:6px 0}
.stacklabel{font-size:11px;font-weight:700;color:#888;text-transform:uppercase;letter-spacing:.05em;min-width:62px}
.tag{display:inline-block;font-size:12px;padding:3px 9px;border-radius:12px;background:#eef;color:#234;border:1px solid #dde}
.tag-ui{background:#eaf2fb;border-color:#cfe0f5;color:#1c4f80}
.tag-net{background:#eafaf1;border-color:#c8eed8;color:#127a4a}
.tag-upd{background:#fef5e7;border-color:#f7e0b0;color:#8a5b00}
.tag-sdk{background:#f3eefb;border-color:#e2d4f5;color:#5b2c87}
.surfrow{display:flex;flex-wrap:wrap;gap:8px;margin-top:14px}
.surf{flex:1 1 80px;min-width:80px;text-align:center;background:#fafbfc;border:1px solid #ececec;border-radius:6px;padding:8px 6px}
.surf b{display:block;font-size:19px;color:#222}
.surf span{font-size:11px;color:#888;text-transform:uppercase;letter-spacing:.04em}
.scope{margin-top:14px;padding-top:10px;border-top:1px solid #eee;font-size:12px;color:#555}
.chart{display:flex;flex-direction:column;gap:6px}
.bar{display:flex;align-items:center;gap:10px;font-size:13px}
.barlabel{min-width:72px;font-weight:600;color:#444}
.bartrack{flex:1;background:#eee;border-radius:4px;height:16px;overflow:hidden}
.barfill{display:block;height:100%}
.barcount{min-width:36px;text-align:right;font-weight:700}
.toolbar{position:sticky;top:0;z-index:20;display:flex;flex-wrap:wrap;gap:8px;align-items:center;background:#f4f5f7;padding:10px 0;margin-bottom:10px;border-bottom:1px solid #e1e1e1}
#search{flex:1;min-width:200px;padding:8px 12px;border:1px solid #ccc;border-radius:6px;font-size:14px}
.filterbar{display:flex;align-items:center;gap:10px;margin:0 0 10px}
.tabfilter{flex:1;max-width:460px;padding:6px 10px;border:1px solid #ccc;border-radius:6px;font-size:13px}
.filtcount{color:#566573;font-size:12px}
.chip{cursor:pointer;font-size:12px;font-weight:600;padding:6px 11px;border-radius:14px;border:1px solid #ccc;background:#fff;color:#444;user-select:none}
.chip.active{background:#222;color:#fff;border-color:#222}
.btn{cursor:pointer;font-size:12px;padding:6px 11px;border-radius:6px;border:1px solid #ccc;background:#fff;color:#333}
.btn:hover{background:#f0f0f0}
.sevsection{margin:10px 0}
.sevhead{font-size:18px;margin:14px 0 8px;cursor:pointer;user-select:none;padding-bottom:6px;border-bottom:2px solid #e1e1e1}
.caret{display:inline-block;width:16px;transition:transform .15s}
.sevsection.collapsed .caret{transform:rotate(-90deg)}
.sevsection.collapsed .sevbody{display:none}
.seccount{color:#999;font-weight:400;font-size:14px}
.finding{background:#fff;border:1px solid #e3e3e3;border-radius:6px;margin:8px 0;overflow:hidden}
.fhead{display:flex;flex-wrap:wrap;align-items:center;gap:8px;padding:10px 14px;cursor:pointer}
.fhead:hover{background:#fafafa}
.fid{font-family:Consolas,monospace;font-size:12px;color:#999;font-weight:700}
.badge{display:inline-block;font-size:10px;font-weight:700;letter-spacing:.05em;padding:3px 7px;border-radius:3px;color:#fff;text-transform:uppercase}
.ftitle{font-weight:600;font-size:14px;flex:1;min-width:160px}
.frule{font-family:Consolas,monospace;font-size:11px;color:#888}
.fbody{display:none;padding:0 14px 12px;border-top:1px solid #f0f0f0}
.finding.open .fbody{display:block}
.kv{width:100%;border-collapse:collapse;margin-top:8px}
.kv th{text-align:left;vertical-align:top;padding:4px 12px 4px 0;font-weight:600;font-size:12px;color:#666;width:100px}
.kv td{padding:4px 0;font-size:13px;vertical-align:top}
code{font-family:Consolas,Menlo,monospace;font-size:12px;background:#f4f4f4;padding:1px 5px;border-radius:3px;word-break:break-word}
code.verify{display:block;white-space:pre-wrap;padding:8px 10px;background:#1e1e1e;color:#d4d4d4;line-height:1.5;border-left:3px solid #2874a6}
.ruletable{width:100%;border-collapse:collapse;font-size:13px}
.ruletable th,.ruletable td{padding:6px 10px;border-bottom:1px solid #eee;text-align:left}
.ruletable .num{text-align:right}
.rulerow{cursor:pointer}
.rulerow:hover{background:#f6f6f6}
h3{font-size:15px;margin:0 0 10px}
.recon .reconhead{cursor:pointer;user-select:none;margin:0 0 12px}
.recon.collapsed .reconbody{display:none}
.reconblock{margin:0 0 16px}
.reconblock h4{font-size:13px;margin:0 0 6px;color:#2c3e50;text-transform:uppercase;letter-spacing:.03em;border-left:3px solid #2874a6;padding-left:8px}
.recontab{width:100%;border-collapse:collapse;font-size:12.5px;margin-bottom:4px}
.recontab th{text-align:left;background:#f4f6f8;padding:5px 9px;border-bottom:2px solid #e1e1e1;font-size:11px;text-transform:uppercase;letter-spacing:.03em;color:#566573}
.recontab td{padding:5px 9px;border-bottom:1px solid #eee;vertical-align:top;word-break:break-word}
.recontab tr:hover{background:#fafbfc}
.reconlist{margin:4px 0 4px 4px;padding-left:18px;font-size:13px}
.reconlist li{margin:2px 0}
.emptynote{font-size:12.5px;color:#999;font-style:italic;padding:4px 0 4px 11px}
.cve .cvehead,.hardening .hardhead{cursor:pointer;user-select:none;margin:0 0 12px}
.cve.collapsed .cvebody,.hardening.collapsed .hardbody{display:none}
.cvetab td,.hardtab td{vertical-align:top}
.cvetab a,.recontab a{color:#1c4f80}
.cvesum{font-size:11.5px;color:#666;margin-top:3px;line-height:1.4}
.cvenote{font-size:11.5px;color:#7b241c;background:#fdf3f3;border:1px solid #e3b7b7;border-radius:5px;padding:7px 10px;margin-top:8px}
.hardtab{font-size:12px}
.hardtab th{white-space:nowrap}
.sbom .sbomhead{cursor:pointer;user-select:none;margin:0 0 12px}
.sbom.collapsed .sbombody{display:none}
.sbomtab{font-size:12px}
.sbomtab code.sha{font-size:10.5px;color:#566573;word-break:break-all}
.sbomtab code.path{font-size:11px;word-break:break-all}
.nores{padding:20px;text-align:center;color:#999;display:none}
.disclaimer{margin-top:40px;padding:14px 16px;border:1px solid #e3b7b7;background:#fdf3f3;border-radius:6px;font-size:11.5px;line-height:1.6;color:#7b241c}
.disclaimer strong{color:#9b0000}
@media print{
  body{background:#fff}
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

  function apply(){
    findings.forEach(function(f){
      var okSev=(activeSev==='ALL'||f.getAttribute('data-sev')===activeSev);
      var okQ=(query===''||f.getAttribute('data-text').indexOf(query)>=0||f.getAttribute('data-rule').indexOf(query)>=0);
      f.style.display=(okSev&&okQ)?'':'none';
    });
    var totalVisible=0;
    sections.forEach(function(s){
      var vis=s.querySelectorAll('.finding:not([style*="display: none"])').length;
      var cnt=s.querySelector('.seccount');
      if(cnt) cnt.textContent='('+vis+')';
      s.style.display=vis>0?'':'none';
      totalVisible+=vis;
    });
    var nr=document.getElementById('nores');
    if(nr) nr.style.display=totalVisible===0?'block':'none';
  }

  if(search) search.addEventListener('input',function(){query=search.value.toLowerCase().trim();apply();});

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
  document.querySelectorAll('.sevhead').forEach(function(h){
    h.addEventListener('click',function(){h.parentNode.classList.toggle('collapsed');});
  });
  var rh=document.querySelector('.recon .reconhead');
  if(rh) rh.addEventListener('click',function(){rh.parentNode.classList.toggle('collapsed');});
  document.querySelectorAll('.cve .cvehead,.hardening .hardhead,.sbom .sbomhead').forEach(function(h){
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

$cardHtml
$reconHtml
$chartHtml
$cveHtml
$ruleSummaryHtml
$toolbarHtml

  <div id='findings'>
$($sectionHtml -join "`n")
  </div>
  <div id='nores' class='nores'>No findings match the current filter.</div>
$hardeningHtml
$sbomHtml

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
