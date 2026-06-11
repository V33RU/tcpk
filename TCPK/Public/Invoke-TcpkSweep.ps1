function Invoke-TcpkSweep {
<#
.SYNOPSIS
    Audit MANY install locations in one call -- explicit list and/or auto-discovery --
    then write a merged summary across all of them.

.DESCRIPTION
    Apps (especially Electron / electron-builder / MSI installers) scatter across
    several folders: Programs, Local, Roaming, Program Files. Invoke-TcpkAudit takes
    ONE -Target; this driver runs it once per location into its own subfolder, then
    rolls the results up into a single sweep report.

    Targets come from either or both of:
      -Target   an explicit list of directories / files
      -AppName  auto-discovered: every top-level folder matching *AppName* across the
                usual install roots (Get-TcpkInstallLocations)

    Each target gets a full audit (its own report.html / .xlsx / findings.json in a
    subfolder of -OutDir). The sweep then writes, at the OutDir root:
      sweep-summary.json    per-target severity counts + paths
      sweep-findings.json   the merged finding set (each finding keeps its File path,
                            so its source location is unambiguous)
      sweep-summary.html    one self-contained page: per-target matrix + links +
                            the combined CRITICAL/HIGH list (no server, just a file)

.PARAMETER Target
    One or more directories / files to audit.

.PARAMETER AppName
    Discover install locations by name (e.g. 'myapp') across Programs / Local / Roaming /
    Program Files / ProgramData.

.PARAMETER Root
    Override the discovery roots (mainly for testing).

.PARAMETER OutDir
    Parent output directory. Each target audits into OutDir\<sanitized-name>.

.PARAMETER Acknowledge
    Pass-through to each Invoke-TcpkAudit. Recommended -- without it every per-target
    audit prompts interactively.

.PARAMETER EnableLlm / AllowCloudLlm
    Pass-through to each audit (see Invoke-TcpkAudit).

.PARAMETER FailOn
    INFO/LOW/MEDIUM/HIGH/CRITICAL -- throw at the end if ANY finding across ALL targets
    meets or exceeds the threshold (CI gate).

.EXAMPLE
    Invoke-TcpkSweep -AppName myapp -OutDir .\out\myapp -Acknowledge

.EXAMPLE
    Invoke-TcpkSweep -Target 'C:\App\v1','C:\App\v2' -OutDir .\out\app -Acknowledge

.OUTPUTS
    [TcpkFinding[]] -- the merged finding set across every target.
#>
    [CmdletBinding()]
    param(
        [string[]]$Target,
        [string]$AppName,
        [string[]]$Root,
        [string]$OutDir = '.\tcpk-sweep',
        [switch]$Acknowledge,
        [switch]$EnableLlm,
        [switch]$AllowCloudLlm,
        [ValidateSet('INFO','LOW','MEDIUM','HIGH','CRITICAL')][string]$FailOn
    )

    # ---- resolve the target set (AppName discovery + explicit Target), de-duplicated ----
    $set  = New-Object 'System.Collections.Generic.List[string]'
    $seen = New-Object 'System.Collections.Generic.HashSet[string]'
    $add = {
        param($p)
        if (-not $p) { return }
        $full = "$p"; try { $full = (Resolve-Path -LiteralPath $p -ErrorAction Stop).Path } catch { }
        if (Test-Path -LiteralPath $full) {
            if ($seen.Add($full.ToLowerInvariant())) { $set.Add($full) }
        } else {
            Write-Warning "Sweep: target not found, skipping: $p"
        }
    }
    if ($AppName) { foreach ($d in (Get-TcpkInstallLocations -AppName $AppName -Root $Root)) { & $add $d } }
    if ($Target)  { foreach ($t in $Target) { & $add $t } }
    if (-not $set.Count) { throw "Invoke-TcpkSweep: no targets resolved. Use -Target and/or -AppName." }

    Write-TcpkInfo "Sweep: $($set.Count) target(s) -> $OutDir"
    New-Item -ItemType Directory -Path $OutDir -Force -ErrorAction SilentlyContinue | Out-Null

    # ---- per-target audit ----
    $merged    = New-Object 'System.Collections.Generic.List[object]'
    $rows      = New-Object 'System.Collections.Generic.List[object]'
    $usedNames = New-Object 'System.Collections.Generic.HashSet[string]'
    $sevs = @('CRITICAL','HIGH','MEDIUM','LOW','INFO')

    foreach ($t in $set) {
        $leaf = ($t -replace '[^A-Za-z0-9._-]','_').Trim('_')
        if (-not $leaf) { $leaf = 'target' }
        if ($leaf.Length -gt 40) { $leaf = $leaf.Substring($leaf.Length - 40) }
        $name = $leaf; $i = 1
        while (-not $usedNames.Add($name)) { $name = "${leaf}_$i"; $i++ }
        $sub = Join-Path $OutDir $name

        Write-TcpkInfo "Sweep: auditing $t"
        $f = @()
        try {
            $f = @(Invoke-TcpkAudit -Target $t -OutDir $sub -Acknowledge:$Acknowledge `
                    -EnableLlm:$EnableLlm -AllowCloudLlm:$AllowCloudLlm)
        } catch {
            Write-Warning "Sweep: audit failed for $t : $($_.Exception.Message)"
        }
        foreach ($x in $f) { $merged.Add($x) }

        $counts = @{}
        foreach ($sev in $sevs) { $counts[$sev] = @($f | Where-Object { "$($_.Severity)" -eq $sev }).Count }
        $rows.Add([pscustomobject]@{
            Target = $t; Name = $name; Report = (Join-Path $name 'report.html')
            Total = @($f).Count
            CRITICAL = $counts.CRITICAL; HIGH = $counts.HIGH; MEDIUM = $counts.MEDIUM
            LOW = $counts.LOW; INFO = $counts.INFO
        })
    }

    # ---- merged outputs ----
    $genUtc = (Get-Date).ToUniversalTime().ToString('u')
    ([pscustomobject]@{
        appName = "$AppName"; generated = $genUtc
        targetCount = $set.Count; totalFindings = $merged.Count
        perTarget = $rows
    } | ConvertTo-Json -Depth 6) | Set-Content -LiteralPath (Join-Path $OutDir 'sweep-summary.json') -Encoding UTF8

    ($merged | ConvertTo-Json -Depth 6) | Set-Content -LiteralPath (Join-Path $OutDir 'sweep-findings.json') -Encoding UTF8

    # self-contained HTML summary (ASCII only -- report-output rule)
    $sevColor = @{ CRITICAL='#f85149'; HIGH='#db6d28'; MEDIUM='#d29922'; LOW='#3fb950'; INFO='#8b949e' }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append("<!doctype html><html><head><meta charset='utf-8'><title>TCPK sweep</title><style>")
    [void]$sb.Append("body{background:#0d1117;color:#e6edf3;font-family:Segoe UI,Arial,sans-serif;margin:24px}")
    [void]$sb.Append("h1{font-family:Consolas,monospace}a{color:#58a6ff}")
    [void]$sb.Append("table{border-collapse:collapse;width:100%;margin:12px 0}")
    [void]$sb.Append("th,td{border:1px solid #30363d;padding:6px 10px;text-align:left;font-size:13px}")
    [void]$sb.Append("th{background:#161b22}td.n{text-align:right;font-family:Consolas,monospace}")
    [void]$sb.Append(".pill{padding:1px 7px;border-radius:9px;font-size:11px;font-family:Consolas,monospace}")
    [void]$sb.Append("</style></head><body>")
    [void]$sb.Append("<h1>TCPK sweep summary</h1>")
    [void]$sb.Append("<p>App: <b>$([System.Net.WebUtility]::HtmlEncode("$AppName"))</b> &middot; targets: $($set.Count) &middot; total findings: $($merged.Count) &middot; generated $genUtc UTC</p>")
    [void]$sb.Append("<table><tr><th>Target</th><th>Crit</th><th>High</th><th>Med</th><th>Low</th><th>Info</th><th>Total</th><th>Report</th></tr>")
    foreach ($r in $rows) {
        $tEnc = [System.Net.WebUtility]::HtmlEncode($r.Target)
        $rep  = [System.Net.WebUtility]::HtmlEncode($r.Report)
        [void]$sb.Append("<tr><td>$tEnc</td><td class='n'>$($r.CRITICAL)</td><td class='n'>$($r.HIGH)</td><td class='n'>$($r.MEDIUM)</td><td class='n'>$($r.LOW)</td><td class='n'>$($r.INFO)</td><td class='n'>$($r.Total)</td><td><a href='$rep'>open</a></td></tr>")
    }
    [void]$sb.Append("</table>")
    # combined CRITICAL + HIGH list
    $top = @($merged | Where-Object { "$($_.Severity)" -in 'CRITICAL','HIGH' } |
             Sort-Object @{E={ switch("$($_.Severity)"){'CRITICAL'{0}'HIGH'{1}default{2}} }}, RuleId)
    [void]$sb.Append("<h2>Critical &amp; High across all targets ($($top.Count))</h2>")
    if ($top.Count) {
        [void]$sb.Append("<table><tr><th>Severity</th><th>Confidence</th><th>Rule</th><th>Title</th><th>File</th></tr>")
        foreach ($x in $top) {
            $col = $sevColor["$($x.Severity)"]; if (-not $col) { $col = '#8b949e' }
            $title = [System.Net.WebUtility]::HtmlEncode("$($x.Title)")
            $file  = [System.Net.WebUtility]::HtmlEncode("$($x.File)")
            [void]$sb.Append("<tr><td><span class='pill' style='background:$col;color:#0d1117'>$($x.Severity)</span></td><td>$([System.Net.WebUtility]::HtmlEncode("$($x.Confidence)"))</td><td>$([System.Net.WebUtility]::HtmlEncode("$($x.RuleId)"))</td><td>$title</td><td>$file</td></tr>")
        }
        [void]$sb.Append("</table>")
    } else {
        [void]$sb.Append("<p>None.</p>")
    }
    [void]$sb.Append("</body></html>")
    Set-Content -LiteralPath (Join-Path $OutDir 'sweep-summary.html') -Value $sb.ToString() -Encoding UTF8

    # ---- console summary ----
    Write-TcpkInfo "Sweep complete: $($merged.Count) findings across $($set.Count) target(s). See $OutDir\sweep-summary.html"
    $rows | Format-Table Name, CRITICAL, HIGH, MEDIUM, LOW, INFO, Total -AutoSize | Out-Host

    # ---- CI gate ----
    if ($FailOn) {
        $rank = @{ 'INFO'=0;'LOW'=1;'MEDIUM'=2;'HIGH'=3;'CRITICAL'=4 }
        $thr  = $rank[$FailOn]
        $hit  = @($merged | Where-Object { $rank["$($_.Severity)"] -ge $thr })
        if ($hit.Count) { throw "Invoke-TcpkSweep: $($hit.Count) finding(s) at or above $FailOn across the sweep." }
    }

    return ,$merged.ToArray()
}
