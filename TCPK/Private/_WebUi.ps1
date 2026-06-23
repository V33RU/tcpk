# TCPK local web control panel -- internals.
#
# A loopback-only HTTP server (raw TcpListener, no HttpListener urlacl / no admin, no
# external deps) that lets a browser DRIVE a discovery audit and view the result in the
# intelligence dashboard. Security model (see Start-TcpkWebUi):
#   * binds 127.0.0.1 ONLY                         -> no other host can reach it
#   * every /api/* call needs an X-TCPK-Token       -> a custom header a cross-origin
#     header matching the per-session token            site cannot set without a CORS
#                                                       preflight we never allow (kills
#                                                       localhost-CSRF / DNS-rebind)
#   * Host header must be 127.0.0.1:<port>          -> anti DNS-rebind
#   * the API exposes a FIXED verb set, never        -> the browser cannot send arbitrary
#     arbitrary PowerShell; target is a path           PowerShell, and the exploit bucket
#     validated to exist                               ($script:TcpkExploitEnabled) is
#                                                       NEVER touched here -- discovery only
#
# Pure helpers (token / host / auth / target / routing / dispatch / SPA html) are unit-
# testable WITHOUT a socket; only the accept loop in Start-TcpkWebUi needs the network.

# --- session token (per launch) ------------------------------------------------
function New-TcpkWebToken {
    [CmdletBinding()] param()
    $bytes = New-Object byte[] 24
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    -join ($bytes | ForEach-Object { $_.ToString('x2') })
}

# --- request authentication (pure) ---------------------------------------------
function Test-TcpkWebHost {
    [CmdletBinding()]
    param([AllowNull()][string]$HostHeader, [Parameter(Mandatory)][int]$Port)
    if (-not $HostHeader) { return $false }
    $h = $HostHeader.Trim()
    $name = $h; $hp = -1
    $ci = $h.LastIndexOf(':')
    if ($ci -ge 0) { $name = $h.Substring(0, $ci); [int]::TryParse($h.Substring($ci + 1), [ref]$hp) | Out-Null }
    if ($name -notin '127.0.0.1', 'localhost') { return $false }
    if ($ci -ge 0 -and $hp -ne $Port) { return $false }
    return $true
}

function Test-TcpkWebRequestAuth {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Request, [Parameter(Mandatory)][string]$Token, [Parameter(Mandatory)][int]$Port)
    if (-not (Test-TcpkWebHost $Request.Headers['host'] $Port)) { return $false }
    $tok = "$($Request.Headers['x-tcpk-token'])"
    return ($tok.Length -gt 0 -and $tok -ceq $Token)
}

# --- target validation (pure) --------------------------------------------------
function Resolve-TcpkWebTarget {
    [CmdletBinding()]
    param([AllowNull()][string]$Raw)
    if ([string]::IsNullOrWhiteSpace($Raw)) { return $null }
    $p = $Raw.Trim().Trim('"')
    try { $rp = (Resolve-Path -LiteralPath $p -ErrorAction Stop).Path } catch { return $null }
    if (-not (Test-Path -LiteralPath $rp)) { return $null }
    return $rp
}

# --- response builders ---------------------------------------------------------
function New-TcpkWebJson {
    [CmdletBinding()] param([int]$Status, $Obj)
    @{ Status = $Status; ContentType = 'application/json; charset=utf-8'; Body = ($Obj | ConvertTo-Json -Depth 8) }
}

# --- installed-app discovery for the picker ------------------------------------
function Find-TcpkWebApps {
    [CmdletBinding()] param([string]$Query)
    if ([string]::IsNullOrWhiteSpace($Query)) { return @() }
    $q = $Query.Trim()
    # Primary: filter the registry-derived list (rich name/path/publisher/version).
    $hits = @(@(Get-TcpkInstalledApps) | Where-Object { "$($_.name)" -like "*$q*" -or "$($_.path)" -like "*$q*" })
    if ($hits.Count) { return $hits }
    # Fallback: scan common install roots for a folder whose NAME matches. Note:
    # Get-TcpkInstallLocations returns PATH STRINGS (not objects), and ',@()'-wraps its
    # result, so flatten defensively and build the display object from each path.
    $dirs = @(); try { $dirs = @(Get-TcpkInstallLocations -AppName $q) } catch { }
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($d in $dirs) {
        if ($d -is [System.Array]) { $paths = $d } else { $paths = @($d) }
        foreach ($pp in $paths) {
            $p = "$pp"; if ([string]::IsNullOrWhiteSpace($p)) { continue }
            $out.Add([ordered]@{ name = (Split-Path $p -Leaf); path = $p; publisher = ''; version = '' })
        }
    }
    @($out.ToArray())
}

# --- installed-app enumeration: list ALL (registry Uninstall) for auto-detect --
function Get-TcpkInstalledApps {
    [CmdletBinding()] param([int]$Max = 400)
    $seen = @{}; $out = New-Object System.Collections.Generic.List[object]
    $keys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    foreach ($k in $keys) {
        $items = @()
        try { $items = @(Get-ItemProperty -Path $k -ErrorAction SilentlyContinue) } catch { }
        foreach ($p in $items) {
            $name = "$($p.DisplayName)"; if (-not $name) { continue }
            $loc = "$($p.InstallLocation)".Trim().Trim('"'); if (-not $loc) { continue }
            if (-not (Test-Path -LiteralPath $loc)) { continue }
            $key = $loc.ToLowerInvariant(); if ($seen.ContainsKey($key)) { continue }
            $seen[$key] = $true
            $out.Add([ordered]@{ name = $name; path = $loc; publisher = "$($p.Publisher)"; version = "$($p.DisplayVersion)" })
            if ($out.Count -ge $Max) { break }
        }
        if ($out.Count -ge $Max) { break }
    }
    # Emit the items individually (NOT ',@(...)') so a caller's @(...) collects a FLAT
    # array of app objects. The leading-comma idiom double-wrapped this into [[...]],
    # which made /api/apps return a nested array the SPA could not render.
    $out | Sort-Object { "$($_.name)" }
}

# --- target identity auto-detect (mirror of the desktop GUI Auto-Detect) -------
# Derive PackageName / PackageFamilyName / ProcessName from a target path. A WindowsApps
# MSIX path yields the package identity by regex; a classic install folder uses the leaf
# folder name + the largest top-level .exe as the process guess. Operator-editable hints,
# not authoritative -- same behaviour as the desktop GUI's Auto-Detect button.
function Resolve-TcpkWebIdentity {
    [CmdletBinding()] param([AllowNull()][string]$Path)
    $res = [ordered]@{ packageName = ''; packageFamilyName = ''; processName = ''; note = '' }
    $p = Resolve-TcpkWebTarget $Path
    if (-not $p) { $res.note = 'target not found -- enter a valid path first'; return $res }
    if ($p -match 'WindowsApps\\([A-Za-z0-9.\-]+)_[\d.]+_[a-z0-9]+__([a-z0-9]+)') {
        $res.packageName = $matches[1]
        $res.packageFamilyName = "$($matches[1])_$($matches[2])"
    } elseif (Test-Path -LiteralPath $p -PathType Container) {
        $res.packageName = (Split-Path $p -Leaf)
    } else {
        $res.packageName = [System.IO.Path]::GetFileNameWithoutExtension($p)
    }
    try {
        if (Test-Path -LiteralPath $p -PathType Container) {
            $exe = Get-ChildItem -LiteralPath $p -Filter '*.exe' -File -ErrorAction SilentlyContinue |
                   Sort-Object Length -Descending | Select-Object -First 1
            if ($exe) { $res.processName = $exe.BaseName }
        } elseif ($p -match '\.exe$') {
            $res.processName = [System.IO.Path]::GetFileNameWithoutExtension($p)
        }
    } catch { }
    $res.note = if ($res.processName) { "detected: $($res.packageName) / process '$($res.processName)' -- edit if wrong" }
                else { "detected package '$($res.packageName)'; no top-level .exe -- set ProcessName manually" }
    return $res
}

# POST /api/identify {path} -- auto-detect the package/process identity for a target.
function Invoke-TcpkWebIdentify {
    [CmdletBinding()] param([Parameter(Mandatory)]$Request)
    $b = $null; try { $b = $Request.Body | ConvertFrom-Json } catch { }
    $path = if ($b) { "$($b.path)" } else { '' }
    return (New-TcpkWebJson 200 (Resolve-TcpkWebIdentity -Path $path))
}

# --- AI provider config + connectivity test ------------------------------------
# Write the operator's chosen provider/model/key to llm-config.json (read by the audit
# job). Mirrors the desktop GUI's Set-AiConfigFromGui. The key stays in the local,
# gitignored llm-config.json -- same as the GUI.
function Set-TcpkWebLlmConfig {
    [CmdletBinding()] param([Parameter(Mandatory)]$Body)
    $prov = "$($Body.provider)"; if (-not $prov) { $prov = 'ollama' }
    $cfgArgs = @{ Provider = $prov; Enabled = $true }
    if ("$($Body.model)")   { $cfgArgs.Model   = "$($Body.model)" }
    if ("$($Body.apiKey)")  { $cfgArgs.ApiKey  = "$($Body.apiKey)" }
    if ("$($Body.baseUrl)") { $cfgArgs.BaseUrl = "$($Body.baseUrl)" }
    try { Set-TcpkLlmConfig @cfgArgs | Out-Null } catch { }
}

# POST /api/testai -- set the config, then ping the provider (Test-TcpkLlmAvailable).
# The ping sends NO decompiled code (just a /models or 1-token request), so for a cloud
# provider we flip the in-session cloud gate to let the connectivity check run.
function Test-TcpkWebLlm {
    [CmdletBinding()] param([Parameter(Mandatory)]$Request)
    $b = $null; try { $b = $Request.Body | ConvertFrom-Json } catch { }
    if (-not $b) { return (New-TcpkWebJson 400 @{ error = 'bad body' }) }
    Set-TcpkWebLlmConfig -Body $b
    $reachable = $false; $err = ''; $cloud = $false
    try {
        $cloud = [bool](Test-TcpkLlmIsCloud)
        if ($cloud) { $script:TcpkLlmCloudEnabled = $true }   # ping only; no IL leaves the box
        $reachable = [bool](Test-TcpkLlmAvailable)
    } catch { $err = "$($_.Exception.Message)" }
    return (New-TcpkWebJson 200 @{ reachable = $reachable; provider = "$($b.provider)"; cloud = $cloud; error = $err })
}

# --- async audit jobs ----------------------------------------------------------
# The audit runs in a background Start-Job (separate process) so the single-threaded
# server stays responsive to /api/status polls. Output is tagged LOG\t.. / FND\t..
# exactly like the desktop GUI; pause/resume is a signal file the audit polls
# (-PauseSignalPath). DISCOVERY ONLY -- no exploit switch is ever forwarded.
function Get-TcpkWebAuditJobScript {
    return {
        param($modulePath, $params)
        Import-Module $modulePath -Force
        Invoke-TcpkAudit @params 6>&1 | ForEach-Object {
            if ($_ -is [string]) { if ($_ -notmatch '^LOGX\t') { "LOG`t$_" } }
            elseif ($_ -is [System.Management.Automation.InformationRecord]) { $t = "$_"; if ($t -notmatch '^LOGX\t') { "LOG`t$t" } }
            elseif ($_.GetType().Name -eq 'TcpkFinding') { "FND`t$($_.Severity)`t$($_.Confidence)`t$($_.RuleId)`t$($_.Title)" }
        }
    }
}

function Start-TcpkWebAuditJob {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Request, [Parameter(Mandatory)]$State)
    $bodyObj = $null; try { $bodyObj = $Request.Body | ConvertFrom-Json } catch { }
    $rawTarget = if ($bodyObj) { "$($bodyObj.target)" } else { '' }
    $target = Resolve-TcpkWebTarget $rawTarget
    if (-not $target) { return (New-TcpkWebJson 400 @{ error = "target not found or invalid: $rawTarget" }) }

    $jobId = [guid]::NewGuid().ToString('N')
    # Write reports to a persistent, discoverable <repo-parent>\out\<target>_<stamp> folder -- the
    # SAME location the desktop GUI uses -- instead of a throwaway %TEMP% dir. Tests pass
    # $State.OutRoot to redirect into a temp dir; falls back to %TEMP% if the root cannot resolve.
    $stamp = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
    $leaf = try { Split-Path $target -Leaf } catch { '' }; if (-not $leaf) { $leaf = 'audit' }
    $outRoot = if ("$($State.OutRoot)") { "$($State.OutRoot)" } else { try { Split-Path -Parent (Split-Path -Parent $script:TcpkRoot) } catch { $null } }
    $outDir = if ($outRoot) { Join-Path $outRoot "out\${leaf}_$stamp" } else { Join-Path ([IO.Path]::GetTempPath()) ("tcpk-web-" + $jobId) }
    if (-not (Test-Path -LiteralPath $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }
    $pauseFlag = Join-Path ([IO.Path]::GetTempPath()) ("tcpk-webpause-" + $jobId + ".flag")

    $params = @{ Target = $target; OutDir = $outDir; Acknowledge = $true; PauseSignalPath = $pauseFlag }
    if ($bodyObj) {
        if ("$($bodyObj.packageName)")       { $params.PackageName = "$($bodyObj.packageName)" }
        if ("$($bodyObj.packageFamilyName)") { $params.PackageFamilyName = "$($bodyObj.packageFamilyName)" }
        if ("$($bodyObj.processName)")       { $params.ProcessName = "$($bodyObj.processName)" }
        if ("$($bodyObj.profile)" -in 'Quick', 'Standard', 'Full') { $params.ScanProfile = "$($bodyObj.profile)" }
        if ($bodyObj.deepRuntime) { $params.EnableDeepRuntime = $true }
        if ($bodyObj.onlineCve)   { $params.OnlineCve = $true }   # opt-in OSV live CVE (discovery-only)
        if ($bodyObj.enableLlm) {
            $params.EnableLlm = $true
            # Apply the chosen provider/model/key to llm-config.json so the audit job (a
            # fresh process that reads that file) actually uses them -- mirrors the desktop
            # GUI's Set-AiConfigFromGui. Without this the AI fields would be decorative.
            Set-TcpkWebLlmConfig -Body $bodyObj
            if ($bodyObj.allowCloudLlm) { $params.AllowCloudLlm = $true }
        }
    }

    $job = Start-Job -ScriptBlock (Get-TcpkWebAuditJobScript) -ArgumentList $State.Psd1, $params
    $State.Jobs[$jobId] = @{
        Job = $job; OutDir = $outDir; PauseFlag = $pauseFlag; Target = $target
        Log = (New-Object System.Collections.Generic.List[string])
        Findings = (New-Object System.Collections.Generic.List[object])
        Done = $false; Result = $null; ChecksDone = 0; Paused = $false
    }
    return (New-TcpkWebJson 200 @{ jobId = $jobId; total = $State.ChkTotal })
}

function Read-TcpkJsonFile {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    try { return (Get-Content -LiteralPath $Path -Raw -ErrorAction Stop | ConvertFrom-Json) } catch { return $null }
}

function Build-TcpkWebResult {
    param($Entry, $State)
    $od = $Entry.OutDir
    $findings = @(Read-TcpkJsonFile (Join-Path $od 'findings.json'))
    $prof = Read-TcpkJsonFile (Join-Path $od 'profile.json')
    $model = $null
    try { $model = Get-TcpkIntelModel -Findings $findings -Target $Entry.Target -Profile $prof } catch { }
    $reportFiles = @(
        @{ file = 'index.html';   label = 'HTML report' },
        @{ file = 'intel.html';   label = 'Intel report (dashboard)' },
        @{ file = 'report.md';    label = 'Markdown report' },
        @{ file = 'report.xlsx';  label = 'Excel report' },
        @{ file = 'report.sarif'; label = 'SARIF (code-scanning)' },
        @{ file = 'sbom.cdx.json';label = 'SBOM (CycloneDX)' },
        @{ file = 'run.log';      label = 'Run log (text)' }
    )
    $reports = New-Object System.Collections.Generic.List[object]
    foreach ($r in $reportFiles) { if (Test-Path -LiteralPath (Join-Path $od $r.file)) { $reports.Add([ordered]@{ file = $r.file; label = $r.label }) } }
    $logs = @()
    try { $logs = @(Get-Content -LiteralPath (Join-Path $od 'run.jsonl') -ErrorAction SilentlyContinue | Where-Object { $_ } | ForEach-Object { $_ | ConvertFrom-Json }) } catch { }
    # $reports is a generic List -> set via indexer (see the @() / [ordered] gotcha above).
    $res = [ordered]@{
        model     = $model
        recon     = $prof
        sbom      = (Read-TcpkJsonFile (Join-Path $od 'sbom.cdx.json'))
        hardening = @(Read-TcpkJsonFile (Join-Path $od 'hardening.json'))
        signing   = @(Read-TcpkJsonFile (Join-Path $od 'signing.json'))
        logs      = @($logs)
    }
    $res['reports'] = @($reports.ToArray())
    return $res
}

function Get-TcpkWebJobStatus {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$State, [Parameter(Mandatory)][string]$JobId)
    if (-not $State.Jobs.ContainsKey($JobId)) { return (New-TcpkWebJson 404 @{ error = 'no such job' }) }
    $e = $State.Jobs[$JobId]

    $out = @()
    try { $out = @(Receive-Job -Job $e.Job -ErrorAction SilentlyContinue) } catch { }
    $jstate = "$($e.Job.State)"
    $terminal = $jstate -in 'Completed', 'Failed', 'Stopped'
    if ($terminal) { try { $out += @(Receive-Job -Job $e.Job -ErrorAction SilentlyContinue) } catch { } }   # final drain

    $newLog = New-Object System.Collections.Generic.List[string]
    $newFnd = New-Object System.Collections.Generic.List[object]
    foreach ($line in $out) {
        $s = "$line"
        if ($s.StartsWith("LOG`t")) {
            $msg = $s.Substring(4); $e.Log.Add($msg); $newLog.Add($msg)
            if ($msg -match '^\s*Test-Tcpk\S+\s+\d+ findings') { $e.ChecksDone++ }
        } elseif ($s.StartsWith("FND`t")) {
            $parts = $s.Substring(4) -split "`t", 4
            $f = [ordered]@{ sev = "$($parts[0])"; conf = "$($parts[1])"; rule = "$($parts[2])"; title = "$($parts[3])" }
            $e.Findings.Add($f); $newFnd.Add($f)
        }
    }

    # NB: assigning a generic List via @(...) INSIDE an [ordered]@{} literal throws
    # "Argument types do not match" on PS 5.1 -- set those keys via the indexer.
    $resp = [ordered]@{
        state = $jstate.ToLowerInvariant(); paused = [bool]$e.Paused
        checksDone = $e.ChecksDone; total = $State.ChkTotal; done = $false
    }
    $resp['log'] = @($newLog.ToArray())
    $resp['findings'] = @($newFnd.ToArray())
    if ($terminal) {
        if (-not $e.Done) {
            $e.Done = $true
            if ($jstate -eq 'Completed') { try { $e.Result = Build-TcpkWebResult -Entry $e -State $State } catch { } }
            try { Remove-Job -Job $e.Job -Force -ErrorAction SilentlyContinue } catch { }
            try { Remove-Item -LiteralPath $e.PauseFlag -Force -ErrorAction SilentlyContinue } catch { }
        }
        $resp.done = $true
        $resp.state = $(if ($jstate -eq 'Completed') { 'done' } else { $jstate.ToLowerInvariant() })
        if ($e.Result) { $resp.result = $e.Result }
    }
    return (New-TcpkWebJson 200 $resp)
}

function Invoke-TcpkWebJobControl {
    [CmdletBinding()]
    param($State, [string]$JobId, [string]$Action)
    if (-not $State.Jobs.ContainsKey($JobId)) { return (New-TcpkWebJson 404 @{ error = 'no such job' }) }
    $e = $State.Jobs[$JobId]
    switch ($Action) {
        'pause'  { New-Item -ItemType File -Path $e.PauseFlag -Force | Out-Null; $e.Paused = $true;  return (New-TcpkWebJson 200 @{ paused = $true }) }
        'resume' { Remove-Item -LiteralPath $e.PauseFlag -Force -ErrorAction SilentlyContinue; $e.Paused = $false; return (New-TcpkWebJson 200 @{ paused = $false }) }
        'cancel' {
            try { Stop-Job -Job $e.Job -ErrorAction SilentlyContinue; Remove-Job -Job $e.Job -Force -ErrorAction SilentlyContinue } catch { }
            Remove-Item -LiteralPath $e.PauseFlag -Force -ErrorAction SilentlyContinue
            $e.Done = $true; return (New-TcpkWebJson 200 @{ cancelled = $true })
        }
        default  { return (New-TcpkWebJson 400 @{ error = 'bad action' }) }
    }
}

# Serve a generated report file for download. Filenames are WHITELISTED and the leaf is
# taken via GetFileName so a crafted ?file= cannot traverse out of the job's OutDir.
function Get-TcpkWebReportResponse {
    [CmdletBinding()]
    param($State, [string]$JobId, [string]$File)
    if (-not $State.Jobs.ContainsKey($JobId)) { return (New-TcpkWebJson 404 @{ error = 'no such job' }) }
    $allow = @{
        'index.html'    = 'text/html'
        'intel.html'    = 'text/html'
        'report.md'     = 'text/markdown'
        'report.xlsx'   = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        'report.sarif'  = 'application/json'
        'sbom.cdx.json' = 'application/json'
        'run.log'       = 'text/plain'
    }
    $name = [IO.Path]::GetFileName("$File")
    if (-not $allow.ContainsKey($name)) { return (New-TcpkWebJson 404 @{ error = 'not a downloadable file' }) }
    $p = Join-Path $State.Jobs[$JobId].OutDir $name
    if (-not (Test-Path -LiteralPath $p)) { return (New-TcpkWebJson 404 @{ error = 'file not generated' }) }
    return @{ Status = 200; ContentType = $allow[$name]; File = $p; Download = $name }
}

# Count the audit's checks (for the progress denominator), same source-scan the GUI uses.
function Get-TcpkWebCheckCount {
    $auditFile = Join-Path $script:TcpkRoot 'Public\Invoke-TcpkAudit.ps1'
    $n = 0
    try { $n = @(Get-Content -LiteralPath $auditFile -ErrorAction Stop | Select-String -Pattern "^\s*_RunCheck '").Count } catch { }
    if ($n -lt 1) { $n = 90 }
    return $n
}

# --- request dispatcher (pure given the request) -------------------------------
function Invoke-TcpkWebApi {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Request, [Parameter(Mandatory)]$State)

    if (-not (Test-TcpkWebHost $Request.Headers['host'] $State.Port)) {
        return (New-TcpkWebJson 403 @{ error = 'bad host (loopback only)' })
    }
    $path = "$($Request.Path)"
    $method = "$($Request.Method)"

    if ($method -eq 'GET' -and ($path -eq '/' -or $path -eq '/index.html')) {
        return @{ Status = 200; ContentType = 'text/html; charset=utf-8'; Body = (Get-TcpkWebAppHtml) }
    }

    if ($path -like '/api/*') {
        if (-not (Test-TcpkWebRequestAuth -Request $Request -Token $State.Token -Port $State.Port)) {
            return (New-TcpkWebJson 401 @{ error = 'unauthorized' })
        }
        $job = "$($Request.Query['job'])"
        switch ("$method $path") {
            'GET /api/ping'      { return (New-TcpkWebJson 200 @{ ok = $true; version = "$($State.Version)" }) }
            'GET /api/discover'  { return (New-TcpkWebJson 200 @{ apps = @(Find-TcpkWebApps "$($Request.Query['q'])") }) }
            'GET /api/apps'      { return (New-TcpkWebJson 200 @{ apps = @(Get-TcpkInstalledApps) }) }
            'POST /api/run'      { return (Start-TcpkWebAuditJob -Request $Request -State $State) }
            'POST /api/identify' { return (Invoke-TcpkWebIdentify -Request $Request) }
            'POST /api/testai'   { return (Test-TcpkWebLlm -Request $Request) }
            'GET /api/status'    { return (Get-TcpkWebJobStatus -State $State -JobId $job) }
            'POST /api/pause'    { return (Invoke-TcpkWebJobControl -State $State -JobId $job -Action 'pause') }
            'POST /api/resume'   { return (Invoke-TcpkWebJobControl -State $State -JobId $job -Action 'resume') }
            'POST /api/cancel'   { return (Invoke-TcpkWebJobControl -State $State -JobId $job -Action 'cancel') }
            'GET /api/report'    { return (Get-TcpkWebReportResponse -State $State -JobId $job -File "$($Request.Query['file'])") }
            'POST /api/shutdown' { $State.Stop = $true; return (New-TcpkWebJson 200 @{ ok = $true }) }
            default              { return (New-TcpkWebJson 404 @{ error = 'no such endpoint' }) }
        }
    }
    return (New-TcpkWebJson 404 @{ error = 'not found' })
}

# --- minimal HTTP/1.1 read + write over a raw stream ---------------------------
function Get-TcpkHttpHeaderEnd {
    param([System.Collections.Generic.List[byte]]$Buf)
    for ($i = 0; $i -le ($Buf.Count - 4); $i++) {
        if ($Buf[$i] -eq 13 -and $Buf[$i + 1] -eq 10 -and $Buf[$i + 2] -eq 13 -and $Buf[$i + 3] -eq 10) { return $i }
    }
    return -1
}

function ConvertFrom-TcpkQueryString {
    param([string]$Query)
    $h = @{}
    if ($Query) {
        foreach ($pair in ($Query -split '&')) {
            if (-not $pair) { continue }
            $kv = $pair -split '=', 2
            $k = [System.Uri]::UnescapeDataString($kv[0])
            $v = if ($kv.Count -gt 1) { [System.Uri]::UnescapeDataString($kv[1]) } else { '' }
            if ($k) { $h[$k] = $v }
        }
    }
    return $h
}

function Read-TcpkHttpRequest {
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.IO.Stream]$Stream)
    $buf = New-Object System.Collections.Generic.List[byte]
    $tmp = New-Object byte[] 4096
    $headerEnd = -1
    while ($true) {
        $n = 0
        try { $n = $Stream.Read($tmp, 0, $tmp.Length) } catch { return $null }
        if ($n -le 0) { break }
        for ($i = 0; $i -lt $n; $i++) { $buf.Add($tmp[$i]) }
        $headerEnd = Get-TcpkHttpHeaderEnd $buf
        if ($headerEnd -ge 0) { break }
        if ($buf.Count -gt 131072) { return $null }   # oversized header, bail
    }
    if ($headerEnd -lt 0) { return $null }

    $headerText = [System.Text.Encoding]::ASCII.GetString($buf.GetRange(0, $headerEnd).ToArray())
    $lines = $headerText -split "`r`n"
    if (-not $lines.Count) { return $null }
    $parts = $lines[0] -split ' '
    if ($parts.Count -lt 2) { return $null }
    $method = $parts[0].ToUpperInvariant()
    $rawPath = $parts[1]
    $qpath = $rawPath; $qstr = ''
    $qi = $rawPath.IndexOf('?')
    if ($qi -ge 0) { $qpath = $rawPath.Substring(0, $qi); $qstr = $rawPath.Substring($qi + 1) }

    $headers = @{}
    for ($li = 1; $li -lt $lines.Count; $li++) {
        $line = $lines[$li]; if (-not $line) { continue }
        $ci = $line.IndexOf(':'); if ($ci -lt 0) { continue }
        $headers[$line.Substring(0, $ci).Trim().ToLowerInvariant()] = $line.Substring($ci + 1).Trim()
    }

    $body = ''
    $clen = 0
    if ($headers.ContainsKey('content-length')) { [int]::TryParse($headers['content-length'], [ref]$clen) | Out-Null }
    if ($clen -gt 0) {
        $bodyBytes = New-Object System.Collections.Generic.List[byte]
        $already = $buf.Count - ($headerEnd + 4)
        if ($already -gt 0) { $bodyBytes.AddRange($buf.GetRange($headerEnd + 4, $already)) }
        while ($bodyBytes.Count -lt $clen) {
            $n = 0
            try { $n = $Stream.Read($tmp, 0, [Math]::Min($tmp.Length, $clen - $bodyBytes.Count)) } catch { break }
            if ($n -le 0) { break }
            for ($i = 0; $i -lt $n; $i++) { $bodyBytes.Add($tmp[$i]) }
        }
        $take = [Math]::Min($bodyBytes.Count, $clen)
        $body = [System.Text.Encoding]::UTF8.GetString($bodyBytes.ToArray(), 0, $take)
    }

    return @{ Method = $method; Path = $qpath; Query = (ConvertFrom-TcpkQueryString $qstr); Headers = $headers; Body = $body }
}

function Write-TcpkHttpResponse {
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.IO.Stream]$Stream, [int]$Status, [string]$ContentType, [string]$Body)
    $reason = switch ($Status) {
        200 { 'OK' } 400 { 'Bad Request' } 401 { 'Unauthorized' } 403 { 'Forbidden' }
        404 { 'Not Found' } 500 { 'Internal Server Error' } default { 'OK' }
    }
    $bodyBytes = [System.Text.Encoding]::UTF8.GetBytes("$Body")
    # No CORS allow headers EVER -- cross-origin pages are blocked by the browser.
    $head = "HTTP/1.1 $Status $reason`r`n" +
            "Content-Type: $ContentType`r`n" +
            "Content-Length: $($bodyBytes.Length)`r`n" +
            "Cache-Control: no-store`r`n" +
            "X-Content-Type-Options: nosniff`r`n" +
            "Connection: close`r`n`r`n"
    $headBytes = [System.Text.Encoding]::ASCII.GetBytes($head)
    $Stream.Write($headBytes, 0, $headBytes.Length)
    $Stream.Write($bodyBytes, 0, $bodyBytes.Length)
    $Stream.Flush()
}

# Stream a file as a download (binary-safe -- xlsx etc. are NOT text). Used by /api/report.
function Write-TcpkHttpFile {
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.IO.Stream]$Stream, [string]$Path, [string]$ContentType, [string]$Download)
    $bytes = [IO.File]::ReadAllBytes($Path)
    $head = "HTTP/1.1 200 OK`r`n" +
            "Content-Type: $ContentType`r`n" +
            "Content-Length: $($bytes.Length)`r`n" +
            "Content-Disposition: attachment; filename=`"$Download`"`r`n" +
            "Cache-Control: no-store`r`n" +
            "X-Content-Type-Options: nosniff`r`n" +
            "Connection: close`r`n`r`n"
    $headBytes = [System.Text.Encoding]::ASCII.GetBytes($head)
    $Stream.Write($headBytes, 0, $headBytes.Length)
    $Stream.Write($bytes, 0, $bytes.Length)
    $Stream.Flush()
}

# --- the single-page control panel (self-contained, no CDN) --------------------
function Get-TcpkWebAppHtml {
    [CmdletBinding()] param()
    return $script:TCPK_WEBUI_HTML
}

$script:TCPK_WEBUI_HTML = @'
<!doctype html><html lang="en"><head><meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>TCPK control panel</title>
<style>
:root{--bg:#0b0e14;--panel:#161b22;--panel2:#1c2230;--border:#30363d;--text:#e6edf3;--muted:#8b949e;--dim:#6e7681;
--crit:#f85149;--high:#db6d28;--med:#d29922;--low:#3fb950;--info:#8b949e;--il:#3fb950;--dyn:#39c5cf;--llm:#bc8cff;--accent:#56d364;--ok:#3fb950;--bad:#f85149;}
body.light{--bg:#f6f8fa;--panel:#ffffff;--panel2:#eef1f5;--border:#d0d7de;--text:#1f2328;--muted:#57606a;--dim:#8c959f;--accent:#1a7f37;--il:#1a7f37;--ok:#1a7f37;}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 "Segoe UI",system-ui,Arial,sans-serif}
.wrap{max-width:1160px;margin:0 auto;padding:20px}
.hd{display:flex;align-items:center;justify-content:space-between;gap:14px;flex-wrap:wrap;border-bottom:1px solid var(--border);padding-bottom:12px;margin-bottom:14px}
.brand{font:700 22px Consolas,monospace}.brand span{color:var(--accent)}
.tagline{color:var(--muted);font-size:12px}
.safe{color:var(--dim);font:11px Consolas,monospace;text-align:right}
.panel{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:14px;margin-bottom:12px}
.panel h3{margin:0 0 9px;font:700 12px Consolas,monospace;color:var(--muted);letter-spacing:.05em}
label{font-size:12px;color:var(--muted)}
input[type=text],input[type=password],select{width:100%;background:var(--bg);border:1px solid var(--border);border-radius:7px;color:var(--text);padding:8px 10px;font:13px Consolas,monospace}
.row{display:flex;gap:10px;flex-wrap:wrap;align-items:flex-end;margin-bottom:8px}
.row>div{flex:1;min-width:170px}
.row .grow2{flex:2}
button{cursor:pointer;border:1px solid var(--border);border-radius:7px;padding:8px 14px;font:600 13px Consolas,monospace;background:var(--panel2);color:var(--text)}
button.go{background:var(--accent);color:#08130a;border-color:var(--accent)}
button.warn{border-color:var(--med);color:var(--med)}button.stop{border-color:var(--crit);color:var(--crit)}
button:disabled{opacity:.45;cursor:default}
.mini{padding:5px 10px;font-size:12px}
.opttoggle{cursor:pointer;color:#58a6ff;font:12px Consolas,monospace;user-select:none}
.opts{display:none;border-top:1px solid #21262d;margin-top:8px;padding-top:10px}
.opts.show{display:block}
.chkrow{display:flex;gap:18px;flex-wrap:wrap;align-items:center;margin:6px 0}
.chk{display:flex;gap:6px;align-items:center;font:12px Consolas,monospace;color:var(--text)}
.status{margin-top:9px;font:12px Consolas,monospace;color:var(--muted);min-height:17px}
.spin{display:inline-block;width:11px;height:11px;border:2px solid var(--dim);border-top-color:var(--accent);border-radius:50%;animation:sp .8s linear infinite;vertical-align:-1px;margin-right:6px}
@keyframes sp{to{transform:rotate(360deg)}}
.app{display:flex;justify-content:space-between;gap:10px;padding:6px 9px;border:1px solid var(--border);border-radius:7px;margin-top:5px;cursor:pointer;font:12px Consolas,monospace;background:var(--bg)}
.app:hover{border-color:var(--accent)}.app .p{color:var(--dim)}
.bar{height:9px;background:var(--bg);border:1px solid var(--border);border-radius:6px;overflow:hidden;margin:6px 0}
.bar i{display:block;height:100%;background:var(--accent);width:0%;transition:width .3s}
.ctl{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin:8px 0}
.log{background:#010409;border:1px solid var(--border);border-radius:7px;padding:9px;height:170px;overflow:auto;font:11px Consolas,monospace;color:#c9d1d9;white-space:pre-wrap;word-break:break-word}
.log .crit{color:var(--crit)}.log .find{color:#aed6f1}
.tabs{display:flex;gap:4px;flex-wrap:wrap;border-bottom:1px solid var(--border);margin-bottom:12px}
.tab{cursor:pointer;padding:8px 13px;font:12px Consolas,monospace;color:var(--muted);border:1px solid transparent;border-bottom:none;border-radius:8px 8px 0 0}
.tab.on{color:var(--text);background:var(--panel);border-color:var(--border)}
.tab .n{color:var(--dim)}
.pane{display:none}.pane.on{display:block}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(110px,1fr));gap:10px;margin-bottom:12px}
.stat{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:11px 13px}
.stat b{font:700 25px Consolas,monospace;display:block;line-height:1.1}.stat small{color:var(--muted);font-size:12px}
.chips{display:flex;gap:7px;flex-wrap:wrap;margin-bottom:12px}
.chip{cursor:pointer;user-select:none;border:1px solid var(--border);border-radius:20px;padding:4px 11px;font:12px Consolas,monospace;color:var(--muted);background:var(--panel)}
.chip.on{color:var(--bg);font-weight:700}.chip.crit.on{background:var(--crit)}.chip.high.on{background:var(--high)}.chip.med.on{background:var(--med)}.chip.low.on{background:var(--low)}.chip.info.on{background:var(--info)}
.card{background:var(--panel);border:1px solid var(--border);border-left-width:4px;border-radius:10px;margin-bottom:9px;overflow:hidden}
.card.crit{border-left-color:var(--crit)}.card.high{border-left-color:var(--high)}.card.med{border-left-color:var(--med)}.card.low{border-left-color:var(--low)}.card.info{border-left-color:var(--info)}
.chead{display:flex;align-items:center;gap:9px;padding:10px 12px;cursor:pointer;flex-wrap:wrap}
.pill{font:700 10px Consolas,monospace;padding:2px 8px;border-radius:5px;color:#0b0e14}
.pill.crit{background:var(--crit)}.pill.high{background:var(--high)}.pill.med{background:var(--med)}.pill.low{background:var(--low)}.pill.info{background:var(--info)}
.badge{font:11px Consolas,monospace;padding:2px 8px;border-radius:12px;border:1px solid var(--border);color:var(--muted)}
.badge.il{color:var(--il);border-color:var(--il)}.badge.dyn{color:var(--dyn);border-color:var(--dyn)}.badge.llm{color:var(--llm);border-color:var(--llm)}
.ttl{font-weight:600;flex:1;min-width:170px}.rule{font:11px Consolas,monospace;color:var(--dim)}.cvss{font:11px Consolas,monospace;color:var(--muted)}
.cbody{display:none;padding:0 12px 12px;border-top:1px solid #21262d}.card.open .cbody{display:block}
.sec{margin-top:10px}.sec h4{margin:0 0 4px;font:700 11px Consolas,monospace;color:var(--muted)}.sec p{margin:0;color:#c9d1d9}
pre.ev{background:#010409;border:1px solid var(--border);border-radius:7px;padding:9px;overflow:auto;font:12px Consolas,monospace;color:#c9d1d9;white-space:pre-wrap;word-break:break-word}
table{width:100%;border-collapse:collapse;font:12px Consolas,monospace}
.tblwrap{overflow-x:auto;max-width:100%}
th,td{text-align:left;padding:6px 9px;border-bottom:1px solid #21262d;vertical-align:top;white-space:nowrap;max-width:320px;overflow:hidden;text-overflow:ellipsis}
th{color:var(--muted);font-weight:700;position:sticky;top:0;background:var(--panel)}
td.ok{color:var(--ok)}td.bad{color:var(--bad)}
.kv{font:12px Consolas,monospace;color:var(--muted)}.kv b{color:#c9d1d9}
.dl{display:inline-block;margin:5px 8px 0 0}
.cat{font-size:10px;padding:1px 7px;border-radius:9px;border:1px solid var(--border);color:var(--muted)}
.flag{font-size:10px;color:var(--crit)}
.empty{color:var(--muted);text-align:center;padding:24px}
.foot{color:var(--dim);font:11px Consolas,monospace;text-align:center;margin-top:16px;padding-top:12px;border-top:1px solid var(--border)}
a.lnk{color:#58a6ff;cursor:pointer}
</style></head><body><div class="wrap">
<div class="hd"><div><div class="brand">TC<span>PK</span> control panel</div><div class="tagline">drive a discovery audit -- loopback only, exploit bucket disabled</div></div><div class="safe" id="safe">127.0.0.1 -- discovery only</div></div>

<div class="panel" id="runpanel">
<div class="row"><div class="grow2"><label>Target -- install dir, EXE/DLL, or MSIX/MSI/ZIP (auto-unwrapped)</label><input type="text" id="target" placeholder="C:\Program Files\Acme\Desktop"/></div><div style="flex:0 0 auto;min-width:0"><button class="mini" id="detect">Auto-Detect</button> <button class="go" id="run">Run audit</button></div></div>
<div class="opttoggle" id="optTog">- options (package / process / AI verify)</div>
<div class="opts show" id="opts">
<div class="row"><div><label>Profile (scan depth)</label><select id="profile"><option value="Full">Full</option><option value="Standard">Standard</option><option value="Quick">Quick -- skip slow OS scans</option></select></div><div class="g2"></div></div>
<div class="row"><div><label>PackageName (MSIX, optional)</label><input type="text" id="packageName"/></div><div><label>PackageFamilyName (MSIX, optional)</label><input type="text" id="packageFamilyName"/></div><div><label>ProcessName (runtime, optional)</label><input type="text" id="processName"/></div></div>
<div class="chkrow"><label class="chk"><input type="checkbox" id="deepRuntime"/> deep runtime checks</label><label class="chk"><input type="checkbox" id="enableLlm"/> AI-verify findings</label><label class="chk" title="Query the OSV API for the shipped NuGet components -- OFF = offline catalog only; ON sends only package name+version to api.osv.dev"><input type="checkbox" id="onlineCve"/> online CVE (OSV)</label></div>
<div class="row" id="aiRow" style="display:none"><div><label>AI provider</label><select id="provider"><option value="ollama">ollama (local)</option><option value="claude">claude</option><option value="openai">openai</option><option value="gemini">gemini</option><option value="grok">grok</option><option value="deepseek">deepseek</option><option value="custom">custom endpoint</option></select></div><div><label>model</label><input type="text" id="model" placeholder="qwen2.5-coder:7b"/></div><div><label>API key</label><input type="password" id="apiKey" placeholder="for cloud providers"/></div><div style="flex:0 0 auto;display:flex;align-items:flex-end"><button class="mini" id="testai">Test AI</button></div></div>
<div class="row" id="urlRow" style="display:none"><div class="g2"><label>custom OpenAI-compatible base URL</label><input type="text" id="baseUrl" placeholder="https://host/v1"/></div></div>
<div id="aiTest" style="color:var(--muted);font:11px Consolas,monospace;margin:2px 0"></div>
<div class="chkrow" id="cloudRow" style="display:none"><label class="chk"><input type="checkbox" id="allowCloudLlm"/> allow cloud LLM -- I accept decompiled code leaves this machine</label></div>
</div>
<div class="row" style="margin-top:8px"><div><label>or find an installed app by name</label><input type="text" id="q" placeholder="Acme"/></div><div style="flex:0 0 auto;min-width:0"><button class="mini" id="find">Find</button> <button class="mini" id="auto">Auto-detect all</button></div></div>
<div id="apps"></div>
<div class="status" id="status"></div>
</div>

<div class="panel" id="progress" style="display:none"><h3>AUDIT PROGRESS</h3>
<div class="bar"><i id="barfill"></i></div>
<div class="kv" id="progtext">starting...</div>
<div class="ctl"><button class="mini warn" id="pause">Pause</button><button class="mini stop" id="cancel">Cancel</button><span class="opttoggle" id="logTog">hide log</span></div>
<div class="log" id="log"></div>
</div>

<div id="results" style="display:none">
<div class="tabs" id="tabs"></div>
<div id="panes"></div>
</div>

<div class="foot">TCPK web control panel &middot; evidence over assertion &middot; nothing leaves 127.0.0.1 &middot; <a class="lnk" id="theme">light theme</a> &middot; <a class="lnk" id="stop">stop server</a></div>
</div>
<script>
(function(){
  var TOKEN=new URLSearchParams(location.search).get('t')||'';
  var $=function(id){return document.getElementById(id);};
  function esc(s){s=(s==null?'':String(s));return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
  function arr(x){return Array.isArray(x)?x:(x?[x]:[]);}
  function api(p,o){o=o||{};o.headers=Object.assign({'X-TCPK-Token':TOKEN},o.headers||{});return fetch(p,o);}
  function status(h,busy){$('status').innerHTML=(busy?'<span class="spin"></span>':'')+h;}
  var SEV=['CRITICAL','HIGH','MEDIUM','LOW','INFO'];
  var SC={CRITICAL:'crit',HIGH:'high',MEDIUM:'med',LOW:'low',INFO:'info'};
  var SCOL={CRITICAL:'var(--crit)',HIGH:'var(--high)',MEDIUM:'var(--med)',LOW:'var(--low)',INFO:'var(--info)'};
  function confClass(c){c=c||'';if(c.indexOf('IL')>=0)return'il';if(c.indexOf('dynamic')>=0)return'dyn';if(c.indexOf('LLM')>=0)return'llm';return'';}
  var JOB=null,TOTAL=135,poll=null,RESULT=null,fstate={};SEV.forEach(function(s){fstate[s]=true;});

  if(!TOKEN){status('No session token in the URL. Re-open the link printed by Start-TcpkWebUi.');}
  else{api('/api/ping').then(function(r){return r.json();}).then(function(){status('ready. Enter a target and Run audit.');}).catch(function(){status('cannot reach the server.');});}

  $('optTog').onclick=function(){var on=$('opts').classList.toggle('show');this.textContent=(on?'- ':'+ ')+'options (package / process / AI verify)';};
  var AIDEF={ollama:{m:'qwen2.5-coder:7b',cloud:false},claude:{m:'claude-sonnet-4-5',cloud:true},openai:{m:'gpt-4o',cloud:true},gemini:{m:'gemini-2.0-flash',cloud:true},grok:{m:'grok-2-latest',cloud:true},deepseek:{m:'deepseek-chat',cloud:true},custom:{m:'',cloud:true}};
  function syncProvider(){var p=$('provider').value;var d=AIDEF[p]||AIDEF.ollama;var cur=$('model').value,isDef=false;for(var k in AIDEF){if(AIDEF[k].m&&AIDEF[k].m===cur)isDef=true;}if(!cur||isDef)$('model').value=d.m;$('apiKey').disabled=!d.cloud;$('urlRow').style.display=(p==='custom')?'flex':'none';$('cloudRow').style.display=d.cloud?'flex':'none';$('aiTest').textContent='';}
  $('enableLlm').onchange=function(){var on=this.checked;$('aiRow').style.display=on?'flex':'none';if(on){syncProvider();}else{$('urlRow').style.display='none';$('cloudRow').style.display='none';}};
  $('provider').onchange=syncProvider;
  $('testai').onclick=function(){var body={provider:$('provider').value,model:$('model').value.trim(),apiKey:$('apiKey').value,baseUrl:$('baseUrl')?$('baseUrl').value.trim():''};$('aiTest').innerHTML='<span style="color:var(--muted)">testing '+esc(body.provider)+'...</span>';api('/api/testai',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}).then(function(r){return r.json();}).then(function(d){$('aiTest').innerHTML=d.reachable?('<span style="color:var(--ok)">reachable -- '+esc(body.provider)+' OK</span>'):('<span style="color:var(--bad)">not reachable'+(d.error?' ('+esc(d.error)+')':'')+'</span>');}).catch(function(){$('aiTest').innerHTML='<span style="color:var(--bad)">test failed</span>';});};
  $('logTog').onclick=function(){var l=$('log');var h=l.style.display==='none';l.style.display=h?'block':'none';this.textContent=h?'hide log':'show log';};

  $('find').onclick=function(){doFind('/api/discover?q='+encodeURIComponent($('q').value.trim()),$('q').value.trim());};
  $('auto').onclick=function(){doFind('/api/apps','all installed apps');};
  $('detect').onclick=function(){var t=$('target').value.trim();if(!t){status('enter a target path first.');return;}status('auto-detecting identity...',true);
    api('/api/identify',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({path:t})}).then(function(r){return r.json();}).then(function(d){
      $('packageName').value=d.packageName||'';$('packageFamilyName').value=d.packageFamilyName||'';$('processName').value=d.processName||'';
      if(!$('opts').classList.contains('show')){$('opts').classList.add('show');$('optTog').textContent='- options (package / process / AI verify)';}
      status(d.note||'identity detected.');
    }).catch(function(){status('auto-detect failed.');});};
  function doFind(url,what){if(url.indexOf('discover')>=0 && !$('q').value.trim()){return;}status('listing '+esc(what)+'...',true);$('apps').innerHTML='';
    api(url).then(function(r){return r.json();}).then(function(d){var apps=arr(d.apps);if(!apps.length){status('nothing matched. Type a path above.');return;}
      status(apps.length+' app(s). Click one to use its path.');
      $('apps').innerHTML=apps.map(function(a){return '<div class="app" data-p="'+esc(a.path)+'"><span>'+esc(a.name||a.path)+(a.version?' <span class="p">'+esc(a.version)+'</span>':'')+'</span><span class="p">'+esc(a.path)+'</span></div>';}).join('');
      Array.prototype.forEach.call(document.querySelectorAll('.app'),function(el){el.onclick=function(){$('target').value=this.getAttribute('data-p');status('target set. Click Run audit.');};});
    }).catch(function(){status('lookup failed.');});};

  $('run').onclick=function(){
    var t=$('target').value.trim();if(!t){status('enter a target path first.');return;}
    var body={target:t,profile:$('profile').value,packageName:$('packageName').value.trim(),packageFamilyName:$('packageFamilyName').value.trim(),processName:$('processName').value.trim(),deepRuntime:$('deepRuntime').checked,onlineCve:$('onlineCve').checked,enableLlm:$('enableLlm').checked,allowCloudLlm:$('allowCloudLlm').checked,provider:$('provider').value,model:$('model').value.trim(),apiKey:$('apiKey').value,baseUrl:$('baseUrl')?$('baseUrl').value.trim():''};
    $('run').disabled=true;$('results').style.display='none';$('panes').innerHTML='';$('tabs').innerHTML='';$('log').innerHTML='';
    status('starting audit...',true);
    api('/api/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}).then(function(r){return r.json().then(function(j){return{ok:r.ok,j:j};});}).then(function(res){
      if(!res.ok){$('run').disabled=false;status('could not start: '+esc(res.j&&res.j.error||'error'));return;}
      JOB=res.j.jobId;TOTAL=res.j.total||135;$('progress').style.display='block';$('barfill').style.width='0%';$('pause').textContent='Pause';$('pause').disabled=false;$('cancel').disabled=false;
      status('audit running...',true);startPoll();
    }).catch(function(e){$('run').disabled=false;status('error: '+esc(e&&e.message||e));});
  };

  function logLine(msg){var cls='';if(/CRITICAL/.test(msg))cls='crit';var d=document.createElement('div');if(cls)d.className=cls;d.textContent=msg;var L=$('log');L.appendChild(d);L.scrollTop=L.scrollHeight;}
  function startPoll(){if(poll)clearInterval(poll);poll=setInterval(tick,1000);tick();}
  function tick(){if(!JOB)return;
    api('/api/status?job='+JOB).then(function(r){return r.json();}).then(function(s){
      arr(s.log).forEach(logLine);
      var pct=s.total?Math.min(100,Math.round(s.checksDone/s.total*100)):0;
      $('barfill').style.width=pct+'%';
      $('progtext').innerHTML='state <b>'+esc(s.state)+'</b>'+(s.paused?' (paused)':'')+' &middot; checks <b>'+esc(s.checksDone)+'/'+esc(s.total)+'</b> &middot; '+pct+'%';
      if(s.done){clearInterval(poll);poll=null;$('run').disabled=false;$('pause').disabled=true;$('cancel').disabled=true;
        if(s.state==='done'){$('barfill').style.width='100%';$('progtext').innerHTML='state <b>done</b> &middot; '+esc(s.checksDone)+' checks run &middot; complete';
          if(s.result){RESULT=s.result;status('done.');renderResult(s.result);}}
        else{status('audit '+esc(s.state)+'.');}
      }
    }).catch(function(){});
  }
  $('pause').onclick=function(){if(!JOB)return;var resume=this.textContent==='Resume';api('/api/'+(resume?'resume':'pause')+'?job='+JOB,{method:'POST'}).then(function(r){return r.json();}).then(function(){$('pause').textContent=resume?'Pause':'Resume';});};
  $('cancel').onclick=function(){if(!JOB)return;api('/api/cancel?job='+JOB,{method:'POST'}).then(function(){if(poll)clearInterval(poll);poll=null;status('cancelled.');$('run').disabled=false;$('pause').disabled=true;$('cancel').disabled=true;});};
  $('stop').onclick=function(){api('/api/shutdown',{method:'POST'}).then(function(){status('server stopped. You can close this tab.');}).catch(function(){});};
  $('theme').onclick=function(){var l=document.body.classList.toggle('light');this.textContent=l?'dark theme':'light theme';};

  var TABS=[['findings','Findings'],['recon','Recon'],['sbom','SBOM'],['hardening','DLL Mitigation'],['signing','DLL Signing'],['logs','Logs'],['reports','Reports']];
  function renderResult(r){
    $('results').style.display='block';
    var counts={findings:(r.model&&arr(r.model.findings).length)||0,recon:r.recon?1:0,sbom:(r.sbom&&arr(r.sbom.components).length)||0,hardening:arr(r.hardening).length,signing:arr(r.signing).length,logs:arr(r.logs).length,reports:arr(r.reports).length};
    $('tabs').innerHTML=TABS.map(function(t,i){return '<div class="tab'+(i===0?' on':'')+'" data-t="'+t[0]+'">'+t[1]+' <span class="n">'+counts[t[0]]+'</span></div>';}).join('');
    $('panes').innerHTML=TABS.map(function(t,i){return '<div class="pane'+(i===0?' on':'')+'" id="pane-'+t[0]+'"></div>';}).join('');
    Array.prototype.forEach.call(document.querySelectorAll('.tab'),function(el){el.onclick=function(){var k=this.getAttribute('data-t');Array.prototype.forEach.call(document.querySelectorAll('.tab'),function(x){x.classList.toggle('on',x===el);});Array.prototype.forEach.call(document.querySelectorAll('.pane'),function(p){p.classList.toggle('on',p.id==='pane-'+k);});};});
    renderFindings(r.model||{});renderRecon(r.recon);renderSbom(r.sbom);renderTable($('pane-hardening'),arr(r.hardening),true);renderTable($('pane-signing'),arr(r.signing),false);renderLogs(arr(r.logs));renderReports(arr(r.reports));
  }

  function renderFindings(m){var sv=(m.summary&&m.summary.severity)||{},F=arr(m.findings);
    var s='<div class="grid">';SEV.forEach(function(k){s+='<div class="stat"><b style="color:'+SCOL[k]+'">'+(sv[k]||0)+'</b><small>'+k+'</small></div>';});s+='</div>';
    s+='<div class="chips">';SEV.forEach(function(k){s+='<span class="chip '+SC[k]+(fstate[k]?' on':'')+'" data-sev="'+k+'">'+k+'</span>';});s+='</div>';
    s+='<div id="fcards"></div>';$('pane-findings').innerHTML=s;
    Array.prototype.forEach.call(document.querySelectorAll('#pane-findings .chip'),function(el){el.onclick=function(){var k=this.getAttribute('data-sev');fstate[k]=!fstate[k];this.classList.toggle('on');drawCards(F);};});
    drawCards(F);
  }
  function drawCards(F){var sh=F.filter(function(f){return fstate[f.sev];});
    if(!sh.length){$('fcards').innerHTML='<div class="empty">No findings match the filter.</div>';return;}
    $('fcards').innerHTML=sh.map(card).join('');
    Array.prototype.forEach.call(document.querySelectorAll('#fcards .chead'),function(el){el.onclick=function(){this.parentNode.classList.toggle('open');};});
  }
  function card(f){var sc=SC[f.sev]||'info';var cwe=arr(f.cwe).join(', ');
    var s='<div class="card '+sc+'"><div class="chead"><span class="pill '+sc+'">'+esc(f.sev)+'</span><span class="badge '+confClass(f.conf)+'">'+esc(f.conf)+'</span>'+(f.cvss?'<span class="cvss">'+esc(f.cvss)+'</span>':'')+'<span class="ttl">'+esc(f.title)+'</span><span class="rule">'+esc(f.rule)+'</span></div><div class="cbody">';
    if(f.desc)s+='<div class="sec"><h4>WHAT &amp; WHY</h4><p>'+esc(f.desc)+'</p></div>';
    if(f.evidence)s+='<div class="sec"><h4>EVIDENCE</h4><pre class="ev">'+esc(f.evidence)+'</pre></div>';
    if(arr(f.affected).length)s+='<div class="sec"><h4>AFFECTED ('+arr(f.affected).length+')</h4><pre class="ev">'+esc(arr(f.affected).join('\n'))+'</pre></div>';
    if(f.verify)s+='<div class="sec"><h4>HOW TO VERIFY</h4><pre class="ev">'+esc(f.verify)+'</pre></div>';
    if(f.fix)s+='<div class="sec"><h4>FIX</h4><p>'+esc(f.fix)+'</p></div>';
    s+='<div class="sec"><div class="kv">'+(cwe?'CWE: <b>'+esc(cwe)+'</b> &middot; ':'')+(f.attack?'ATT&amp;CK: <b>'+esc(f.attack)+'</b> &middot; ':'')+(f.tasvs?'TASVS: <b>'+esc(f.tasvs)+'</b> &middot; ':'')+'file: <b>'+esc(f.file||'-')+'</b></div></div>';
    return s+'</div></div>';}

  function renderRecon(p){if(!p){$('pane-recon').innerHTML='<div class="empty">No recon profile.</div>';return;}
    var s='<div class="panel"><h3>IDENTITY</h3><table>';
    ['Name','Version','Publisher','AppType','Runtime','UiFramework','PrivilegeModel','UpdateMechanism','CodeSigning'].forEach(function(k){if(p[k]!=null&&(''+p[k]).length)s+='<tr><td class="kv">'+k+'</td><td>'+esc(p[k])+'</td></tr>';});
    s+='</table></div>';
    var eps=arr(p.EndpointMap);
    if(eps.length){s+='<div class="panel"><h3>ENDPOINTS ('+eps.length+')</h3><table><tr><th>category</th><th>host</th><th>scheme</th><th>flags</th></tr>';
      eps.forEach(function(e){s+='<tr><td><span class="cat">'+esc(e.Category||'')+'</span></td><td>'+esc(e.Host)+'</td><td class="kv">'+esc(e.Schemes||'')+'</td><td>'+arr(e.Flags).map(function(f){return '<span class="flag">'+esc(f)+'</span>';}).join(' ')+'</td></tr>';});
      s+='</table></div>';}
    s+='<div class="panel"><h3>ATTACK SURFACE</h3><div class="kv">listening ports <b>'+arr(p.ListeningPorts).length+'</b> &middot; protocol handlers <b>'+arr(p.ProtocolHandlers).length+'</b> &middot; named pipes <b>'+arr(p.NamedPipes).length+'</b> &middot; COM servers <b>'+arr(p.ComServers).length+'</b></div></div>';
    $('pane-recon').innerHTML=s;}

  function renderSbom(b){if(!b){$('pane-sbom').innerHTML='<div class="empty">No SBOM.</div>';return;}
    var comps=arr(b.components),vulns=arr(b.vulnerabilities);
    var s='<div class="panel"><h3>COMPONENTS ('+comps.length+')</h3><table><tr><th>name</th><th>version</th><th>publisher</th><th>sha-256</th></tr>';
    comps.forEach(function(c){var h=arr(c.hashes)[0];s+='<tr><td>'+esc(c.name)+'</td><td class="kv">'+esc(c.version)+'</td><td class="kv">'+esc(c.publisher||'')+'</td><td class="kv">'+esc(h?(''+h.content).slice(0,16)+'...':'')+'</td></tr>';});
    s+='</table></div>';
    if(vulns.length){s+='<div class="panel"><h3>VULNERABILITIES ('+vulns.length+')</h3><table><tr><th>id</th><th>severity</th><th>detail</th></tr>';
      vulns.forEach(function(v){var rt=arr(v.ratings)[0];s+='<tr><td>'+esc(v.id)+'</td><td>'+esc(rt?rt.severity:'')+'</td><td class="kv">'+esc(v.description||'')+'</td></tr>';});s+='</table></div>';}
    $('pane-sbom').innerHTML=s;}

  function cellClass(v){var t=(''+v).toLowerCase();if(/^(yes|true|enabled|hardened|present|valid|signed|on)$/.test(t))return'ok';if(/^(no|false|disabled|weak|missing|absent|unsigned|off|n\/a)$/.test(t))return'bad';return'';}
  function renderTable(el,rows,colorize){if(!rows.length){el.innerHTML='<div class="empty">No data (no PE files in target, or not computed).</div>';return;}
    var cols=[];rows.slice(0,8).forEach(function(r){Object.keys(r).forEach(function(k){if(cols.indexOf(k)<0)cols.push(k);});});
    var s='<div class="panel"><div class="tblwrap"><table><tr>'+cols.map(function(c){return '<th>'+esc(c)+'</th>';}).join('')+'</tr>';
    rows.forEach(function(r){s+='<tr>'+cols.map(function(c){var v=r[c];var t=(v==null?'':(typeof v==='object'?JSON.stringify(v):''+v));var cc=colorize?cellClass(v):'';return '<td'+(cc?' class="'+cc+'"':'')+' title="'+esc(t)+'">'+esc(t)+'</td>';}).join('')+'</tr>';});
    s+='</table></div></div>';el.innerHTML=s;}

  function renderLogs(rows){if(!rows.length){$('pane-logs').innerHTML='<div class="empty">No run log.</div>';return;}
    var s='<div class="panel"><table><tr><th>time</th><th>level</th><th>component</th><th>message</th><th>ms</th></tr>';
    rows.forEach(function(e){var lv=(e.level||'');var cc=/ERROR/.test(lv)?'bad':(/SUCCESS/.test(lv)?'ok':'');s+='<tr><td class="kv">'+esc(e.ts||e.time||'')+'</td><td'+(cc?' class="'+cc+'"':'')+'>'+esc(lv)+'</td><td class="kv">'+esc(e.component||'')+'</td><td>'+esc(e.message||'')+'</td><td class="kv">'+esc(e.durationMs>=0?e.durationMs:'')+'</td></tr>';});
    s+='</table></div>';$('pane-logs').innerHTML=s;}

  function renderReports(reps){if(!reps.length){$('pane-reports').innerHTML='<div class="empty">No report files.</div>';return;}
    $('pane-reports').innerHTML='<div class="panel"><h3>GENERATED REPORTS</h3><div class="kv" style="margin-bottom:8px">These were written to a temp folder during the audit. Click to download (fetched with your session token).</div>'+reps.map(function(r){return '<button class="dl mini" data-f="'+esc(r.file)+'">'+esc(r.label)+'  ('+esc(r.file)+')</button>';}).join('')+'</div>';
    Array.prototype.forEach.call(document.querySelectorAll('#pane-reports .dl'),function(el){el.onclick=function(){download(this.getAttribute('data-f'));};});}
  function download(file){if(!JOB)return;api('/api/report?job='+JOB+'&file='+encodeURIComponent(file)).then(function(r){return r.blob();}).then(function(b){var url=URL.createObjectURL(b);var a=document.createElement('a');a.href=url;a.download=file;document.body.appendChild(a);a.click();a.remove();setTimeout(function(){URL.revokeObjectURL(url);},2000);});}
})();
</script></body></html>
'@
