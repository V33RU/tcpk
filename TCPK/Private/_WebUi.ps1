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
# Pure helpers (token / host / auth / target / routing / dispatch) are unit-testable
# WITHOUT a socket; only the accept loop in Start-TcpkWebUi needs the network.

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
    if ($p -match 'WindowsApps[\\/]([A-Za-z0-9.\-]+)_[\d.]+_[a-z0-9]+__([a-z0-9]+)') {
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
    # App-kind fingerprint (what kind of application is this) -- shown before the audit runs.
    try {
        $ai = Get-TcpkAppIdentity -Path $p
        $res.appName    = "$($ai.Name)"
        $res.appVersion = "$($ai.Version)"
        $res.appType    = "$($ai.AppType)"
        $res.runtime    = "$($ai.Runtime)"
        $res.arch       = "$($ai.Architecture)"
        $res.managed    = [bool]$ai.Managed
        $res.ui         = (@($ai.UiFrameworks) -join ', ')
        $res.publisher  = "$($ai.Publisher)"
        $res.signature  = "$($ai.SignatureStatus)"
        $res.appSummary = "$($ai.Summary)"
    } catch { $res.appSummary = '' }
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
            if ($_ -is [string]) { if ($_.StartsWith("TCPKFND`t")) { "FND`t" + $_.Substring(8) } elseif ($_ -notmatch '^LOGX\t') { "LOG`t$_" } }
            elseif ($_ -is [System.Management.Automation.InformationRecord]) { $t = "$_"; if ($t.StartsWith("TCPKFND`t")) { "FND`t" + $t.Substring(8) } elseif ($t -notmatch '^LOGX\t') { "LOG`t$t" } }
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
    # $State.OutRoot to redirect the output root; falls back to <tool folder>\work\out\ if the
    # root cannot resolve. Never outside the tool folder.
    $stamp = Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'
    $leaf = try { Split-Path $target -Leaf } catch { '' }; if (-not $leaf) { $leaf = 'audit' }
    $outRoot = if ("$($State.OutRoot)") { "$($State.OutRoot)" } else { try { Split-Path -Parent (Split-Path -Parent $script:TcpkRoot) } catch { $null } }
    $outDir = if ($outRoot) { Join-Path $outRoot "work\out\${leaf}_$stamp" } else { Get-TcpkWorkDir -Kind 'out' -Leaf ("web-" + $jobId) -NoCreate }
    if (-not (Test-Path -LiteralPath $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }
    $pauseFlag = Join-Path (Get-TcpkWorkDir -Kind 'run') ("webpause-" + $jobId + ".flag")

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
        @{ file = 'coverage.json';label = 'Coverage manifest' },
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
        'coverage.json' = 'application/json'
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
