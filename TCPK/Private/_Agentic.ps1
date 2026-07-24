# TCPK Agentic workbench -- internals.
#
# A loopback-only, phased, AI-driven front-end that REUSES the web control panel's
# proven API (Invoke-TcpkWebApi: target discovery, identity auto-detect, async audit
# job, live log, AI config, report download) and adds /api/agent/* routes for the
# decompile + AI line-review phases (wired in later build phases).
#
# Security model is identical to Start-TcpkWebUi and is enforced by the SAME helpers:
#   * binds 127.0.0.1 ONLY                    -> no other host can reach it
#   * every /api/* needs an X-TCPK-Token        -> cross-origin pages cannot set it
#   * Host header must be 127.0.0.1:<port>      -> anti DNS-rebind
#   * fixed verb set; the exploit bucket is NEVER reachable here -- discovery only
#
# The HTML shell is pure-ASCII, self-contained (no CDN), dark "console" theme matching
# the v1.8.2 report + control panel (risk gauge + severity donut + triage table +
# confidence ladder + a persistent agent console dock).

# --- request dispatcher (pure given the request) -------------------------------
function Invoke-TcpkAgenticApi {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Request, [Parameter(Mandatory)]$State)

    if (-not (Test-TcpkWebHost $Request.Headers['host'] $State.Port)) {
        return (New-TcpkWebJson 403 @{ error = 'bad host (loopback only)' })
    }
    $path = "$($Request.Path)"
    $method = "$($Request.Method)"

    # The agentic SPA shell at '/'. Served BEFORE delegation so the workbench (not the
    # control panel) is the front-end for this server.
    if ($method -eq 'GET' -and ($path -eq '/' -or $path -eq '/index.html')) {
        return @{ Status = 200; ContentType = 'text/html; charset=utf-8'; Body = (Get-TcpkAgenticAppHtml) }
    }

    # Agentic-only routes (auth-gated): decompile / IL, per-method AI review, the
    # interception-capture review, and the autonomous-agent job. All wired and live.
    if ($path -like '/api/agent/*') {
        if (-not (Test-TcpkWebRequestAuth -Request $Request -Token $State.Token -Port $State.Port)) {
            return (New-TcpkWebJson 401 @{ error = 'unauthorized' })
        }
        switch ("$method $path") {
            'GET /api/agent/modules'    { return (New-TcpkWebJson 200 (Get-TcpkAgentModules -Target "$($Request.Query['target'])" -Summary)) }
            'GET /api/agent/llm-models' { return (New-TcpkWebJson 200 (Get-TcpkAgentLlmModels)) }
            'POST /api/agent/decompile' { $b=$null; try { $b = $Request.Body | ConvertFrom-Json } catch {}; return (New-TcpkWebJson 200 (Get-TcpkAgentDecompile -Dll "$(if($b){$b.dll})" -Method "$(if($b){$b.method})")) }
            'POST /api/agent/native'    { $b=$null; try { $b = $Request.Body | ConvertFrom-Json } catch {}; return (New-TcpkWebJson 200 (Get-TcpkAgentNativePe -Dll "$(if($b){$b.dll})")) }
            'POST /api/agent/review'    { $b=$null; try { $b = $Request.Body | ConvertFrom-Json } catch {}; return (New-TcpkWebJson 200 (Get-TcpkAgentReview -Dll "$(if($b){$b.dll})" -Method "$(if($b){$b.method})" -Agent $b)) }
            'POST /api/agent/auto'      { return (Start-TcpkAgentAutoJob -Request $Request -State $State) }
            'GET /api/agent/auto-status'{ return (Get-TcpkAgentAutoStatus -State $State -JobId "$($Request.Query['job'])") }
            'POST /api/agent/intercept' { $b=$null; try { $b = $Request.Body | ConvertFrom-Json } catch {}; return (New-TcpkWebJson 200 (Get-TcpkAgentInterceptReview -File "$(if($b){$b.file})" -Kind "$(if($b){$b.kind})")) }
            'POST /api/agent/runtime'   { $b=$null; try { $b = $Request.Body | ConvertFrom-Json } catch {}; return (New-TcpkWebJson 200 (Get-TcpkAgentRuntime -Check "$(if($b){$b.check})" -Process "$(if($b){$b.process})" -Path "$(if($b){$b.path})")) }
            'GET /api/agent/proclist'   { return (New-TcpkWebJson 200 (Get-TcpkAgentProcList)) }
            'POST /api/agent/procmon'   { $b=$null; try { $b = $Request.Body | ConvertFrom-Json } catch {}; return (New-TcpkWebJson 200 (Get-TcpkAgentProcmon -Proc "$(if($b){$b.proc})")) }
            'POST /api/agent/audit-binary' { $b=$null; try { $b = $Request.Body | ConvertFrom-Json } catch {}; return (New-TcpkWebJson 200 (Get-TcpkAgentBinaryAudit -Dll "$(if($b){$b.dll})")) }
            'POST /api/agent/asar'         { $b=$null; try { $b = $Request.Body | ConvertFrom-Json } catch {}; return (New-TcpkWebJson 200 (Get-TcpkAgentAsar -Target "$(if($b){$b.target})")) }
            'POST /api/agent/asar-file'    { $b=$null; try { $b = $Request.Body | ConvertFrom-Json } catch {}; return (New-TcpkWebJson 200 (Get-TcpkAgentAsarFile -Dir "$(if($b){$b.dir})" -Rel "$(if($b){$b.rel})")) }
            'POST /api/agent/hex'          { $b=$null; try { $b = $Request.Body | ConvertFrom-Json } catch {}; return (New-TcpkWebJson 200 (Get-TcpkAgentHex -Path "$(if($b){$b.path})" -Offset ([int]("0" + "$(if($b){$b.offset})")) -Length ([int]("0" + "$(if($b){$b.length})")))) }
            'POST /api/agent/inspect'      { $b=$null; try { $b = $Request.Body | ConvertFrom-Json } catch {}; return (New-TcpkWebJson 200 (Get-TcpkAgentHexInspect -Path "$(if($b){$b.path})" -Offset ([int64]("0" + "$(if($b){$b.offset})")))) }
            'POST /api/agent/hexfind'      { $b=$null; try { $b = $Request.Body | ConvertFrom-Json } catch {}; return (New-TcpkWebJson 200 (Get-TcpkAgentHexFind -Path "$(if($b){$b.path})" -Query "$(if($b){$b.query})" -Kind "$(if($b){$b.kind})" -From ([int64]("0" + "$(if($b){$b.from})")))) }
            'POST /api/agent/strings'      { $b=$null; try { $b = $Request.Body | ConvertFrom-Json } catch {}; return (New-TcpkWebJson 200 (Get-TcpkAgentHexStrings -Path "$(if($b){$b.path})" -Min ([int]("0" + "$(if($b){$b.min})")) -Filter "$(if($b){$b.filter})" -Kind "$(if($b){$b.kind})")) }
            default                     { return (New-TcpkWebJson 404 @{ error = 'no such agent endpoint' }) }
        }
    }

    # Everything else -> reuse the proven control-panel API verbatim (it does its own
    # Host + token auth): /api/ping, /api/discover, /api/apps, /api/identify, /api/run,
    # /api/status, /api/pause, /api/resume, /api/cancel, /api/testai, /api/report,
    # /api/shutdown. One source of truth -- the agentic UI and the panel never drift.
    return (Invoke-TcpkWebApi -Request $Request -State $State)
}

# --- Phase 2: decompile / IL view (agentic) -----------------------------------
# Reuses the Cecil bridge (_Decompile.ps1) and the SHARED sink map so the workbench's
# "sink-bearing methods" match exactly what the IL verifier proves. Discovery-only:
# reads IL, never executes the target.

# The sink specs the workbench flags on: every sink from the SHARED callsite map (so the
# decompile view matches what the IL verifier proves) PLUS the high-value deserialization
# types (which live in their own detector, not the callsite map). Built once per session.
function Get-TcpkAgentSinkSpecs {
    if ($script:TcpkAgentSinkSpecs) { return $script:TcpkAgentSinkSpecs }
    $list = New-Object 'System.Collections.Generic.List[object]'
    foreach ($kv in (Get-TcpkCallsiteSinkMap).GetEnumerator()) {
        foreach ($s in $kv.Value.Sinks) { $list.Add([pscustomobject]@{ T = "$($s.T)"; M = "$($s.M)"; Mo = [bool]$s.Mo }) }
    }
    foreach ($t in @(
        'System.Runtime.Serialization.Formatters.Binary.BinaryFormatter',
        'System.Runtime.Serialization.NetDataContractSerializer',
        'System.Web.UI.LosFormatter','System.Web.UI.ObjectStateFormatter',
        'System.Messaging.BinaryMessageFormatter','SoapFormatter',
        'System.Xml.Serialization.XmlSerializer','System.Runtime.Serialization.DataContractSerializer'
    )) { $list.Add([pscustomobject]@{ T = $t; M = ''; Mo = $false }) }
    $script:TcpkAgentSinkSpecs = $list
    return $list
}

# If a called method (Cecil MethodReference) matches a sink spec, return a short label
# ("Process.Start"); else $null. Respects M (exact method on a type) / Mo (P/Invoke
# method-name) / bare-T (any member of the type) so it does NOT over-flag -- e.g. a call
# to System.Environment::get_NewLine is NOT the GetEnvironmentVariable sink.
function Get-TcpkAgentSinkHit {
    param($Mref)
    if (-not $Mref) { return $null }
    $declFull = "$($Mref.DeclaringType.FullName)"; $declLeaf = "$($Mref.DeclaringType.Name)"; $name = "$($Mref.Name)"
    foreach ($s in (Get-TcpkAgentSinkSpecs)) {
        if ($s.Mo) {
            if ($name -like "*$($s.T)*") { return $name }
        } elseif ($s.M) {
            if ($declFull -like "*$($s.T)*" -and $name -eq $s.M) { return "$declLeaf.$name" }
        } else {
            if ($declFull -like "*$($s.T)*") { return "$declLeaf.$name" }
        }
    }
    return $null
}

# GET /api/agent/modules?target= -- list the managed .NET modules in a target (the single
# file, or every first-party DLL/EXE under a directory). Counts only; cheap.
function Get-TcpkAgentModules {
    [CmdletBinding()] param([Parameter(Mandatory)][AllowEmptyString()][string]$Target, [switch]$Summary)
    $p = Resolve-TcpkWebTarget $Target
    if (-not $p) { if ($Summary) { return @{ modules = @(); nativeModules = @(); scanned = 0; managed = 0; native = 0 } } else { return @() } }
    $files = if (Test-Path -LiteralPath $p -PathType Container) {
        @(Get-ChildItem -LiteralPath $p -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.Extension -in '.dll','.exe' })
    } else { @(Get-Item -LiteralPath $p) }
    $out = New-Object 'System.Collections.Generic.List[object]'
    $nat = New-Object 'System.Collections.Generic.List[object]'
    foreach ($f in $files) {
        if ($f.Extension -notin '.dll','.exe') { continue }
        if (Test-TcpkIsFrameworkFile $f.Name) { continue }
        $asm = Get-TcpkCecilAssembly $f.FullName
        if (-not $asm) {
            # not managed .NET -- native PE (C/C++/Go/Rust). Listed for the -Summary
            # (workbench) caller so the user can pick it for a PE/hardening view.
            if ($Summary -and $nat.Count -lt 500) { $nat.Add([ordered]@{ name = $f.Name; path = $f.FullName; kind = 'native'; size = [int64]$f.Length }) }
            continue
        }
        $tc = 0; $mc = 0
        try { foreach ($t in $asm.MainModule.GetTypes()) { $tc++; foreach ($m in $t.Methods) { if ($m.HasBody) { $mc++ } } } } catch { }
        $out.Add([ordered]@{ name = $f.Name; path = $f.FullName; kind = 'managed'; types = $tc; methods = $mc })
        if ($out.Count -ge 200) { break }
    }
    # NOTE: default (non-Summary) return is managed-only -- the autonomous agent + auto
    # primary-target picker must never be handed a native DLL to "decompile".
    if ($Summary) { return @{ modules = @($out.ToArray()); nativeModules = @($nat.ToArray()); scanned = @($files).Count; managed = $out.Count; native = $nat.Count } }
    @($out.ToArray())
}

# POST /api/agent/runtime {check, process, path} -- run ONE read-only Runtime\ check and
# return its findings. Discovery-only by construction: a FIXED whitelist maps a check id to
# a cmdlet + how it is invoked (process / system-wide / target-path). The gated ETW DLL-hijack
# trace and the heavy memory dump are deliberately NOT in the map, so this pane can never
# launch, instrument, or dump a target -- it only reads live state.
function Get-TcpkAgentRuntime {
    [CmdletBinding()] param([string]$Check, [string]$Process, [string]$Path)
    $map = @{
        'loaded-modules'  = @{ fn = 'Test-TcpkLoadedModulePaths';      kind = 'proc' }
        'module-sigs'     = @{ fn = 'Test-TcpkLoadedModuleSignatures'; kind = 'proc' }
        'listening-ports' = @{ fn = 'Test-TcpkListeningPorts';         kind = 'proc' }
        'process-token'   = @{ fn = 'Test-TcpkProcessToken';           kind = 'proc' }
        'mitigations'     = @{ fn = 'Test-TcpkProcessMitigations';     kind = 'proc' }
        'process-dacl'    = @{ fn = 'Test-TcpkProcessDacl';            kind = 'proc' }
        'env-secrets'     = @{ fn = 'Test-TcpkProcessEnvSecrets';      kind = 'proc' }
        'child-procs'     = @{ fn = 'Test-TcpkChildProcesses';         kind = 'proc' }
        'handles'         = @{ fn = 'Test-TcpkHandleEnumeration';      kind = 'proc' }
        'windows'         = @{ fn = 'Test-TcpkWindowEnumeration';      kind = 'proc' }
        'gui-inspector'   = @{ fn = 'Test-TcpkGuiInspector';           kind = 'proc' }
        'named-pipes'     = @{ fn = 'Test-TcpkNamedPipes';             kind = 'sys' }
        'pipe-dacls'      = @{ fn = 'Test-TcpkNamedPipeDacl';          kind = 'sys' }
        'alpc'            = @{ fn = 'Test-TcpkMailslotsAlpc';          kind = 'sys' }
        'com-objects'     = @{ fn = 'Test-TcpkComObjects';             kind = 'path' }
        'named-objects'   = @{ fn = 'Test-TcpkNamedObjects';           kind = 'path' }
        'rpc-surface'     = @{ fn = 'Test-TcpkRpcSurface';             kind = 'path' }
    }
    $spec = $map["$Check"]
    if (-not $spec) { return @{ error = 'unknown or non-discovery check' } }
    $fs = @()
    try {
        switch ($spec.kind) {
            'proc' { if (-not $Process) { return @{ error = 'process name required' } }; $fs = @(& $spec.fn -ProcessName $Process) }
            'sys'  { $fs = @(& $spec.fn) }
            'path' { $p = Resolve-TcpkWebTarget $Path; if (-not $p) { return @{ error = 'target path required (set one in step 2)' } }; $fs = @(& $spec.fn -Path $p) }
        }
    } catch { return @{ error = "$($_.Exception.Message)" } }
    @{ check = "$Check"; findings = @($fs | Where-Object { $_ } | ForEach-Object {
        [ordered]@{ sev = "$($_.Severity)"; conf = "$($_.Confidence)"; rule = "$($_.RuleId)"; title = "$($_.Title)"; evidence = "$($_.Evidence)"; file = "$($_.File)" }
    }) }
}

# GET /api/agent/proclist -- running processes for the Process (live watch) picker. Read-only.
function Get-TcpkAgentProcList {
    $list = New-Object System.Collections.Generic.List[object]
    try { Get-Process -ErrorAction SilentlyContinue | Sort-Object ProcessName | ForEach-Object { $list.Add(@{ name = "$($_.ProcessName)"; pid = $_.Id }) } } catch {}
    return @{ procs = $list.ToArray() }
}
# POST /api/agent/procmon {proc} -- a full read-only snapshot of ONE running process for the
# live-watch view (identity, memory, loaded modules, TCP connections, child processes). The
# browser polls this on an interval. Observes only -- never launches / injects / dumps.
function Get-TcpkAgentProcmon {
    [CmdletBinding()] param([string]$Proc)
    $t = "$Proc".Trim(); if (-not $t) { return @{ error = 'no process' } }
    $p = $null
    if ($t -match '^\d+$') { try { $p = Get-Process -Id ([int]$t) -ErrorAction Stop } catch {} }
    if (-not $p -and $t -match '\(pid\s+(\d+)\)') { try { $p = Get-Process -Id ([int]$Matches[1]) -ErrorAction Stop } catch {} }
    if (-not $p) { $nm = $t -replace '\.exe$', ''; try { $p = Get-Process -Name $nm -ErrorAction Stop | Select-Object -First 1 } catch {} }
    if (-not $p) { return @{ error = "process not found: $t" } }
    $pid2 = $p.Id
    $path = ''; try { $path = $p.MainModule.FileName } catch { $path = '(access denied)' }
    $desc = ''; $comp = ''; $prod = ''; $fver = ''
    try { $fvi = $p.MainModule.FileVersionInfo; $desc = "$($fvi.FileDescription)"; $comp = "$($fvi.CompanyName)"; $prod = "$($fvi.ProductName)"; $fver = "$($fvi.FileVersion)" } catch {}
    $ci = $null; try { $ci = Get-CimInstance Win32_Process -Filter "ProcessId=$pid2" -ErrorAction SilentlyContinue } catch {}
    $parent = ''; $cmd = ''; if ($ci) { $parent = "$($ci.ParentProcessId)"; $cmd = "$($ci.CommandLine)" }
    $owner = ''; try { if ($ci) { $ow = $ci | Invoke-CimMethod -MethodName GetOwner -ErrorAction SilentlyContinue; if ($ow -and $ow.User) { $owner = "$($ow.Domain)\$($ow.User)" } } } catch {}
    $started = ''; try { $started = $p.StartTime.ToString('yyyy-MM-dd HH:mm:ss') } catch {}
    $prio = ''; try { $prio = "$($p.PriorityClass)" } catch {}
    $sess = ''; try { $sess = "$($p.SessionId)" } catch {}
    $mods = New-Object System.Collections.Generic.List[object]
    try { foreach ($m in $p.Modules) { $mn = ''; $mf = ''; try { $mn = "$($m.ModuleName)" } catch {}; try { $mf = "$($m.FileName)" } catch {}; $mods.Add(@{ name = $mn; path = $mf }) } } catch {}
    $conns = New-Object System.Collections.Generic.List[object]
    try { foreach ($c in (Get-NetTCPConnection -OwningProcess $pid2 -ErrorAction SilentlyContinue)) { $conns.Add(@{ local = "$($c.LocalAddress):$($c.LocalPort)"; remote = "$($c.RemoteAddress):$($c.RemotePort)"; state = "$($c.State)" }) } } catch {}
    $kids = New-Object System.Collections.Generic.List[object]
    try { foreach ($k in (Get-CimInstance Win32_Process -Filter "ParentProcessId=$pid2" -ErrorAction SilentlyContinue)) { $kids.Add(@{ name = "$($k.Name)"; pid = $k.ProcessId }) } } catch {}
    $cpu = 0; try { $cpu = [Math]::Round($p.CPU, 1) } catch {}
    return @{
        ok = $true; pid = $pid2; name = "$($p.ProcessName)"; path = $path; desc = $desc; company = $comp; product = $prod; fver = $fver
        parent = $parent; user = $owner; started = $started; priority = $prio; session = $sess; cmd = $cmd
        ws = [Math]::Round($p.WorkingSet64 / 1MB, 1); priv = [Math]::Round($p.PrivateMemorySize64 / 1MB, 1)
        peak = [Math]::Round($p.PeakWorkingSet64 / 1MB, 1); virt = [Math]::Round($p.VirtualMemorySize64 / 1MB, 1)
        handles = $p.HandleCount; threads = $p.Threads.Count; cpu = $cpu
        modules = $mods.ToArray(); conns = $conns.ToArray(); children = $kids.ToArray()
    }
}

# POST /api/agent/audit-binary {dll} -- a FOCUSED, per-binary static audit of ONE module.
# The Decompile pane's "Audit selected" used to call /api/run (a full app audit) per DLL, so
# it re-discovered the whole app (e.g. an Electron app.asar) and returned identical whole-app
# findings for every binary. This runs only the FILE-SCOPED checks against the single file, so
# results are actually about that binary (PE hardening, IL/native sinks, secrets, TLS, deser,
# signing). Discovery-only: reads the file, never executes it.
function Get-TcpkAgentBinaryAudit {
    [CmdletBinding()] param([string]$Dll)
    $p = Resolve-TcpkWebTarget $Dll
    if (-not $p -or -not (Test-Path -LiteralPath $p -PathType Leaf)) { return @{ error = 'file not found' } }
    $fs = New-Object System.Collections.Generic.List[object]
    foreach ($c in 'Test-TcpkPeMitigations','Test-TcpkCallsites','Test-TcpkSecrets','Test-TcpkTlsBypass','Test-TcpkDeserialization') {
        if (-not (Get-Command $c -ErrorAction SilentlyContinue)) { continue }
        try { foreach ($f in @(& $c -Path $p)) { if ($f) { $fs.Add($f) } } } catch { }
    }
    # Per-file Authenticode: emit a finding when the binary is not validly signed.
    try {
        $sig = Get-AuthenticodeSignature -LiteralPath $p -ErrorAction Stop
        if ("$($sig.Status)" -ne 'Valid') {
            $fs.Add([pscustomobject]@{ Severity = 'MEDIUM'; Confidence = 'Confirmed'; RuleId = 'authenticode.pe-not-signed'; Title = "$(Split-Path $p -Leaf) is not validly Authenticode-signed (status: $($sig.Status))"; Evidence = "$($sig.Status)"; File = (Split-Path $p -Leaf) })
        }
    } catch { }
    @{ dll = (Split-Path $p -Leaf); findings = @($fs | Where-Object { $_ } | ForEach-Object {
        [ordered]@{ sev = "$($_.Severity)"; conf = "$($_.Confidence)"; rule = "$($_.RuleId)"; title = "$($_.Title)"; evidence = "$($_.Evidence)" }
    }) }
}

# --- Asar extraction + hex view (agentic) -------------------------------------
# For an Electron target the developer's real code is JavaScript inside resources\app.asar.
# These routes extract the asar to a temp folder so the operator can browse/analyse the JS,
# and provide a bounded hex view of any in-scope file. Discovery-only: files are read, never
# executed. Extracted dirs are tracked so file reads can be scoped to them (anti-traversal).
$script:TcpkAgentAsarDirs = @{}

# POST /api/agent/asar {target} -- find the largest .asar under the target and unpack it to a
# temp folder, returning the file list. Reuses the asar layout from Get-TcpkAsarNpmComponents.
function Get-TcpkAgentAsar {
    [CmdletBinding()] param([string]$Target)
    $p = Resolve-TcpkWebTarget $Target
    if (-not $p) { return @{ error = 'target not found (pick one in step 2)' } }
    $dir = if (Test-Path -LiteralPath $p -PathType Container) { $p } else { Split-Path -Parent $p }
    $asar = Get-ChildItem -LiteralPath $dir -Recurse -File -Filter '*.asar' -ErrorAction SilentlyContinue | Sort-Object Length -Descending | Select-Object -First 1
    if (-not $asar) { return @{ error = 'no .asar found under the target (not an Electron app?)' } }
    if ($asar.Length -gt 400MB) { return @{ error = "asar too large to extract ($([int]($asar.Length/1MB)) MB)" } }
    try {
        $bytes = [System.IO.File]::ReadAllBytes($asar.FullName)
        if ($bytes.Length -lt 16) { return @{ error = 'asar too small / invalid' } }
        $headerObjSize = [System.BitConverter]::ToUInt32($bytes, 4)
        $jsonSize = [System.BitConverter]::ToUInt32($bytes, 12)
        if (($jsonSize + 16) -gt $bytes.Length) { return @{ error = 'asar header invalid' } }
        $tree = [System.Text.Encoding]::UTF8.GetString($bytes, 16, $jsonSize) | ConvertFrom-Json
        $base = 8 + $headerObjSize
        $outDir = Join-Path ([System.IO.Path]::GetTempPath()) ('tcpk-asar-' + [System.Guid]::NewGuid().ToString('N').Substring(0, 10))
        New-Item -ItemType Directory -Path $outDir -Force | Out-Null
        $files = New-Object System.Collections.Generic.List[object]
        $stack = New-Object System.Collections.Generic.Stack[object]
        $stack.Push([pscustomobject]@{ node = $tree; rel = '' })
        $total = [int64]0; $cap = [int64]200MB
        while ($stack.Count) {
            $cur = $stack.Pop()
            if (-not $cur.node.files) { continue }
            foreach ($prop in $cur.node.files.PSObject.Properties) {
                $child = $prop.Value
                $childRel = if ($cur.rel) { "$($cur.rel)/$($prop.Name)" } else { "$($prop.Name)" }
                if ($child.files) { $stack.Push([pscustomobject]@{ node = $child; rel = $childRel }); continue }
                if ($null -eq $child.offset) { continue }
                $sz = [int64]$child.size; $off = $base + [int64]$child.offset
                if ($sz -lt 0 -or ($off + $sz) -gt $bytes.Length) { continue }
                if (($total + $sz) -gt $cap -or $files.Count -ge 8000) { continue }
                $dest = Join-Path $outDir ($childRel -replace '/', '\')
                $ddir = Split-Path -Parent $dest
                if ($ddir -and -not (Test-Path -LiteralPath $ddir)) { New-Item -ItemType Directory -Path $ddir -Force | Out-Null }
                $buf = New-Object 'byte[]' $sz
                if ($sz -gt 0) { [System.Array]::Copy($bytes, $off, $buf, 0, $sz) }
                [System.IO.File]::WriteAllBytes($dest, $buf)
                $files.Add([ordered]@{ path = $childRel; size = $sz })
                $total += $sz
            }
        }
        $script:TcpkAgentAsarDirs[$outDir] = $true
        return @{ asar = $asar.FullName; outDir = $outDir; count = $files.Count; bytes = $total; files = @($files.ToArray() | Sort-Object { $_.path }) }
    } catch { return @{ error = "$($_.Exception.Message)" } }
}

# POST /api/agent/asar-file {dir, rel} -- read one extracted file's text (bounded), scoped to
# the tracked extract dir so a '..' cannot escape it.
function Get-TcpkAgentAsarFile {
    [CmdletBinding()] param([string]$Dir, [string]$Rel)
    if (-not $Dir -or -not $script:TcpkAgentAsarDirs.ContainsKey($Dir)) { return @{ error = 'unknown extract dir (extract first)' } }
    $full = try { [System.IO.Path]::GetFullPath((Join-Path $Dir ($Rel -replace '/', '\'))) } catch { return @{ error = 'bad path' } }
    $root = ([System.IO.Path]::GetFullPath($Dir)).TrimEnd('\') + '\'
    if (-not $full.StartsWith($root, [System.StringComparison]::OrdinalIgnoreCase)) { return @{ error = 'path outside the extract dir' } }
    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) { return @{ error = 'file not found' } }
    $sz = (Get-Item -LiteralPath $full).Length
    $cap = [int64]512KB
    $bytes = [System.IO.File]::ReadAllBytes($full)
    $trunc = $false
    if ($bytes.Length -gt $cap) { $b2 = New-Object 'byte[]' $cap; [System.Array]::Copy($bytes, 0, $b2, 0, $cap); $bytes = $b2; $trunc = $true }
    @{ path = $Rel; size = $sz; truncated = $trunc; text = [System.Text.Encoding]::UTF8.GetString($bytes); full = $full }
}

# POST /api/agent/hex {path, offset, length} -- a bounded hex + ASCII page of any in-scope file
# (a native DLL, or a file from an extracted asar). Read-only, chunked (files can be huge).
function Get-TcpkAgentHex {
    [CmdletBinding()] param([string]$Path, [int]$Offset = 0, [int]$Length = 2048)
    $p = Resolve-TcpkWebTarget $Path
    if (-not $p -or -not (Test-Path -LiteralPath $p -PathType Leaf)) { return @{ error = 'file not found' } }
    if ($Length -le 0 -or $Length -gt 8192) { $Length = 2048 }
    if ($Offset -lt 0) { $Offset = 0 }
    $fi = Get-Item -LiteralPath $p
    $total = [int64]$fi.Length
    if ($Offset -ge $total) { return @{ path = $fi.Name; size = $total; offset = $Offset; rows = @() } }
    $count = [int][Math]::Min([int64]$Length, $total - $Offset)
    $buf = New-Object 'byte[]' $count
    $fsr = [System.IO.File]::OpenRead($p)
    try { [void]$fsr.Seek($Offset, 'Begin'); [void]$fsr.Read($buf, 0, $count) } finally { $fsr.Dispose() }
    $rows = New-Object System.Collections.Generic.List[object]
    for ($i = 0; $i -lt $count; $i += 16) {
        $n = [Math]::Min(16, $count - $i)
        $hex = New-Object System.Text.StringBuilder
        $asc = New-Object System.Text.StringBuilder
        for ($j = 0; $j -lt 16; $j++) {
            if ($j -lt $n) {
                $bv = $buf[$i + $j]
                [void]$hex.Append(('{0:x2} ' -f $bv))
                $ch = if ($bv -ge 32 -and $bv -lt 127) { [char]$bv } else { '.' }
                [void]$asc.Append($ch)
            } else { [void]$hex.Append('   ') }
            if ($j -eq 7) { [void]$hex.Append(' ') }
        }
        $rows.Add([ordered]@{ off = ('{0:x8}' -f ($Offset + $i)); hex = $hex.ToString().TrimEnd(); ascii = $asc.ToString() })
    }
    @{ path = $fi.Name; size = $total; offset = $Offset; length = $count; rows = @($rows.ToArray()) }
}

# POST /api/agent/inspect {path, offset} -- Data Inspector: interpret the 16 bytes at an offset
# as int/uint 8/16/32/64 (LE + BE), float/double, ASCII / UTF-16, and a u32 epoch timestamp.
function Get-TcpkAgentHexInspect {
    [CmdletBinding()] param([string]$Path, [int64]$Offset = 0)
    $p = Resolve-TcpkWebTarget $Path
    if (-not $p -or -not (Test-Path -LiteralPath $p -PathType Leaf)) { return @{ error = 'file not found' } }
    if ($Offset -lt 0) { $Offset = 0 }
    $total = [int64](Get-Item -LiteralPath $p).Length
    if ($Offset -ge $total) { return @{ error = 'offset past end of file' } }
    $n = [int][Math]::Min([int64]16, $total - $Offset)
    $buf = New-Object 'byte[]' 16
    $fsr = [System.IO.File]::OpenRead($p)
    try { [void]$fsr.Seek($Offset, 'Begin'); [void]$fsr.Read($buf, 0, $n) } finally { $fsr.Dispose() }
    $be = { param($len) $c = New-Object 'byte[]' $len; [System.Array]::Copy($buf, 0, $c, 0, $len); [System.Array]::Reverse($c); , $c }
    $rows = New-Object System.Collections.Generic.List[object]
    $add = { param($k, $v) $rows.Add([ordered]@{ n = $k; v = "$v" }) }
    & $add 'int8'      ([sbyte]$buf[0]);            & $add 'uint8'     ($buf[0])
    & $add 'int16 LE'  ([System.BitConverter]::ToInt16($buf, 0));  & $add 'int16 BE' ([System.BitConverter]::ToInt16((& $be 2), 0))
    & $add 'uint16 LE' ([System.BitConverter]::ToUInt16($buf, 0)); & $add 'uint16 BE'([System.BitConverter]::ToUInt16((& $be 2), 0))
    & $add 'int32 LE'  ([System.BitConverter]::ToInt32($buf, 0));  & $add 'int32 BE' ([System.BitConverter]::ToInt32((& $be 4), 0))
    & $add 'uint32 LE' ([System.BitConverter]::ToUInt32($buf, 0)); & $add 'uint32 BE'([System.BitConverter]::ToUInt32((& $be 4), 0))
    & $add 'int64 LE'  ([System.BitConverter]::ToInt64($buf, 0));  & $add 'uint64 LE'([System.BitConverter]::ToUInt64($buf, 0))
    & $add 'float LE'  ([System.BitConverter]::ToSingle($buf, 0)); & $add 'double LE'([System.BitConverter]::ToDouble($buf, 0))
    $asc = -join (0..([Math]::Min(15, $n - 1)) | ForEach-Object { $b = $buf[$_]; if ($b -ge 32 -and $b -lt 127) { [char]$b } else { '.' } })
    & $add 'ASCII (16)' $asc
    try { & $add 'UTF-16 (8)' (([System.Text.Encoding]::Unicode.GetString($buf, 0, 16)) -replace '[\x00-\x1f]', '.') } catch { }
    try { $u = [System.BitConverter]::ToUInt32($buf, 0); if ($u -gt 0 -and $u -lt 4102444800) { & $add 'u32 as epoch' ([System.DateTimeOffset]::FromUnixTimeSeconds($u).UtcDateTime.ToString('u')) } } catch { }
    @{ offset = $Offset; size = $total; rows = @($rows.ToArray()) }
}

# Naive byte-substring search (fine for typical DLL/asar sizes); returns -1 if not found.
function Find-TcpkBytesIndex {
    [CmdletBinding()] param([byte[]]$Hay, [byte[]]$Needle, [int64]$Start)
    $nlen = $Needle.Length; if ($nlen -eq 0) { return [int64]-1 }
    $lim = $Hay.Length - $nlen
    for ($i = [int]([Math]::Max([int64]0, $Start)); $i -le $lim; $i++) {
        $ok = $true
        for ($j = 0; $j -lt $nlen; $j++) { if ($Hay[$i + $j] -ne $Needle[$j]) { $ok = $false; break } }
        if ($ok) { return [int64]$i }
    }
    return [int64]-1
}

# POST /api/agent/hexfind {path, query, kind, from} -- find the next 'hex' or 'ascii' match at
# or after 'from'. Reads the whole file (size-guarded).
function Get-TcpkAgentHexFind {
    [CmdletBinding()] param([string]$Path, [string]$Query, [string]$Kind = 'ascii', [int64]$From = 0)
    $p = Resolve-TcpkWebTarget $Path
    if (-not $p -or -not (Test-Path -LiteralPath $p -PathType Leaf)) { return @{ error = 'file not found' } }
    if ([string]::IsNullOrEmpty($Query)) { return @{ error = 'empty search' } }
    if ((Get-Item -LiteralPath $p).Length -gt 300MB) { return @{ error = 'file too large to search' } }
    $needle = $null
    if ($Kind -eq 'hex') {
        $hx = ($Query -replace '[^0-9a-fA-F]', '')
        if ($hx.Length -lt 2 -or ($hx.Length % 2)) { return @{ error = 'hex needs an even number of hex digits' } }
        $needle = [byte[]](0..(($hx.Length / 2) - 1) | ForEach-Object { [Convert]::ToByte($hx.Substring($_ * 2, 2), 16) })
    } else {
        $needle = [System.Text.Encoding]::ASCII.GetBytes($Query)
    }
    $bytes = [System.IO.File]::ReadAllBytes($p)
    $idx = Find-TcpkBytesIndex -Hay $bytes -Needle $needle -Start $From
    @{ offset = $idx; size = $bytes.Length; needleLen = $needle.Length }
}

# POST /api/agent/strings {path, min, filter, kind} -- extract printable ASCII + UTF-16LE
# ("wide") strings with their byte offsets, so a name / URL / path / function name can be
# clicked to jump into the hex view. 'filter' narrows to strings containing a substring
# (case-insensitive) -- this is the "find a name" case. Reads the whole file (size-guarded);
# a regex over a Latin1 view keeps every match's byte offset exact and is fast.
function Get-TcpkAgentHexStrings {
    [CmdletBinding()] param([string]$Path, [int]$Min = 4, [string]$Filter = '', [string]$Kind = 'both', [int]$Cap = 2000)
    $p = Resolve-TcpkWebTarget $Path
    if (-not $p -or -not (Test-Path -LiteralPath $p -PathType Leaf)) { return @{ error = 'file not found' } }
    if ((Get-Item -LiteralPath $p).Length -gt 300MB) { return @{ error = 'file too large to scan' } }
    if ($Min -lt 2) { $Min = 2 } elseif ($Min -gt 200) { $Min = 200 }
    if ($Cap -lt 1) { $Cap = 1 } elseif ($Cap -gt 20000) { $Cap = 20000 }
    $bytes = [System.IO.File]::ReadAllBytes($p)
    $lat = [System.Text.Encoding]::GetEncoding(28591)   # Latin1: 1 byte <-> 1 char, offsets preserved
    $text = $lat.GetString($bytes)
    $flt = "$Filter"
    $hits = New-Object System.Collections.Generic.List[object]
    $total = 0
    $cmp = [System.StringComparison]::OrdinalIgnoreCase
    if ($Kind -eq 'both' -or $Kind -eq 'ascii') {
        foreach ($m in ([regex]::Matches($text, "[\x20-\x7E]{$Min,}"))) {
            $v = $m.Value
            if ($flt -and $v.IndexOf($flt, $cmp) -lt 0) { continue }
            $total++
            if ($hits.Count -lt $Cap) {
                if ($v.Length -gt 300) { $v = $v.Substring(0, 300) }
                $hits.Add([pscustomobject]@{ offset = [int64]$m.Index; kind = 'a'; text = $v })
            }
        }
    }
    if ($Kind -eq 'both' -or $Kind -eq 'wide') {
        foreach ($m in ([regex]::Matches($text, "(?:[\x20-\x7E]\x00){$Min,}"))) {
            $v = [System.Text.Encoding]::Unicode.GetString($bytes, $m.Index, $m.Length)
            if ($flt -and $v.IndexOf($flt, $cmp) -lt 0) { continue }
            $total++
            if ($hits.Count -lt $Cap) {
                if ($v.Length -gt 300) { $v = $v.Substring(0, 300) }
                $hits.Add([pscustomobject]@{ offset = [int64]$m.Index; kind = 'w'; text = $v })
            }
        }
    }
    $items = @($hits | Sort-Object offset)
    @{ items = $items; total = $total; capped = [bool]($total -gt $items.Count); min = $Min; size = $bytes.Length }
}

# POST /api/agent/native {dll} -- for a NON-.NET (native) PE: exploit-mitigation
# (ASLR/DEP/CFG/...) flags, Authenticode signing, high-risk imported APIs, and
# import/export counts. Read-only PE parse -- the target is never executed. This is
# what the workbench shows when the user selects a native DLL (Cecil can't read it).
function Get-TcpkAgentNativePe {
    [CmdletBinding()] param([Parameter(Mandatory)][AllowEmptyString()][string]$Dll)
    $p = Resolve-TcpkWebTarget $Dll
    if (-not $p -or -not (Test-Path -LiteralPath $p -PathType Leaf)) { return @{ error = 'file not found' } }
    $info = Read-TcpkPe -Path $p
    if (-not $info) { return @{ error = 'not a readable PE file' } }

    $arch = switch ($info.Machine) { 0x8664 {'x64'} 0x14C {'x86'} 0xAA64 {'ARM64'} 0x1C0 {'ARM'} 0x1C4 {'ARM'} default { ('0x{0:X}' -f $info.Machine) } }

    $hb = @{ ASLR = 0x0040; DEP = 0x0100; CFG = 0x4000; HighEntropyVA = 0x0020; ForceIntegrity = 0x0080 }
    $hard = [ordered]@{}
    foreach ($k in 'ASLR','DEP','CFG','HighEntropyVA','ForceIntegrity') { $hard[$k] = [bool]($info.DllCharacteristics -band $hb[$k]) }
    $hard['SafeSEH'] = "$($info.SafeSeh)"
    $hard['GS']      = "$($info.StackCookie)"
    $missing = @(); foreach ($n in 'ASLR','DEP','CFG') { if (-not $hard[$n]) { $missing += $n } }
    $status = if (-not $hard['ASLR'] -or -not $hard['DEP']) { 'WEAK' } elseif ($missing.Count) { 'PARTIAL' } else { 'HARDENED' }

    $sign = @{ status = 'unknown'; signer = '' }
    try {
        $sig = Get-AuthenticodeSignature -LiteralPath $p -ErrorAction Stop
        $sign.status = "$($sig.Status)"
        if ($sig.SignerCertificate) { $sign.signer = "$($sig.SignerCertificate.Subject)" }
    } catch { }

    $risky = @{
        'CreateProcessW'='spawns a child process';'CreateProcessA'='spawns a child process';'CreateProcessAsUserW'='spawns a process as another user';'WinExec'='spawns a child process';'ShellExecuteW'='launches a program or URL';'ShellExecuteA'='launches a program or URL';'ShellExecuteExW'='launches a program or URL';'system'='shell command execution';'_wsystem'='shell command execution';'_popen'='shell pipe execution';
        'WriteProcessMemory'='process-injection primitive';'VirtualAllocEx'='process-injection primitive';'CreateRemoteThread'='remote-thread injection';'SetWindowsHookExW'='global hook / injection';'QueueUserAPC'='APC injection';'NtMapViewOfSection'='section-mapping injection';
        'LoadLibraryW'='dynamic library load';'LoadLibraryA'='dynamic library load';'LoadLibraryExW'='dynamic library load';'GetProcAddress'='dynamic symbol resolution';
        'strcpy'='unbounded copy (overflow risk)';'strcat'='unbounded concat (overflow risk)';'sprintf'='unbounded format (overflow risk)';'gets'='unbounded input (overflow risk)';'lstrcpyW'='legacy unbounded copy';'lstrcatW'='legacy unbounded concat';'wcscpy'='unbounded wide copy';'_snwprintf'='non-terminating format';
        'URLDownloadToFileW'='downloads a remote file';'InternetOpenUrlW'='HTTP fetch';'WinHttpConnect'='HTTP connection';'HttpSendRequestW'='HTTP request';
        'RegSetValueExW'='writes the registry';'RegCreateKeyExW'='creates registry keys';
        'WinVerifyTrust'='signature verification (check if bypassable)';'CryptDecrypt'='decrypts data';'CryptEncrypt'='encrypts data'
    }
    $imp = @($info.Imports)
    $hits = New-Object 'System.Collections.Generic.List[object]'
    foreach ($fn in ($imp | Select-Object -Unique)) { if ($risky.ContainsKey("$fn")) { $hits.Add([ordered]@{ api = "$fn"; note = $risky["$fn"] }) } }

    return @{
        file = (Split-Path $p -Leaf); arch = $arch; managed = $false
        hardening = $hard; hardeningStatus = $status; missing = ($missing -join ', ')
        signing = $sign
        importsTotal = $imp.Count; exportsTotal = @($info.Exports).Count
        riskyImports = @($hits.ToArray())
        exportsSample = @(@($info.Exports) | Select-Object -First 12)
    }
}

# POST /api/agent/decompile {dll, method?} -- with no method: the module's type/method
# totals + the methods that INVOKE a sink (the ones worth reading). With a method
# ("Type::Method"): that method's IL body, each instruction flagged if it calls a sink.
function Get-TcpkAgentDecompile {
    [CmdletBinding()] param([Parameter(Mandatory)][AllowEmptyString()][string]$Dll, [string]$Method)
    $p = Resolve-TcpkWebTarget $Dll
    if (-not $p) { return @{ error = 'module not found' } }
    if (-not (Initialize-TcpkCecil)) { return @{ error = 'decompiler unavailable -- bundle Mono.Cecil into tools\ILSpy\' } }
    $asm = Get-TcpkCecilAssembly $p
    if (-not $asm) { return @{ error = 'not a managed .NET assembly' } }

    if ("$Method") {
        $md = $null
        foreach ($t in $asm.MainModule.GetTypes()) {
            foreach ($m in $t.Methods) { if ("$($t.FullName)::$($m.Name)" -eq $Method) { $md = $m; break } }
            if ($md) { break }
        }
        if (-not $md) { return @{ error = 'method not found' } }
        $il = New-Object 'System.Collections.Generic.List[object]'
        if ($md.HasBody) {
            $n = 0
            foreach ($ins in $md.Body.Instructions) {
                $arg = "$($ins.Operand)"
                $mref = $ins.Operand -as [Mono.Cecil.MethodReference]
                $isSink = [bool](Get-TcpkAgentSinkHit $mref)
                if ($arg.Length -gt 130) { $arg = $arg.Substring(0, 130) + '...' }
                $il.Add([ordered]@{ off = ('IL_{0:X4}' -f $ins.Offset); op = "$($ins.OpCode.Name)"; arg = $arg; sink = $isSink })
                $n++; if ($n -ge 400) { break }
            }
        }
        return @{ method = "$($md.DeclaringType.FullName)::$($md.Name)"; sig = "$($md.FullName)"; il = @($il.ToArray()) }
    }

    $methods = New-Object 'System.Collections.Generic.List[object]'
    $tc = 0; $mc = 0
    foreach ($t in $asm.MainModule.GetTypes()) {
        $tc++
        foreach ($m in $t.Methods) {
            if (-not $m.HasBody) { continue }
            $mc++
            if ($methods.Count -ge 120) { continue }
            $hits = New-Object 'System.Collections.Generic.List[string]'
            foreach ($ins in $m.Body.Instructions) {
                $mref = $ins.Operand -as [Mono.Cecil.MethodReference]
                $lbl = Get-TcpkAgentSinkHit $mref
                if ($lbl) { [void]$hits.Add($lbl) }
            }
            if ($hits.Count) { $methods.Add([ordered]@{ name = "$($t.FullName)::$($m.Name)"; sinks = @($hits | Select-Object -Unique | Select-Object -First 5) }) }
        }
    }
    return @{ module = (Split-Path $p -Leaf); types = $tc; methods = $mc; interesting = @($methods.ToArray()) }
}

# --- Phase 3: AI line-by-line review (agentic) ---------------------------------
# The selected agent reads ONE method's decompiled IL and judges exploitability; the
# deterministic IL reachability (caller scan) is computed alongside so the UI shows
# proven facts next to the model's opinion. Mirrors Invoke-TcpkLlmCodeJudgment's policy:
# the LLM is ADVISORY -- reachability/sinks are the ground truth. Cloud egress is gated.

# Deterministic reachability for one method: public / virtual / entry-point / event-
# handler-shaped / has an in-assembly caller. The caller set is scanned once per assembly.
function Get-TcpkAgentReachable {
    param($Asm, $Method)
    if (-not $script:TcpkAgentCalledCache) { $script:TcpkAgentCalledCache = @{} }
    $key = "$($Asm.FullName)"
    $called = $script:TcpkAgentCalledCache[$key]
    if (-not $called) {
        $called = New-Object 'System.Collections.Generic.HashSet[string]'
        try {
            foreach ($t in $Asm.MainModule.GetTypes()) {
                foreach ($m in $t.Methods) {
                    if (-not $m.HasBody) { continue }
                    foreach ($ins in $m.Body.Instructions) { $r = $ins.Operand -as [Mono.Cecil.MethodReference]; if ($r) { [void]$called.Add($r.FullName) } }
                }
            }
        } catch { }
        $script:TcpkAgentCalledCache[$key] = $called
    }
    $handlerRx = '^(On[A-Z]|.*_(Click|Load|Closing|Closed|Changed|Tick)$|Handle|Execute$|CanExecute$)'
    return [bool]($Method.IsPublic -or $Method.IsVirtual -or $called.Contains($Method.FullName) -or ("$($Method.Name)" -match $handlerRx))
}

# POST /api/agent/review {dll, method, provider?, model?, apiKey?, baseUrl?, allowCloud?}
function Get-TcpkAgentReview {
    [CmdletBinding()] param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Dll,
        [Parameter(Mandatory)][AllowEmptyString()][string]$Method,
        $Agent
    )
    $p = Resolve-TcpkWebTarget $Dll
    if (-not $p) { return @{ error = 'module not found' } }
    if (-not "$Method") { return @{ error = 'no method selected' } }
    if (-not (Initialize-TcpkCecil)) { return @{ error = 'decompiler unavailable -- bundle Mono.Cecil into tools\ILSpy\' } }
    $asm = Get-TcpkCecilAssembly $p
    if (-not $asm) { return @{ error = 'not a managed .NET assembly' } }

    $md = $null
    foreach ($t in $asm.MainModule.GetTypes()) { foreach ($m in $t.Methods) { if ("$($t.FullName)::$($m.Name)" -eq $Method) { $md = $m; break } }; if ($md) { break } }
    if (-not $md) { return @{ error = 'method not found' } }

    $ilLines = New-Object 'System.Collections.Generic.List[string]'
    $sinks = New-Object 'System.Collections.Generic.List[string]'
    if ($md.HasBody) {
        $n = 0
        foreach ($ins in $md.Body.Instructions) {
            $arg = "$($ins.Operand)"; if ($arg.Length -gt 140) { $arg = $arg.Substring(0, 140) + '...' }
            $ilLines.Add(('IL_{0:X4}  {1} {2}' -f $ins.Offset, $ins.OpCode.Name, $arg))
            $lbl = Get-TcpkAgentSinkHit ($ins.Operand -as [Mono.Cecil.MethodReference]); if ($lbl) { [void]$sinks.Add($lbl) }
            $n++; if ($n -ge 400) { break }
        }
    }
    $sinkList = @($sinks | Select-Object -Unique)
    $ilText = ($ilLines -join "`n")
    $reach = Get-TcpkAgentReachable -Asm $asm -Method $md

    # apply the chosen agent + gate cloud egress (no IL leaves the box for a local agent)
    if ($Agent) { try { Set-TcpkWebLlmConfig -Body $Agent } catch { } }
    $cloud = $false; try { $cloud = [bool](Test-TcpkLlmIsCloud) } catch { }
    if ($cloud) {
        if ($Agent -and $Agent.allowCloud) { $script:TcpkLlmCloudEnabled = $true }
        else { return @{ error = 'cloud agent selected but cloud egress is OFF -- enable "allow cloud egress" in step 1'; reachable = $reach; sinks = $sinkList; il = $ilText } }
    }
    $avail = $false; try { $avail = [bool](Test-TcpkLlmAvailable) } catch { }
    if (-not $avail) { return @{ error = 'AI agent not reachable -- configure + Test it in step 1 (Connect)'; reachable = $reach; sinks = $sinkList; il = $ilText } }

    $sys = @(
        'You are a senior application-security reviewer reading decompiled .NET CIL (IL) for ONE method.',
        'Judge whether this method contains a REAL, exploitable vulnerability, grounded in the actual opcodes.',
        'Be conservative: a mere API reference, a constant/guarded argument, or an unreachable helper is NOT a vulnerability.',
        'Weigh the listed sink APIs and whether attacker-controllable input could reach them in this method.',
        'Reply with ONLY this JSON (no prose, no code fences):',
        '{"verdict":"vulnerable|safe|uncertain","severity":"critical|high|medium|low|info","sink":"the dangerous API or none","risk":"one concise sentence","exploit":"how an attacker reaches/abuses it, or why not","fix":"one concrete remediation","lines":[{"il":"IL_XXXX","note":"why this specific line matters"}]}'
    ) -join "`n"
    $usr = "Method: $Method`nReachable (IL: public/virtual/entrypoint/has-caller): $reach`nSink APIs called: $((@($sinkList) -join ', '))`n`nDecompiled IL:`n$ilText"

    $ai = $null
    try { $ai = Invoke-TcpkLlm -System $sys -User $usr -AsJson } catch { return @{ error = "AI call failed: $($_.Exception.Message)"; reachable = $reach; sinks = $sinkList; il = $ilText } }
    return @{ method = $Method; reachable = $reach; sinks = $sinkList; il = $ilText; ai = $ai; cloud = $cloud }
}

# POST /api/agent/intercept {file, kind} -- parse an EXISTING mitmproxy (proxy) or Frida
# (hook) capture into intercept.* findings for the workbench. DISCOVERY-SAFE: it only
# parses a local capture via the ungated -FlowFile / -HookFile path -- it never launches
# or injects (the gated active capture stays a CLI operation, off the browser).
function Get-TcpkAgentInterceptReview {
    [CmdletBinding()] param([AllowEmptyString()][string]$File, [AllowEmptyString()][string]$Kind)
    if (-not "$File" -or -not (Test-Path -LiteralPath "$File" -PathType Leaf)) { return @{ error = 'capture file not found' } }
    $p = (Resolve-Path -LiteralPath "$File").Path
    $kind = if ("$Kind" -eq 'hook') { 'hook' } else { 'proxy' }
    $findings = @()
    try {
        $findings = if ($kind -eq 'hook') { Invoke-TcpkIntercept -HookFile $p } else { Invoke-TcpkIntercept -FlowFile $p }
    } catch { return @{ error = "parse failed: $($_.Exception.Message)" } }
    $rows = @(@($findings) | ForEach-Object { [ordered]@{ sev = "$($_.Severity)"; conf = "$($_.Confidence)"; rule = "$($_.RuleId)"; title = "$($_.Title)"; evidence = "$($_.Evidence)" } })
    $counts = [ordered]@{ crit = 0; high = 0; med = 0; low = 0; info = 0 }
    foreach ($r in $rows) {
        switch ("$($r.sev)".ToUpper()) { 'CRITICAL' { $counts.crit++ } 'HIGH' { $counts.high++ } 'MEDIUM' { $counts.med++ } 'LOW' { $counts.low++ } default { $counts.info++ } }
    }
    return @{ kind = $kind; count = $rows.Count; counts = $counts; findings = $rows }
}

# GET /api/agent/llm-models -- locally-pulled ollama models (best-effort), so the Connect
# step can show what is available and hint a pull when ollama is reachable but empty.
function Get-TcpkAgentLlmModels {
    [CmdletBinding()] param()
    $models = @()
    try {
        $r = Invoke-RestMethod 'http://localhost:11434/api/tags' -TimeoutSec 5
        $models = @($r.models | ForEach-Object { "$($_.name)" } | Where-Object { $_ })
    } catch { }
    $hint = if ($models.Count) { '' } else { 'ollama is reachable but has no local model -- run:  ollama pull qwen2.5-coder:7b' }
    return @{ models = @($models); hint = $hint }
}

# --- Phase 4: autonomous agent (async background job) --------------------------
# The agent loop makes many LLM calls, so it runs in a background Start-Job (like the
# audit) and streams AGS<tab>json step lines + a final AGR<tab>json result. DISCOVERY
# ONLY -- the agent's tools are read/analyze, never the exploit bucket.
function Get-TcpkAgentAutoJobScript {
    return {
        param($modulePath, $target, $goal, $model, $maxSteps)
        Import-Module $modulePath -Force
        Invoke-TcpkAgentAudit -Target $target -Goal $goal -Model $model -MaxSteps $maxSteps -StreamTagged
    }
}

function Start-TcpkAgentAutoJob {
    [CmdletBinding()] param([Parameter(Mandatory)]$Request, [Parameter(Mandatory)]$State)
    $b = $null; try { $b = $Request.Body | ConvertFrom-Json } catch { }
    $target = Resolve-TcpkWebTarget "$(if($b){$b.target})"
    if (-not $target) { return (New-TcpkWebJson 400 @{ error = 'target not found or invalid' }) }
    if ($b -and "$($b.provider)" -and "$($b.provider)" -ne 'ollama') {
        return (New-TcpkWebJson 400 @{ error = 'the autonomous agent is local-ollama-only in this build -- select the ollama provider' })
    }
    $goal  = if ($b -and "$($b.goal)")  { "$($b.goal)" }  else { 'Find the most serious vulnerabilities in this .NET target.' }
    $model = if ($b -and "$($b.model)") { "$($b.model)" } else { 'qwen2.5-coder:7b' }
    $jobId = [guid]::NewGuid().ToString('N')
    $job = Start-Job -ScriptBlock (Get-TcpkAgentAutoJobScript) -ArgumentList $State.Psd1, $target, $goal, $model, 20
    $State.AgentJobs[$jobId] = @{
        Job = $job; Steps = (New-Object 'System.Collections.Generic.List[object]')
        Findings = @(); Summary = ''; Done = $false; Result = $null
    }
    return (New-TcpkWebJson 200 @{ jobId = $jobId; model = $model })
}

function Get-TcpkAgentAutoStatus {
    [CmdletBinding()] param([Parameter(Mandatory)]$State, [Parameter(Mandatory)][string]$JobId)
    if (-not $State.AgentJobs.ContainsKey($JobId)) { return (New-TcpkWebJson 404 @{ error = 'no such agent job' }) }
    $e = $State.AgentJobs[$JobId]
    $out = @(); try { $out = @(Receive-Job -Job $e.Job -ErrorAction SilentlyContinue) } catch { }
    $jstate = "$($e.Job.State)"; $terminal = $jstate -in 'Completed', 'Failed', 'Stopped'
    if ($terminal) { try { $out += @(Receive-Job -Job $e.Job -ErrorAction SilentlyContinue) } catch { } }
    $newSteps = New-Object 'System.Collections.Generic.List[object]'
    foreach ($line in $out) {
        $s = "$line"
        if ($s.StartsWith("AGS`t")) { $j = $null; try { $j = $s.Substring(4) | ConvertFrom-Json } catch { }; if ($j) { $e.Steps.Add($j); $newSteps.Add($j) } }
        elseif ($s.StartsWith("AGR`t")) { $r = $null; try { $r = $s.Substring(4) | ConvertFrom-Json } catch { }; if ($r) { $e.Result = $r; $e.Findings = @($r.findings); $e.Summary = "$($r.summary)" } }
    }
    $resp = [ordered]@{ state = $jstate.ToLowerInvariant(); done = $false }
    $resp['steps'] = @($newSteps.ToArray())
    if ($terminal) {
        if (-not $e.Done) { $e.Done = $true; try { Remove-Job -Job $e.Job -Force -ErrorAction SilentlyContinue } catch { } }
        $resp.done = $true
        $resp['findings'] = @($e.Findings)
        $resp.summary = $e.Summary
    }
    return (New-TcpkWebJson 200 $resp)
}

# --- the single-page workbench (self-contained, no CDN) ------------------------
function Get-TcpkAgenticAppHtml {
    [CmdletBinding()] param()
    return $script:TCPK_AGENTIC_HTML
}

$script:TCPK_AGENTIC_HTML = @'
<!doctype html><html lang="en"><head><meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>TCPK agentic workbench</title>
<style>
:root{--bg:#0a0d13;--panel:#161b22;--panel2:#1c2230;--border:#30363d;--text:#e6edf3;--muted:#8b949e;--dim:#6e7681;
--accent:#2dd4bf;--blue:#58a6ff;--crit:#f85149;--high:#db6d28;--med:#d29922;--low:#3fb950;--info:#6a7585;
--il:#2ea043;--dyn:#39c5cf;--llm:#bc8cff;--mono:"Cascadia Code","Fira Code",Consolas,monospace;
--hxNull:#5a5a5a;--hxWs:#61afef;--hxAsc:#98c379;--hxCtl:#d19a66;--hxHigh:#c678dd;--hxSep:#5a6472}
*{box-sizing:border-box}html,body{height:100%}
body{margin:0;background:var(--bg);color:var(--text);font:13px/1.5 "Segoe UI",system-ui,Arial,sans-serif}
a{color:var(--blue);cursor:pointer;text-decoration:none}a:hover{text-decoration:underline}
.app{display:grid;grid-template-rows:auto 1fr auto;height:100vh}
.top{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;padding:9px 16px;border-bottom:1px solid var(--border);background:linear-gradient(180deg,#0e131d,#0a0d13)}
.brand{font:700 17px var(--mono)}.brand b{color:var(--accent)}.brand .v{color:var(--dim);font:400 11px var(--mono);margin-left:7px}
.tbar{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.chip{display:flex;gap:6px;align-items:center;font:11px var(--mono);color:var(--muted);background:var(--panel);border:1px solid var(--border);border-radius:18px;padding:4px 10px;max-width:330px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.chip b{color:var(--text)}
.dot{width:8px;height:8px;border-radius:50%;background:var(--dim);flex:0 0 auto}.dot.ok{background:var(--il)}.dot.bad{background:var(--crit)}
.scope{color:#08130a;background:var(--accent);border-radius:5px;padding:3px 9px;font:700 10px var(--mono)}
.mid{display:grid;grid-template-columns:228px 1fr;overflow:hidden}
.rail{border-right:1px solid var(--border);overflow:auto;padding:12px 0;background:#0c1018}
.step{display:flex;gap:10px;padding:10px 16px;cursor:pointer;border-left:3px solid transparent;opacity:.6}
.step:hover{background:var(--panel)}.step.active{opacity:1;border-left-color:var(--accent);background:var(--panel)}.step.done{opacity:1}
.step .num{flex:0 0 24px;height:24px;border-radius:50%;border:1px solid var(--border);display:flex;align-items:center;justify-content:center;font:700 11px var(--mono);color:var(--muted)}
.step.active .num{border-color:var(--accent);color:var(--accent)}.step.done .num{background:var(--accent);color:#08130a;border-color:var(--accent)}
.step .t{font:600 13px var(--mono)}.step .s{font:11px var(--mono);color:var(--dim)}
.legend{margin:14px 16px 0;border-top:1px solid var(--border);padding-top:12px}
.legend h5{margin:0 0 8px;font:700 10px var(--mono);color:var(--muted);letter-spacing:.06em}
.legend div{font:11px var(--mono);color:var(--muted);margin:4px 0;display:flex;gap:8px;align-items:center}
.cdot{width:9px;height:9px;border-radius:2px;flex:0 0 auto}
.stage{overflow:auto;padding:18px 22px}
.pane{display:none}.pane.on{display:block}
h2{font:700 17px var(--mono);margin:0 0 4px}.lead{color:var(--muted);margin:0 0 14px;font-size:12px}
.panel{background:var(--panel);border:1px solid var(--border);border-radius:9px;padding:14px;margin-bottom:11px}
.panel h3{margin:0 0 9px;font:700 11px var(--mono);color:var(--muted);letter-spacing:.05em}
label{font-size:11px;color:var(--muted)}
input[type=text],input[type=password],select{width:100%;background:var(--bg);border:1px solid var(--border);border-radius:7px;color:var(--text);padding:8px 10px;font:13px var(--mono)}
.row{display:flex;gap:10px;flex-wrap:wrap;align-items:flex-end;margin-bottom:10px}.row>div{flex:1;min-width:150px}
button{cursor:pointer;border:1px solid var(--border);border-radius:7px;padding:8px 15px;font:600 13px var(--mono);background:var(--panel2);color:var(--text)}
button.go{background:var(--accent);color:#08130a;border-color:var(--accent)}
button.warn{border-color:var(--med);color:var(--med)}button.stop{border-color:var(--crit);color:var(--crit)}
button:disabled{opacity:.4;cursor:default}
.mini{padding:5px 11px;font-size:12px}
.app-row{display:flex;justify-content:space-between;gap:10px;padding:7px 10px;border:1px solid var(--border);border-radius:7px;margin-top:6px;cursor:pointer;font:12px var(--mono);background:var(--bg)}
.app-row:hover{border-color:var(--accent)}.app-row .p{color:var(--dim);max-width:50%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.note{font:11px var(--mono);color:var(--muted);margin-top:7px}
.ctl{display:flex;gap:8px;flex-wrap:wrap;margin:8px 0}
.chk{display:flex;gap:6px;align-items:center;font:12px var(--mono);color:var(--text);margin:4px 14px 4px 0}
.chkrow{display:flex;flex-wrap:wrap;align-items:center;margin:6px 0}
.bar{height:8px;background:var(--bg);border:1px solid var(--border);border-radius:6px;overflow:hidden;margin:10px 0}
.bar i{display:block;height:100%;width:0;background:var(--accent);transition:width .3s}
.dash{display:flex;gap:16px;flex-wrap:wrap;align-items:center;margin:6px 0 14px}
.counts{display:flex;gap:8px;flex-wrap:wrap}
.cstat{background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:8px 13px;text-align:center;min-width:64px}
.cstat b{font:700 19px var(--mono);display:block;line-height:1.1}.cstat small{color:var(--muted);font-size:10px}
.s-crit b{color:var(--crit)}.s-high b{color:var(--high)}.s-med b{color:var(--med)}.s-low b{color:var(--low)}.s-info b{color:var(--info)}
.chips{display:flex;gap:6px;flex-wrap:wrap;margin:6px 0 10px}
.fchip{cursor:pointer;border:1px solid var(--border);border-radius:18px;padding:3px 11px;font:11px var(--mono);color:var(--muted);user-select:none}
.fchip.on{color:#08130a;font-weight:700}.fchip.crit.on{background:var(--crit)}.fchip.high.on{background:var(--high)}.fchip.med.on{background:var(--med)}.fchip.low.on{background:var(--low)}.fchip.info.on{background:var(--info);color:#fff}
.tbl-wrap{border:1px solid var(--border);border-radius:9px;overflow:auto;max-height:360px}
table{width:100%;border-collapse:collapse;font:12px var(--mono)}
th,td{text-align:left;padding:6px 10px;border-bottom:1px solid #1c2230;white-space:nowrap;vertical-align:top}
th{position:sticky;top:0;background:var(--panel);color:var(--muted);font-weight:700;z-index:1}
td.ttl{white-space:normal;max-width:520px;color:#dbe3ea}
.pill{font:700 9px var(--mono);padding:2px 7px;border-radius:4px;color:#08130a;display:inline-block}
.pill.crit{background:var(--crit)}.pill.high{background:var(--high)}.pill.med{background:var(--med)}.pill.low{background:var(--low)}.pill.info{background:var(--info);color:#fff}
.cb{font:10px var(--mono);padding:2px 7px;border-radius:11px;border:1px solid var(--border);color:var(--muted);display:inline-block}
.cb.il{color:var(--il);border-color:var(--il)}.cb.dyn{color:var(--dyn);border-color:var(--dyn)}.cb.llm{color:var(--llm);border-color:var(--llm)}.cb.conf{color:var(--blue);border-color:var(--blue)}
.cv{display:grid;grid-template-columns:210px 1fr 310px;gap:10px;height:430px}
.cv .col{background:#010409;border:1px solid var(--border);border-radius:8px;overflow:auto;padding:9px}
.cv h4{margin:0 0 8px;font:700 10px var(--mono);color:var(--muted);letter-spacing:.05em}
.file{font:12px var(--mono);color:#c9d1d9;padding:5px 7px;border-radius:6px;cursor:pointer}.file:hover{background:var(--panel)}.file.on{background:var(--panel2);color:var(--accent)}
.mtag{display:inline-block;font:700 9px var(--mono);padding:1px 5px;border-radius:3px;vertical-align:middle}.mtag.net{background:#12351f;color:#4ade80}.mtag.nat{background:#3a2f14;color:#fbbf24}
.code{font:12px/1.65 var(--mono);white-space:pre;color:#c9d1d9}
.code .ln{color:#3a4250;margin-right:12px;user-select:none}
.code .vuln{background:rgba(248,81,73,.14);display:block;margin:0 -9px;padding:0 9px}
.vcard{border:1px solid var(--border);border-left-width:3px;border-radius:7px;padding:9px;margin-bottom:9px;font:11px var(--mono);color:#c9d1d9}
.vcard.crit{border-left-color:var(--crit)}.vcard.med{border-left-color:var(--med)}
.vcard .h{display:flex;gap:7px;align-items:center;margin-bottom:6px}
.kbd{font:11px var(--mono);background:var(--panel2);border:1px solid var(--border);border-radius:4px;padding:1px 6px;color:var(--llm)}
.dl{display:inline-block;margin:6px 9px 0 0}
.dock{border-top:1px solid var(--border);background:#0c1018;height:172px;display:flex;flex-direction:column;transition:height .2s}
.dock.collapsed{height:33px}
.dh{display:flex;align-items:center;justify-content:space-between;padding:7px 14px;cursor:pointer;border-bottom:1px solid var(--border)}
.dh b{font:700 11px var(--mono);color:var(--muted);letter-spacing:.05em}.dh .meta{font:11px var(--mono);color:var(--dim)}
.console{flex:1;overflow:auto;padding:8px 14px;font:11px/1.6 var(--mono);color:#9fb1c1;white-space:pre-wrap;word-break:break-word}
.console .c-find{color:#aed6f1}.console .c-step{color:var(--accent)}.console .c-warn{color:var(--med)}
/* --- UI polish: spacing, visibility, rail organization --- */
:root{--muted:#9aa6b2;--dim:#828d99}
body{line-height:1.6}
input:not([type]),input[type=text],input[type=password],input[type=search]{width:100%;background:var(--bg);border:1px solid var(--border);border-radius:7px;color:var(--text);padding:8px 10px;font:13px var(--mono)}
input::placeholder{color:var(--dim)}
select{background:var(--bg);color:var(--text);border:1px solid var(--border)}
select option{background:var(--panel);color:var(--text)}
.mid{grid-template-columns:248px 1fr}
.stage{padding:22px 28px}
.step{opacity:.85;padding:11px 18px}.step .s{color:var(--muted)}
h2{font-size:18px;margin-bottom:5px}
.lead{font-size:13px;max-width:900px;margin-bottom:16px}
.panel{padding:16px;margin-bottom:14px}
label{font-size:12px}
.note{font-size:12px;line-height:1.55}
.cv{height:60vh;min-height:340px;gap:12px}.cv h4{font-size:11px}
.tbl-wrap{max-height:54vh}
th,td{padding:7px 11px}
.railsep{margin:14px 16px 4px;font:700 9px var(--mono);color:var(--dim);letter-spacing:.14em;text-transform:uppercase;border-top:1px solid var(--border);padding-top:11px}
.railsep.first{border-top:none;padding-top:0;margin:2px 16px 4px}
@media(max-width:1080px){.cv{grid-template-columns:1fr !important;height:auto !important}.cv .col{min-height:200px;max-height:48vh}}
/* --- Dashboard: faithful port of the proposed-redesign mockup, scoped under .dbwrap so
   the mockup class names (.card/.tile/.pill/table/...) never collide with the app's own. --- */
.dbwrap{--line:#232a37;--line-soft:#1a202b;--raise:#1b212d;--faint:#69737f;--accent-ink:#0b0e14;--good:#37c08b;--r:9px;--r-sm:6px;--panel:#11151d;--panel2:#161b25;--dim:#9aa5b4;--text:#e7ebf2;--bg:#0b0e14;--crit:#f0555c;--high:#f5872f;--med:#e5b213;--low:#4f95d8;--info:#7d8899;--accent:#2dd4bf;font-size:13.5px;line-height:1.45}
.dbwrap .pagehead{display:flex;align-items:baseline;gap:12px;margin:0 2px 16px;flex-wrap:wrap}
.dbwrap .pagehead h1{font-size:19px;font-weight:700;margin:0;letter-spacing:.2px;color:var(--text)}
.dbwrap .pagehead .sub{color:var(--dim);font-size:12.5px}.dbwrap .pagehead .sub b{color:var(--good);font-weight:600}
.dbwrap .grid{display:grid;gap:14px}
.dbwrap .stats{grid-template-columns:repeat(6,1fr)}
.dbwrap .tile{background:var(--panel);border:1px solid var(--line);border-radius:var(--r);padding:13px 14px;position:relative;overflow:hidden}
.dbwrap .tile .k{font-size:11px;letter-spacing:.08em;text-transform:uppercase;color:var(--dim);display:flex;align-items:center;gap:7px}
.dbwrap .tile .k .dot{width:8px;height:8px;border-radius:50%}
.dbwrap .tile .v{font-size:27px;font-weight:750;font-variant-numeric:tabular-nums;margin-top:4px;letter-spacing:-.5px}
.dbwrap .tile .stripe{position:absolute;left:0;top:0;bottom:0;width:3px}
.dbwrap .tile.accent .v{color:var(--accent)}
.dbwrap .row2{grid-template-columns:1.35fr 1fr;align-items:stretch}
.dbwrap .card{background:var(--panel);border:1px solid var(--line);border-radius:var(--r);padding:16px}
.dbwrap .card h2{font-size:12.5px;letter-spacing:.06em;text-transform:uppercase;color:var(--dim);margin:0 0 14px;font-weight:650}
.dbwrap .card h2 .hint{float:right;text-transform:none;letter-spacing:0;color:var(--faint);font-weight:500}
.dbwrap .sevbar{display:flex;height:14px;border-radius:6px;overflow:hidden;margin-bottom:14px;box-shadow:inset 0 0 0 1px var(--line-soft)}
.dbwrap .sevbar i{display:block}
.dbwrap .legend{display:flex;flex-direction:column;gap:9px}
.dbwrap .lrow{display:grid;grid-template-columns:12px 1fr auto auto;align-items:center;gap:10px}
.dbwrap .lrow .sw{width:11px;height:11px;border-radius:3px}
.dbwrap .lrow .nm{color:var(--text)}
.dbwrap .lrow .ct{font-variant-numeric:tabular-nums;font-weight:650;font-family:var(--mono);color:var(--text)}
.dbwrap .lrow .bar{grid-column:2/5;height:5px;border-radius:3px;background:var(--line-soft);overflow:hidden;margin-top:-2px}
.dbwrap .lrow .bar i{display:block;height:100%}
.dbwrap .assure{display:flex;align-items:center;gap:18px}
.dbwrap .donut{width:104px;height:104px;border-radius:50%;flex:none;background:conic-gradient(var(--accent) calc(var(--p,0)*1%),var(--line) 0);display:grid;place-items:center;position:relative}
.dbwrap .donut::after{content:"";position:absolute;inset:12px;border-radius:50%;background:var(--panel)}
.dbwrap .donut .in{position:relative;text-align:center}
.dbwrap .donut .in b{font-size:22px;font-weight:750;font-variant-numeric:tabular-nums;color:var(--text)}
.dbwrap .donut .in span{display:block;font-size:10px;color:var(--dim);text-transform:uppercase;letter-spacing:.08em}
.dbwrap .akey{display:flex;flex-direction:column;gap:10px;font-size:12.5px;color:var(--text)}
.dbwrap .akey .r{display:flex;align-items:center;gap:9px}
.dbwrap .akey .r .d{width:10px;height:10px;border-radius:3px}
.dbwrap .akey .r b{margin-left:auto;font-family:var(--mono)}
.dbwrap .cvss{display:flex;align-items:flex-end;gap:8px;height:66px;margin-top:6px}
.dbwrap .cvss .b{flex:1;display:flex;flex-direction:column;align-items:center;gap:6px}
.dbwrap .cvss .b .cbar{width:100%;border-radius:4px 4px 2px 2px;min-height:4px}
.dbwrap .cvss .b .lb{font-size:10px;color:var(--faint);font-family:var(--mono)}
.dbwrap .tablewrap{overflow-x:auto;border:1px solid var(--line);border-radius:var(--r);background:var(--panel)}
.dbwrap table{border-collapse:collapse;width:100%;font-size:12.5px}
.dbwrap thead th{text-align:left;color:var(--faint);font-weight:600;font-size:10.5px;letter-spacing:.07em;text-transform:uppercase;padding:10px 12px;border-bottom:1px solid var(--line);white-space:nowrap;background:var(--panel2);position:static}
.dbwrap tbody td{padding:10px 12px;border-bottom:1px solid var(--line-soft);vertical-align:middle;white-space:normal}
.dbwrap tbody tr:last-child td{border-bottom:none}
.dbwrap tbody tr:hover{background:var(--raise)}
.dbwrap td.sevcell{padding-left:14px;position:relative;white-space:nowrap}
.dbwrap td.sevcell::before{content:"";position:absolute;left:0;top:4px;bottom:4px;width:3px;border-radius:3px;background:var(--s,transparent)}
.dbwrap .dpill{display:inline-flex;align-items:center;gap:6px;font-size:10.5px;font-weight:700;letter-spacing:.04em;padding:3px 8px;border-radius:20px;text-transform:uppercase}
.dbwrap .rid{font-family:var(--mono);font-size:12px;color:var(--text)}
.dbwrap .fttl{color:var(--dim)}
.dbwrap .conf{font-family:var(--mono);font-size:11px;padding:2px 7px;border-radius:5px;border:1px solid var(--line);white-space:nowrap;color:var(--dim)}
.dbwrap .conf.il{color:var(--good);border-color:var(--good)}
.dbwrap .conf.dyn{color:var(--accent);border-color:var(--accent)}
.dbwrap .conf.inf{color:var(--dim)}
.dbwrap .conf.fp{color:var(--faint);text-decoration:line-through}
.dbwrap .score{font-family:var(--mono);font-weight:700;font-variant-numeric:tabular-nums}
.dbwrap .dfile{font-family:var(--mono);font-size:11px;color:var(--faint)}
@media(max-width:980px){.dbwrap .stats{grid-template-columns:repeat(3,1fr)}.dbwrap .row2{grid-template-columns:1fr}}
</style></head><body>
<div class="app">

  <header class="top">
    <div class="brand">TC<b>PK</b> ::agentic<span class="v" id="ver">workbench</span></div>
    <div class="tbar">
      <div class="chip" id="targetChip" style="display:none"><span class="dot ok"></span><span id="targetChipTxt"></span></div>
      <div class="chip" id="agentChip"><span class="dot" id="agentDot"></span>agent: <b id="agentChipTxt">ollama</b></div>
      <div class="chip"><span class="dot ok"></span>127.0.0.1</div>
      <div class="scope">DISCOVERY ONLY</div>
      <a id="stop" title="stop the local server">stop</a>
    </div>
  </header>

  <div class="mid">
    <nav class="rail">
      <div class="railsep first" style="text-transform:none;color:var(--text);font-weight:700;font-size:12px;padding-top:8px;margin-top:4px">OVERVIEW</div>
      <div class="step active" data-p="0"><div class="num" style="border:none;font-size:15px">::</div><div><div class="t">Dashboard</div><div class="s">security posture</div></div></div>
      <div class="railsep" style="text-transform:none;color:var(--text);font-weight:700;font-size:12px;padding-top:8px;margin-top:10px">SCAN<div style="font-weight:400;font-size:10px;color:var(--dim);margin-top:2px;line-height:1.3">Guided. You drive each step; optionally AI-verify the leads.</div></div>
      <div class="step" data-p="1"><div class="num">1</div><div><div class="t">Connect</div><div class="s">session + agent</div></div></div>
      <div class="step" data-p="2"><div class="num">2</div><div><div class="t">Target</div><div class="s">pick the app</div></div></div>
      <div class="step" data-p="3"><div class="num">3</div><div><div class="t">Audit</div><div class="s">discovery scan</div></div></div>
      <div class="step" data-p="4"><div class="num">4</div><div><div class="t">Decompile</div><div class="s">code to source</div></div></div>
      <div class="step" data-p="5"><div class="num">5</div><div><div class="t">AI review</div><div class="s">line-by-line</div></div></div>
      <div class="step" data-p="6"><div class="num">6</div><div><div class="t">Report</div><div class="s">export</div></div></div>
      <div class="railsep" style="text-transform:none;color:var(--text);font-weight:700;font-size:12px;padding-top:8px;margin-top:10px">AGENT <span style="font-weight:600;font-size:9px;color:#fff;background:#2ea043;border-radius:8px;padding:1px 6px">AUTONOMOUS</span><div style="font-weight:400;font-size:10px;color:var(--dim);margin-top:2px;line-height:1.3">Give a goal; the model investigates on its own. The IL prover confirms each finding.</div></div>
      <div class="step" data-p="7"><div class="num">7</div><div><div class="t">Agent</div><div class="s">full auto</div></div></div>
      <div class="railsep" style="text-transform:none;color:var(--text);font-weight:700;font-size:12px;padding-top:8px;margin-top:10px">INTERCEPT<div style="font-weight:400;font-size:10px;color:var(--dim);margin-top:2px;line-height:1.3">Review a proxy or hook capture you made with the CLI.</div></div>
      <div class="step" data-p="8"><div class="num">8</div><div><div class="t">Intercept</div><div class="s">review capture</div></div></div>
      <div class="railsep" style="text-transform:none;color:var(--text);font-weight:700;font-size:12px;padding-top:8px;margin-top:10px">RUNTIME<div style="font-weight:400;font-size:10px;color:var(--dim);margin-top:2px;line-height:1.3">Read-only live checks on a running process.</div></div>
      <div class="step" data-p="9"><div class="num">9</div><div><div class="t">Runtime</div><div class="s">live process</div></div></div>
      <div class="step" data-p="12"><div class="num">12</div><div><div class="t">Process</div><div class="s">live watch</div></div></div>
      <div class="railsep" style="text-transform:none;color:var(--text);font-weight:700;font-size:12px;padding-top:8px;margin-top:10px">FILES<div style="font-weight:400;font-size:10px;color:var(--dim);margin-top:2px;line-height:1.3">Unpack an Electron app.asar, or hex-view any file.</div></div>
      <div class="step" data-p="10"><div class="num">10</div><div><div class="t">Asar</div><div class="s">unpack + browse</div></div></div>
      <div class="step" data-p="11"><div class="num">11</div><div><div class="t">Hex</div><div class="s">byte view</div></div></div>
    </nav>

    <main class="stage">

      <div class="pane on" data-p="0"><div class="dbwrap">
        <div class="pagehead"><h1>Audit summary</h1><div class="sub" id="dashSub">Run an audit (step 3) to populate the security posture overview.</div></div>
        <div class="grid stats" id="kpis"></div>
        <div class="grid row2" style="margin-top:14px">
          <div class="card"><h2>Findings by severity <span class="hint" id="sevTotal"></span></h2><div class="sevbar" id="sevbarStack"></div><div class="legend" id="sevLegend"></div></div>
          <div class="card"><h2>Assurance <span class="hint">proven vs leads</span></h2><div class="assure"><div class="donut" id="donut" style="--p:0"><div class="in"><b id="donutPct">0%</b><span>proven</span></div></div><div class="akey" id="akey"></div></div><h2 style="margin:18px 0 8px">CVSS band</h2><div class="cvss" id="cvssBand"></div></div>
        </div>
        <div style="margin-top:18px"><div class="card" style="padding:0"><div style="padding:16px 16px 12px"><h2 style="margin:0">Top findings <span class="hint">act on proven first</span></h2></div><div class="tablewrap" style="border:none"><table><thead><tr><th>Sev</th><th>Rule</th><th>Finding</th><th>Confidence</th><th>CVSS</th><th>Location</th></tr></thead><tbody id="dashTop"><tr><td colspan="6" class="fttl" style="padding:16px">no findings yet -- run an audit (step 3).</td></tr></tbody></table></div></div></div>
      </div></div>

      <div class="pane" data-p="1">
        <h2>Connect</h2>
        <p class="lead">Local agentic workbench. Choose the AI agent that verifies findings and reviews decompiled code. Nothing leaves the box unless you pick a cloud agent and allow egress.</p>
        <div class="panel">
          <div class="note" id="conn">checking session...</div>
          <div class="note">Scope: <b>discovery only</b> -- the exploit bucket (K01-K06) is not reachable from this UI.</div>
          <div class="note">Bind: <b>127.0.0.1</b> -- not on the network. Auth: per-session token in the URL.</div>
        </div>
        <div class="panel">
          <h3>AI AGENT</h3>
          <div class="row">
            <div><label>provider (which agent)</label><select id="provider" onchange="onProvider()"><option value="ollama">ollama (local)</option><option value="claude">claude</option><option value="openai">openai</option><option value="gemini">gemini</option><option value="grok">grok</option><option value="deepseek">deepseek</option><option value="custom">custom endpoint</option></select></div>
            <div><label>model</label><input id="model" placeholder="qwen2.5-coder:7b" oninput="refreshAgentChip()"/></div>
          </div>
          <div class="row">
            <div><label>API key (cloud providers)</label><input type="password" id="apiKey" placeholder="leave blank for local ollama"/></div>
            <div><label>custom base URL</label><input id="baseUrl" placeholder="http://127.0.0.1:1234/v1"/></div>
            <div style="flex:0 0 auto;display:flex;gap:12px;align-items:flex-end"><label class="chk"><input type="checkbox" id="allowCloud"/> allow cloud egress</label><button class="mini" onclick="testAgent()">Test agent</button></div>
          </div>
          <div class="note" id="agentStatus">ollama (local) by default -- pick a cloud agent + key if you prefer.</div>
        </div>
        <button class="go" onclick="go(2)">Continue to Target</button>
      </div>

      <div class="pane" data-p="2">
        <h2>Target</h2>
        <p class="lead">Point at an install dir, EXE/DLL, or an MSIX/MSI/ZIP (auto-unwrapped). Or search installed apps.</p>
        <div class="panel">
          <div class="row">
            <div style="flex:3"><label>Target path</label><input id="target" placeholder="C:\Program Files\Acme\Desktop" oninput="onTargetInput()"/></div>
            <div style="flex:0 0 auto"><button class="mini" onclick="detect()">Auto-Detect</button></div>
          </div>
          <div class="row">
            <div style="flex:3"><label>...or search installed apps</label><input id="q" placeholder="type a name, e.g. acme" onkeydown="if(event.key==='Enter')search()"/></div>
            <div style="flex:0 0 auto"><button class="mini" onclick="search()">Search</button> <button class="mini" onclick="listAll()">List all</button></div>
          </div>
          <div id="apps"></div>
          <div class="note" id="ident"></div>
        </div>
        <button class="go" id="toAudit" onclick="onTargetSet(val('target'));go(3)" disabled>Continue to Audit</button>
      </div>

      <div class="pane" data-p="3">
        <h2>Audit</h2>
        <p class="lead">Run the discovery scan. Findings stream into the triage table with the evidence ladder (Inferred / Confirmed / Confirmed (IL)).</p>
        <div class="panel">
          <div class="row">
            <div style="max-width:260px"><label>Profile (depth)</label><select id="profile"><option value="Full">Full</option><option value="Standard">Standard</option><option value="Quick">Quick -- skip slow OS scans</option></select></div>
          </div>
          <div class="chkrow">
            <label class="chk"><input type="checkbox" id="deepRuntime"/> deep runtime</label>
            <label class="chk" title="Live CVE: OSV (NuGet/Electron) + NVD/CPE (native libs). Uncheck = offline catalog only."><input type="checkbox" id="onlineCve" checked/> online CVE (OSV + NVD)</label>
            <label class="chk"><input type="checkbox" id="enableLlm"/> AI-verify findings with the selected agent</label>
          </div>
          <div class="note" id="agentNote">agent: ollama (local) -- <a onclick="go(1)">configure</a></div>
          <div class="ctl">
            <button class="go" id="run" onclick="run()">Run audit</button>
            <button class="warn mini" id="pause" onclick="ctl('pause')" disabled>Pause</button>
            <button class="mini" id="resume" onclick="ctl('resume')" disabled>Resume</button>
            <button class="stop mini" id="cancel" onclick="ctl('cancel')" disabled>Cancel</button>
          </div>
          <div class="bar"><i id="prog"></i></div>
        </div>

        <div class="panel">
          <div class="dash">
            <div class="counts">
              <div class="cstat s-crit"><b id="c-crit">0</b><small>critical</small></div>
              <div class="cstat s-high"><b id="c-high">0</b><small>high</small></div>
              <div class="cstat s-med"><b id="c-med">0</b><small>medium</small></div>
              <div class="cstat s-low"><b id="c-low">0</b><small>low</small></div>
              <div class="cstat s-info"><b id="c-info">0</b><small>info</small></div>
            </div>
          </div>
          <div class="chips" id="fchips">
            <span class="fchip crit" data-k="crit" onclick="toggleFilter('crit')">critical</span>
            <span class="fchip high" data-k="high" onclick="toggleFilter('high')">high</span>
            <span class="fchip med" data-k="med" onclick="toggleFilter('med')">medium</span>
            <span class="fchip low" data-k="low" onclick="toggleFilter('low')">low</span>
            <span class="fchip info" data-k="info" onclick="toggleFilter('info')">info</span>
          </div>
          <div class="tbl-wrap">
            <table><thead><tr><th>sev</th><th>confidence</th><th>rule</th><th>finding</th></tr></thead><tbody id="triageBody"><tr><td colspan="4" class="note" style="padding:14px">no findings yet -- run an audit.</td></tr></tbody></table>
          </div>
        </div>
      </div>

      <div class="pane" data-p="4">
        <h2>Decompile</h2>
        <p class="lead">Scans the whole target folder and lists every module. Pick one: <b>.NET</b> modules decompile via Mono.Cecil with sink-bearing methods flagged (the same sinks the IL verifier proves); <b>native</b> (C/C++/Electron) modules can't be decompiled to source, so they show a PE view instead -- exploit-mitigation flags (ASLR/DEP/CFG), Authenticode signing, and high-risk imported APIs.</p>
        <div class="row"><div style="flex:0 0 auto"><button class="mini" onclick="loadModules()">Load modules from target</button></div><div style="flex:0 0 auto"><label class="chk" style="font:11px var(--mono)"><input type="checkbox" id="dcSelAll" onclick="toggleSelAll()"> select all</label></div><div style="flex:0 0 auto"><button class="go mini" id="dcAuditBtn" onclick="auditSelected()" disabled>Audit selected (0)</button></div><div class="note" id="dcStatus" style="flex:1"></div></div>
        <p class="note" style="margin-top:0">Tick the DLL(s) you care about and <b>Audit selected</b> runs a focused TCPK audit on just those binaries (signature, PE hardening, strings, secrets, .NET sink/IL proof) -- separate from decompiling or auditing the whole app.</p>
        <div class="cv">
          <div class="col">
            <h4>MODULES</h4><div id="dcModules"><div class="note">click "Load modules from target"</div></div>
            <h4 style="margin-top:14px">METHODS (sink-bearing)</h4><div id="dcMethods"><div class="note">pick a module</div></div>
          </div>
          <div class="col"><h4 id="dcMethodTitle">DECOMPILED IL</h4><div class="code" id="dcCode"><span class="note">pick a method to see its IL body -- sink calls are highlighted</span></div></div>
          <div class="col"><h4>SINKS IN METHOD</h4><div id="dcSinks"><div class="note">-</div></div>
            <div style="margin-top:14px"><button class="mini" id="dcToReview" onclick="sendToReview()" disabled>Send to AI review -&gt;</button></div>
          </div>
        </div>
        <div id="dcAudit" style="display:none;margin-top:16px"><h4>AUDIT RESULTS (selected modules)</h4><div class="panel" id="dcAuditBody"><div class="note">-</div></div></div>
      </div>

      <div class="pane" data-p="5">
        <h2>AI line-by-line review</h2>
        <p class="lead">The selected agent reads the method's decompiled IL and judges exploitability; the IL prover's reachability is shown alongside, so you get proven facts next to the model's opinion (advisory only -- it never overrides the evidence).</p>
        <div class="row"><div class="note" id="arMethod" style="flex:1">no method selected -- open step 4 (Decompile), pick a method, then click "Send to AI review"</div><div style="flex:0 0 auto"><button class="go mini" id="arRun" onclick="runReview()" disabled>Run AI review</button></div></div>
        <div class="cv" style="grid-template-columns:1fr 1fr">
          <div class="col"><h4>DECOMPILED IL</h4><div class="code" id="arCode"><span class="note">-</span></div></div>
          <div class="col"><h4>AGENT VERDICT + IL CROSS-CHECK</h4><div id="arVerdict"><div class="note">run the review to see the agent's assessment, cross-checked by IL reachability</div></div></div>
        </div>
      </div>

      <div class="pane" data-p="6">
        <h2>Report</h2>
        <p class="lead">Download the generated reports for this run.</p>
        <div class="panel" id="reports"><div class="note">Run an audit first (step 3); the reports appear here when it finishes.</div></div>
      </div>

      <div class="pane" data-p="7">
        <h2>Autonomous agent <span style="font:600 11px sans-serif;color:#fff;background:#2ea043;border-radius:8px;padding:2px 8px;vertical-align:middle">AUTONOMOUS</span></h2>
        <p class="lead"><b>This is the autonomous mode.</b> You give a goal in plain English; a local model then investigates on its own -- it reads the code, picks which methods to inspect, walks the call graph, and submits what it believes are bugs. It does NOT get the final say: the deterministic IL prover re-checks every submission and marks it <b>CONFIRMED</b> (proven path to the sink), <b>NEEDS REVIEW</b>, or <b>REFUTED</b>. The agent proposes, the prover disposes. Read-only tools only; the exploit bucket is never exposed.</p>
        <div class="panel">
          <div class="row">
            <div style="flex:3"><label>Goal</label><input id="autoGoal" value="Find the most serious vulnerabilities in this .NET target."/></div>
            <div style="flex:0 0 auto"><button class="go" id="autoRun" onclick="runAuto()">Run autonomous agent</button></div>
          </div>
          <div class="note" id="autoStatus"><b>Local ollama only.</b> If you picked a cloud agent in step 1, switch the provider back to ollama. Use a capable code model (qwen2.5-coder:7b or better) for reliable multi-step behaviour.</div>
        </div>
        <div class="cv" style="grid-template-columns:1.4fr 1fr">
          <div class="col"><h4>AGENT TRANSCRIPT (reason -&gt; act -&gt; observe)</h4><div id="autoTranscript"><div class="note">click "Run autonomous agent" -- you'll see every step the agent decides, live</div></div></div>
          <div class="col"><h4>FINDINGS (verdict by the IL prover)</h4><div id="autoFindings"><div class="note">-</div></div></div>
        </div>
      </div>

      <div class="pane" data-p="8">
        <h2>Interception</h2>
        <p class="lead">Review a captured traffic session as findings. Capture with the CLI (Invoke-TcpkIntercept, gated) using mitmproxy (proxy mode) or Frida (hook mode), then load the capture file here. Discovery-only: this pane parses a local capture, it never launches or injects.</p>
        <div class="panel">
          <div class="row">
            <div style="flex:1"><label>capture file (mitmproxy flows.jsonl or Frida hook.log)</label><input id="icFile" placeholder="C:\path\tcpk-flows.jsonl"/></div>
            <div><label>kind</label><select id="icKind"><option value="proxy">proxy (mitmproxy)</option><option value="hook">hook (Frida)</option></select></div>
            <div style="flex:0 0 auto;display:flex;align-items:flex-end"><button class="go mini" onclick="loadCapture()">Load capture</button></div>
          </div>
          <div class="note" id="icStatus">point at a capture written by Invoke-TcpkIntercept.</div>
        </div>
        <div id="icFindings"></div>
      </div>

      <div class="pane" data-p="9">
        <h2>Runtime / Live</h2>
        <p class="lead">Read-only live checks on a RUNNING process. Type the process name (or reuse your target), then click a check. Discovery-only -- reads live state (modules, ports, token, handles, IPC); it never launches, injects, or dumps. Some checks need admin.</p>
        <div class="panel">
          <div class="row"><div style="flex:1"><label>process name (for the process checks)</label><input id="rtProc" placeholder="e.g. notepad"/></div></div>
          <div class="note" style="margin-top:6px">process:</div>
          <div style="display:flex;flex-wrap:wrap;gap:6px;margin-top:4px">
            <button class="go mini" onclick="rtRun('loaded-modules')">Loaded Modules</button>
            <button class="go mini" onclick="rtRun('module-sigs')">Module Signatures</button>
            <button class="go mini" onclick="rtRun('listening-ports')">Listening Ports</button>
            <button class="go mini" onclick="rtRun('process-token')">Process Token</button>
            <button class="go mini" onclick="rtRun('mitigations')">Mitigations</button>
            <button class="go mini" onclick="rtRun('process-dacl')">Process DACL</button>
            <button class="go mini" onclick="rtRun('env-secrets')">Env Secrets</button>
            <button class="go mini" onclick="rtRun('child-procs')">Child Procs</button>
            <button class="go mini" onclick="rtRun('handles')">Handles</button>
            <button class="go mini" onclick="rtRun('windows')">Windows</button>
            <button class="go mini" onclick="rtRun('gui-inspector')">GUI Inspector</button>
          </div>
          <div class="note" style="margin-top:8px">system-wide:</div>
          <div style="display:flex;flex-wrap:wrap;gap:6px;margin-top:4px">
            <button class="go mini" onclick="rtRun('named-pipes')">Named Pipes</button>
            <button class="go mini" onclick="rtRun('pipe-dacls')">Pipe DACLs</button>
            <button class="go mini" onclick="rtRun('alpc')">ALPC / Mailslots</button>
          </div>
          <div class="note" style="margin-top:8px">target path (uses the target from step 2):</div>
          <div style="display:flex;flex-wrap:wrap;gap:6px;margin-top:4px">
            <button class="go mini" onclick="rtRun('com-objects')">COM Objects</button>
            <button class="go mini" onclick="rtRun('named-objects')">Named Objects</button>
            <button class="go mini" onclick="rtRun('rpc-surface')">RPC Surface</button>
          </div>
          <div class="note" id="rtStatus" style="margin-top:8px">pick a check.</div>
        </div>
        <div id="rtFindings"></div>
      </div>

      <div class="pane" data-p="12">
        <h2>Process (live watch)</h2>
        <p class="lead">Continuously re-reads ONE running process -- identity, memory, loaded modules, TCP connections, child processes -- refreshing on an interval. Read-only: it observes live state, never launches / injects / dumps.</p>
        <div class="panel">
          <div class="row" style="gap:8px;align-items:flex-end;flex-wrap:wrap">
            <div style="flex:1;min-width:180px"><label>process (name or PID)</label><input id="pmProc" placeholder="e.g. notepad or 1234"/></div>
            <button class="go mini" onclick="pmRefresh()">Refresh list</button>
            <select id="pmList" onchange="if(this.value)$('pmProc').value=this.value"><option value="">-- running --</option></select>
            <div><label>every (s)</label><input id="pmInt" style="width:56px" value="2"/></div>
            <button class="go mini" id="pmStartBtn" onclick="pmStart()">Start</button>
            <button class="go mini" id="pmStopBtn" onclick="pmStop()" disabled>Stop</button>
          </div>
          <div class="row" style="margin-top:6px"><div style="flex:1"><input id="pmFilter" placeholder="module filter -- e.g. system32, .net, appname" oninput="pmRender()"/></div></div>
          <div class="note" id="pmStatus" style="margin-top:6px">pick a process, then Start.</div>
        </div>
        <div class="panel" style="margin-top:8px;max-height:62vh;overflow:auto"><div id="pmView" style="font:12px var(--mono);white-space:pre-wrap;word-break:break-word"><span class="note">not running</span></div></div>
      </div>

      <div class="pane" data-p="10">
        <h2>Asar (unpack + browse)</h2>
        <p class="lead">Electron apps ship their real code as JavaScript inside resources\app.asar. Unpack it here to browse and read the source (the native DLLs have no source -- this is the code that matters). Uses the target from step 2. Discovery-only: files are read, never executed.</p>
        <div class="panel">
          <div class="row">
            <div style="flex:0 0 auto;display:flex;align-items:flex-end"><button class="go mini" onclick="asarExtract()">Extract app.asar</button></div>
            <div style="flex:1;display:flex;align-items:flex-end"><div class="note" id="asStatus">pick a target in step 2, then Extract. A large app can take ~30s.</div></div>
            <div style="flex:0 0 auto;display:flex;align-items:flex-end"><button class="go mini" id="asAuditBtn" onclick="asarToAudit()" disabled>Analyze folder in Audit</button></div>
          </div>
          <div class="row" style="margin-top:6px"><div style="flex:1"><input id="asFilter" placeholder="filter files -- e.g. .js, index, config, token" oninput="asarRender()"/></div></div>
        </div>
        <div class="row" style="align-items:stretch;gap:10px">
          <div class="panel" style="flex:0 0 360px;max-height:58vh;overflow:auto"><h3>FILES</h3><div id="asFiles"><div class="note">not extracted yet</div></div></div>
          <div class="panel" style="flex:1;min-width:0"><h3 id="asViewTitle">SOURCE</h3><pre id="asView" style="max-height:54vh;overflow:auto;white-space:pre-wrap;word-break:break-word;font:12px var(--mono)"><span class="note">click a file to view its source</span></pre></div>
        </div>
      </div>

      <div class="pane" data-p="11">
        <h2>Hex (byte view)</h2>
        <p class="lead">Raw hex + ASCII of any in-scope file -- a native DLL, or a file from an unpacked asar. Go to an offset, find a hex / ASCII pattern, and inspect the bytes at an offset as typed values. Read-only.</p>
        <div class="panel">
          <div class="row"><div style="flex:1"><label>file path</label><input id="hxPath" placeholder="C:\path\to\file.dll"/></div>
            <div style="flex:0 0 auto;display:flex;align-items:flex-end"><button class="go mini" onclick="hexLoad(0)">Load</button></div></div>
          <div class="row" style="margin-top:6px;gap:8px;align-items:flex-end;flex-wrap:wrap">
            <button class="go mini" onclick="hexPage(-1)">&lt; prev</button>
            <button class="go mini" onclick="hexPage(1)">next &gt;</button>
            <div><label>go to offset (hex)</label><input id="hxGoto" style="width:110px" placeholder="1a4"/></div>
            <button class="go mini" onclick="hexGoto()">Go</button>
            <div><label>find</label><input id="hxFind" style="width:150px" placeholder="pattern"/></div>
            <select id="hxKind"><option value="ascii">ascii</option><option value="hex">hex</option></select>
            <button class="go mini" onclick="hexFind()">Find next</button>
          </div>
          <div class="row" style="margin-top:6px;gap:8px;align-items:flex-end;flex-wrap:wrap">
            <div><label>strings: min len</label><input id="hxSMin" style="width:56px" value="4"/></div>
            <div><label>filter by name / substring</label><input id="hxSFilter" style="width:200px" placeholder="e.g. http, .dll, Password"/></div>
            <select id="hxSKind"><option value="both">ascii+wide</option><option value="ascii">ascii</option><option value="wide">wide (UTF-16)</option></select>
            <button class="go mini" onclick="hexStrings()">List strings</button>
            <span class="note" id="hxSInfo"></span>
          </div>
          <div class="note" id="hxStatus" style="margin-top:6px">enter a path and Load.</div>
        </div>
        <div class="panel" id="hxSPanel" style="display:none">
          <div class="note" style="margin-bottom:4px">click a row to jump to its offset in the hex view (a = ascii, w = wide / UTF-16)</div>
          <div id="hxSList" style="max-height:26vh;overflow:auto;font:12px var(--mono)"></div>
        </div>
        <div class="row" style="align-items:stretch;gap:10px">
          <div class="panel" style="flex:1;min-width:0"><pre id="hxView" style="max-height:58vh;overflow:auto;font:12px var(--mono);line-height:1.35"><span class="note">-</span></pre></div>
          <div class="panel" style="flex:0 0 300px">
            <h3>DATA INSPECTOR</h3>
            <div class="note" style="margin:-4px 0 6px">bytes at offset <span id="hxInsOff" style="color:var(--accent)">0x0</span> -- click a hex row, or set below</div>
            <div class="row" style="align-items:flex-end;gap:6px"><div><label>offset (hex)</label><input id="hxInsIn" style="width:110px" placeholder="0"/></div><button class="go mini" onclick="hexInspect()">Inspect</button></div>
            <table style="width:100%;font:11px var(--mono);margin-top:8px;border-collapse:collapse" id="hxInsTab"><tbody><tr><td class="note">load a file, then inspect an offset</td></tr></tbody></table>
          </div>
        </div>
      </div>

    </main>
  </div>

  <section class="dock" id="dock">
    <div class="dh" onclick="toggleDock()"><b>AGENT CONSOLE</b><span class="meta" id="dockMeta">idle</span></div>
    <div class="console" id="console">workbench ready. select a target and run an audit to see live backend activity here.
</div>
  </section>

</div>
<script>
var P=new URLSearchParams(location.search),T=P.get('t')||'';
var JOB=null,timer=null,counts={crit:0,high:0,med:0,low:0,info:0},result=null,FINDINGS=[],FILTER={};
function $(id){return document.getElementById(id);}
function esc(s){s=(s==null?'':''+s);return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
function val(id){return $(id).value;}
function getAgent(){return {provider:val('provider'),model:val('model'),apiKey:val('apiKey'),baseUrl:val('baseUrl'),allowCloud:$('allowCloud').checked};}
function onProvider(){refreshAgentChip();$('agentDot').className='dot';}
function refreshAgentChip(){var a=getAgent();$('agentChipTxt').textContent=a.provider+(a.model?(' / '+a.model):'');var n=$('agentNote');if(n)n.innerHTML='agent: '+esc(a.provider)+(a.model?(' / '+esc(a.model)):'')+(a.provider==='ollama'?' (local)':' (cloud)')+' -- <a onclick="go(1)">configure</a>';}
async function api(path,opts){opts=opts||{};opts.headers=Object.assign({'X-TCPK-Token':T},opts.headers||{});
  if(opts.json!==undefined){opts.body=JSON.stringify(opts.json);opts.headers['Content-Type']='application/json';opts.method=opts.method||'POST';delete opts.json;}
  var r=await fetch(path,opts);var ct=r.headers.get('content-type')||'';return (ct.indexOf('json')>=0)?r.json():r.text();}
async function testAgent(){var st=$('agentStatus');st.textContent='testing...';st.style.color='';var a=getAgent();
  try{var r=await api('/api/testai',{json:{provider:a.provider,model:a.model,apiKey:a.apiKey,baseUrl:a.baseUrl}});
    if(r.reachable){st.textContent='reachable -- '+a.provider+(r.cloud?' (cloud)':' (local)');st.style.color='var(--il)';$('agentDot').className='dot ok';}
    else{st.textContent='NOT reachable'+(r.error?(' -- '+r.error):'');st.style.color='var(--crit)';$('agentDot').className='dot bad';}
    if(a.provider==='ollama'){try{var lm=await api('/api/agent/llm-models');var base=st.textContent;if(lm.models&&lm.models.length){st.innerHTML=esc(base)+' &nbsp;|&nbsp; models: '+esc(lm.models.slice(0,6).join(', '));}else if(lm.hint){st.innerHTML=esc(base)+' <span style="color:var(--med)">&nbsp;|&nbsp; '+esc(lm.hint)+'</span>';}}catch(e){}}}
  catch(e){st.textContent='test failed';st.style.color='var(--crit)';$('agentDot').className='dot bad';}refreshAgentChip();}
function go(n){document.querySelectorAll('.pane').forEach(function(p){p.classList.toggle('on',+p.dataset.p===n);});
  document.querySelectorAll('.step').forEach(function(s){s.classList.toggle('active',+s.dataset.p===n);});
  if(n===4 && (window._target||val('target').trim()) && !window._dcLoaded){window._dcLoaded=true;setTimeout(loadModules,120);}
  if(n===5 && window._dcMethod){prepReview();}
  if(n===0){renderDash();}}
function mark(n){document.querySelectorAll('.step').forEach(function(s){if(+s.dataset.p<=n)s.classList.add('done');});}
document.querySelectorAll('.step').forEach(function(s){s.addEventListener('click',function(){go(+s.dataset.p);});});
$('stop').addEventListener('click',async function(){try{await api('/api/shutdown',{method:'POST'});}catch(e){}document.body.innerHTML='<p style="padding:30px;font-family:monospace">server stopped -- you can close this tab.</p>';});
(async function(){try{var p=await api('/api/ping');$('conn').innerHTML='session authenticated -- engine v'+esc(p.version||'?')+' ready.';$('ver').textContent='v'+(p.version||'?');}catch(e){$('conn').textContent='cannot reach the local engine.';}})();
refreshAgentChip();
(function(){var qt=P.get('target');if(qt){$('target').value=qt;$('toAudit').disabled=false;onTargetSet(qt);detect();var mp=P.get('method');if(mp){window._dcDll=qt;window._dcMethod=mp;}var ph=P.get('phase');if(ph){go(+ph);}else{go(3);if(P.get('autorun')==='1'){setTimeout(run,1200);}}if(mp&&ph==='5'){setTimeout(function(){prepReview();runReview();},700);}if(ph==='7'&&P.get('auto')==='1'){setTimeout(runAuto,600);}}})();
renderDash();
function onTargetInput(){var t=val('target').trim();$('toAudit').disabled=!t;window._target=t;window._dcLoaded=false;}
function onTargetSet(t){window._target=t;$('targetChip').style.display='flex';$('targetChipTxt').textContent=t;}
function pick(path){$('target').value=path;$('toAudit').disabled=false;onTargetSet(path);detect();}
async function detect(){var t=val('target').trim();if(!t)return;$('ident').textContent='identifying...';onTargetSet(t);
  try{var r=await api('/api/identify',{json:{path:t}});
    if(r.appSummary){$('ident').innerHTML='<b style="color:var(--accent)">'+esc(r.appName||r.packageName||'app')+'</b>'+(r.appVersion?' v'+esc(r.appVersion):'')+' &middot; '+esc(r.appType||'')+' &middot; '+esc(r.runtime||'')+' '+esc(r.arch||'')+(r.managed?' (managed .NET)':' (native)')+(r.ui?' &middot; UI: '+esc(r.ui):'')+'<br>signing: '+esc(r.signature||'?')+(r.publisher?' &middot; '+esc(r.publisher):'');}
    else{$('ident').textContent=r.note||'';}
    $('toAudit').disabled=false;window._ident=r;}catch(e){$('ident').textContent='identify failed';}}
function appRow(a){var d=document.createElement('div');d.className='app-row';d.innerHTML='<span>'+esc(a.name||a.path)+'</span><span class="p">'+esc(a.path||'')+'</span>';d.onclick=function(){pick(a.path);};return d;}
function render(apps){var box=$('apps');box.innerHTML='';if(!apps||!apps.length){box.innerHTML='<div class="note">no matches</div>';return;}apps.slice(0,60).forEach(function(a){box.appendChild(appRow(a));});}
async function search(){var q=val('q').trim();var box=$('apps');box.innerHTML='<div class="note">searching...</div>';try{var r=await api('/api/discover?q='+encodeURIComponent(q));render(r.apps);}catch(e){box.innerHTML='<div class="note">search failed</div>';}}
async function listAll(){var box=$('apps');box.innerHTML='<div class="note">loading...</div>';try{var r=await api('/api/apps');render(r.apps);}catch(e){box.innerHTML='<div class="note">load failed</div>';}}
function setRun(on){$('run').disabled=on;$('pause').disabled=!on;$('cancel').disabled=!on;$('resume').disabled=true;$('dockMeta').textContent=on?'running...':'idle';}
async function run(){var t=val('target').trim();if(!t){go(2);$('ident').textContent='pick a target first';return;}
  counts={crit:0,high:0,med:0,low:0,info:0};FINDINGS=[];window._seenFind={};renderTriage();paint();$('prog').style.width='0%';
  var body={target:t,profile:val('profile'),deepRuntime:$('deepRuntime').checked,onlineCve:$('onlineCve').checked};
  if(window._ident){body.packageName=window._ident.packageName;body.packageFamilyName=window._ident.packageFamilyName;body.processName=window._ident.processName;}
  if($('enableLlm').checked){var ag=getAgent();body.enableLlm=true;body.provider=ag.provider;body.model=ag.model;body.apiKey=ag.apiKey;body.baseUrl=ag.baseUrl;body.allowCloudLlm=ag.allowCloud;}
  setRun(true);openDock();log('[step] starting audit on '+t,'c-step');
  try{var r=await api('/api/run',{json:body});if(r.error){log('[error] '+r.error,'c-warn');setRun(false);return;}JOB=r.jobId;poll();}catch(e){log('[error] run failed','c-warn');setRun(false);}}
async function ctl(a){if(!JOB)return;try{await api('/api/'+a+'?job='+JOB,{method:'POST'});
  if(a==='pause'){$('resume').disabled=false;$('pause').disabled=true;log('[step] paused','c-step');}
  if(a==='resume'){$('resume').disabled=true;$('pause').disabled=false;log('[step] resumed','c-step');}
  if(a==='cancel'){stopPoll();setRun(false);log('[step] cancelled','c-step');}}catch(e){}}
function poll(){timer=setInterval(tick,1000);}
function stopPoll(){if(timer){clearInterval(timer);timer=null;}}
async function tick(){if(!JOB)return;var s;try{s=await api('/api/status?job='+JOB);}catch(e){return;}
  (s.log||[]).forEach(function(l){log(l,'');});
  (s.findings||[]).forEach(function(f){if(!window._seenFind)window._seenFind={};var key=(f.sev||'')+'|'+(f.conf||'')+'|'+(f.rule||'');if(window._seenFind[key])return;window._seenFind[key]=1;var k=sevKey(f.sev);if(counts[k]!==undefined)counts[k]++;FINDINGS.push(f);log('[find] '+f.sev+' '+f.rule+' -- '+f.title,'c-find');});
  if(s.findings&&s.findings.length){renderTriage();renderDash();}
  paint();
  if(s.checksDone!==undefined)$('dockMeta').textContent=(s.paused?'paused ':'running ')+s.checksDone+'/'+(s.total||'?')+' checks';
  if(s.total)$('prog').style.width=Math.min(100,Math.round(100*(s.checksDone||0)/s.total))+'%';
  if(s.done){stopPoll();setRun(false);$('prog').style.width='100%';$('dockMeta').textContent='done';log('[step] audit complete','c-step');mark(3);if(s.result){result=s.result;showReports();populateFromResult();go(0);}}}
// The live FND stream can be empty (the audit writes findings to its reports without emitting
// them on the pipeline), so on completion we (re)build the triage table + counters from the
// authoritative result model -- same {sev,conf,rule,title} shape the stream would have used.
function populateFromResult(){var mf=(result&&result.model&&result.model.findings)?result.model.findings:[];if(!mf.length)return;
  counts={crit:0,high:0,med:0,low:0,info:0};FINDINGS=[];
  mf.forEach(function(f){var k=sevKey(f.sev);if(counts[k]!==undefined)counts[k]++;FINDINGS.push({sev:f.sev,conf:f.conf,rule:f.rule,title:f.title,file:f.file,cvss:f.cvss});});
  renderTriage();paint();renderDash();log('[step] '+mf.length+' findings loaded into triage','c-step');}
function paint(){for(var k in counts)$('c-'+k).textContent=counts[k];}
function sevKey(s){s=(s||'INFO').toUpperCase();var m={CRITICAL:'crit',HIGH:'high',MEDIUM:'med',LOW:'low',INFO:'info'};return m[s]||'info';}
async function rtRun(check){var box=$('rtFindings'),st=$('rtStatus');
  var proc=(val('rtProc')||'').trim();
  st.textContent='running '+check+'...';box.innerHTML='';
  try{var r=await api('/api/agent/runtime',{json:{check:check,process:proc,path:(window._target||val('target')||'')}});
    if(r.error){st.textContent='error: '+r.error;box.innerHTML='<div class="note">'+esc(r.error)+'</div>';return;}
    var fs=r.findings||[];
    st.textContent=check+': '+fs.length+' finding'+(fs.length===1?'':'s');
    if(!fs.length){box.innerHTML='<div class="note">no findings</div>';return;}
    box.innerHTML=fs.map(function(f){var kc=sevKey(f.sev);
      return '<div class="vcard" style="border-left-color:var(--'+kc+')"><div class="h"><span class="pill" style="background:var(--'+kc+');color:#08130a">'+esc(f.sev)+'</span> '+esc(f.rule)+' <span style="color:var(--dim)">('+esc(f.conf)+')</span></div><div class="note">'+esc(f.title)+'</div>'+(f.evidence?'<div style="font:11px var(--mono);color:var(--dim);margin-top:3px">'+esc(f.evidence)+'</div>':'')+'</div>';
    }).join('');
  }catch(e){st.textContent='request failed';}}
// --- Process (live watch) ---
window._pm={data:null,timer:null};
async function pmRefresh(){try{var r=await api('/api/agent/proclist');var s=$('pmList');s.innerHTML='<option value="">-- running --</option>'+(r.procs||[]).map(function(p){var lbl=p.name+'  (pid '+p.pid+')';return '<option value="'+esc(lbl)+'">'+esc(p.name)+'  ('+p.pid+')</option>';}).join('');$('pmStatus').textContent=(r.procs||[]).length+' processes -- pick one, then Start';}catch(e){$('pmStatus').textContent='list failed';}}
async function pmTick(){var t=(val('pmProc')||'').trim();if(!t){$('pmStatus').textContent='enter a process (name or PID)';pmStop();return;}
  try{var r=await api('/api/agent/procmon',{json:{proc:t}});if(r.error){$('pmStatus').textContent=r.error;return;}window._pm.data=r;$('pmStatus').textContent='watching '+esc(r.name)+' (pid '+r.pid+') -- '+new Date().toLocaleTimeString();pmRender();}catch(e){$('pmStatus').textContent='read failed';}}
function pmStart(){pmStop();var n=parseInt(val('pmInt')||'2',10);if(isNaN(n)||n<1)n=2;$('pmStartBtn').disabled=true;$('pmStopBtn').disabled=false;pmTick();window._pm.timer=setInterval(pmTick,n*1000);}
function pmStop(){if(window._pm.timer){clearInterval(window._pm.timer);window._pm.timer=null;}$('pmStartBtn').disabled=false;$('pmStopBtn').disabled=true;}
function pmRender(){var d=window._pm.data;if(!d){$('pmView').innerHTML='<span class="note">not running</span>';return;}
  var flt=(val('pmFilter')||'').toLowerCase();
  function hd(t){return '\n<span style="color:var(--dyn);font-weight:700">'+t+'</span>\n';}
  function row(l,v,c){return '<span style="color:var(--dim)">  '+esc(l)+'</span>   <span style="color:'+(c||'var(--text)')+'">'+esc(v)+'</span>\n';}
  var h='<span style="color:var(--dim)">monitoring -- '+new Date().toLocaleTimeString()+'</span>\n';
  h+=hd('PROCESS');
  h+=row('name / pid', d.name+' ('+d.pid+')'+(d.parent?('    parent '+d.parent):''));
  h+=row('path', d.path||'', 'var(--accent)');
  if(d.desc)h+=row('description', d.desc);
  if(d.company)h+=row('company', d.company);
  if(d.product||d.fver)h+=row('product', (d.product||'')+(d.fver?('  (v'+d.fver+')'):''));
  if(d.user)h+=row('user', d.user, 'var(--med)');
  if(d.started)h+=row('started', d.started+'    priority '+(d.priority||'')+'    session '+(d.session||''));
  if(d.cmd)h+=row('command', d.cmd, 'var(--dim)');
  h+=hd('MEMORY');
  h+=row('memory', 'WS '+d.ws+' MB | private '+d.priv+' MB | peak '+d.peak+' MB | virtual '+d.virt+' MB');
  h+=row('counts', 'handles '+d.handles+'    threads '+d.threads+'    cpu '+d.cpu+'s');
  var mods=(d.modules||[]);var total=mods.length;if(flt)mods=mods.filter(function(m){return ((m.name||'')+' '+(m.path||'')).toLowerCase().indexOf(flt)>=0;});
  h+=hd('MODULES ('+mods.length+(flt?(' of '+total):'')+')');
  h+=mods.map(function(m){var nm=(m.name||'');var pad=nm.length<34?nm+Array(34-nm.length+3).join(' '):nm+'  ';return '  <span style="color:#98c379">'+esc(pad)+'</span><span style="color:var(--dim)">'+esc(m.path||'')+'</span>';}).join('\n')+(mods.length?'\n':'');
  var cons=(d.conns||[]);h+=hd('NETWORK -- TCP ('+cons.length+')');
  h+=cons.length?cons.map(function(c){return '  <span style="color:var(--text)">'+esc(c.local)+'</span> <span style="color:var(--dim)">-&gt;</span> <span style="color:#d19a66">'+esc(c.remote)+'</span>    <span style="color:'+(c.state==='Established'?'var(--accent)':'var(--dim)')+'">'+esc(c.state)+'</span>';}).join('\n')+'\n':'  <span style="color:var(--dim)">(none)</span>\n';
  var kids=(d.children||[]);h+=hd('CHILD PROCESSES ('+kids.length+')');
  h+=kids.length?kids.map(function(k){return '  <span style="color:var(--med)">'+esc(k.name)+'</span> <span style="color:var(--dim)">(pid '+k.pid+')</span>';}).join('\n')+'\n':'  <span style="color:var(--dim)">(none)</span>\n';
  $('pmView').innerHTML=h;}
// --- Asar (unpack + browse) ---
window._asar={outDir:'',files:[]};window._asarLast='';
async function asarExtract(){var t=(window._target||val('target')||'').trim();var st=$('asStatus');
  if(!t){st.textContent='no target -- pick one in step 2 first';return;}
  st.textContent='extracting app.asar (a big app can take ~30s)...';$('asFiles').innerHTML='<div class="note">extracting...</div>';$('asAuditBtn').disabled=true;
  try{var r=await api('/api/agent/asar',{json:{target:t}});
    if(r.error){st.textContent='error: '+r.error;$('asFiles').innerHTML='<div class="note">'+esc(r.error)+'</div>';return;}
    window._asar={outDir:r.outDir,files:r.files||[]};
    st.textContent=r.count+' files ('+Math.round(r.bytes/1024)+' KB) unpacked';$('asAuditBtn').disabled=false;asarRender();
  }catch(e){st.textContent='extract failed';}}
function asarRender(){var q=(val('asFilter')||'').toLowerCase();var fs=window._asar.files||[];var rows=[];var shown=0;
  for(var i=0;i<fs.length&&shown<600;i++){var f=fs[i];if(q&&f.path.toLowerCase().indexOf(q)<0)continue;shown++;
    rows.push('<div class="file" style="cursor:pointer;padding:2px 4px;font:11px var(--mono)" onclick="asarView('+i+')">'+esc(f.path)+' <span style="color:var(--dim)">('+f.size+')</span></div>');}
  var tot=q?fs.filter(function(f){return f.path.toLowerCase().indexOf(q)>=0;}).length:fs.length;var more=tot-shown;
  $('asFiles').innerHTML=(rows.join('')||'<div class="note">no match</div>')+(more>0?'<div class="note">... +'+more+' more (refine the filter)</div>':'');}
async function asarView(i){var f=(window._asar.files||[])[i];if(!f)return;var rel=f.path;
  $('asViewTitle').textContent='SOURCE: '+rel;$('asView').innerHTML='<span class="note">loading...</span>';
  try{var r=await api('/api/agent/asar-file',{json:{dir:window._asar.outDir,rel:rel}});
    if(r.error){$('asView').innerHTML='<span class="note">'+esc(r.error)+'</span>';return;}
    window._asarLast=r.full;
    $('asView').textContent=r.text+(r.truncated?'\n\n... [truncated at 512 KB]':'');
    $('asViewTitle').innerHTML='SOURCE: '+esc(rel)+'  <a style="color:var(--accent);font:11px var(--mono);cursor:pointer" onclick="hexFromAsar()">[hex]</a>';
  }catch(e){$('asView').innerHTML='<span class="note">load failed</span>';}}
function hexFromAsar(){if(!window._asarLast)return;$('hxPath').value=window._asarLast;go(11);hexLoad(0);}
function asarToAudit(){if(!window._asar.outDir)return;window._target=window._asar.outDir;var ti=$('target');if(ti)ti.value=window._asar.outDir;go(3);}
// --- Hex (byte view) + data inspector + go-to / find ---
window._hex={path:'',offset:0,size:0,page:2048,rows:[],hl:-1};
// ImHex-style byte colouring: null=dim, whitespace=blue, printable=green, control=orange, high=purple.
function bcol(v){if(v===0)return'var(--hxNull)';if(v===9||v===10||v===13)return'var(--hxWs)';if(v>=32&&v<=126)return'var(--hxAsc)';if(v<32||v===127)return'var(--hxCtl)';return'var(--hxHigh)';}
function hexRender(){var rows=window._hex.rows||[];var hl=window._hex.hl;
  $('hxView').innerHTML=(rows.map(function(x){var ro=parseInt(x.off,16);var hot=(hl>=0&&hl>=ro&&hl<ro+16);
    var pairs=(x.hex.match(/[0-9a-fA-F]{2}/g)||[]);
    var hx='';for(var i=0;i<pairs.length;i++){var v=parseInt(pairs[i],16);hx+='<span style="color:'+bcol(v)+'">'+pairs[i]+'</span>'+(i===7?'  ':' ');}
    var asc=(x.ascii||'');var ah='';for(var i=0;i<asc.length;i++){var v=(i<pairs.length)?parseInt(pairs[i],16):46;ah+='<span style="color:'+bcol(v)+'">'+esc(asc[i])+'</span>';}
    return '<div onclick="hexInspect('+ro+')" style="cursor:pointer;padding:0 2px'+(hot?';background:rgba(88,166,255,.20)':'')+'"><span style="color:var(--accent)">'+x.off+'</span>  '+hx+'<span style="color:var(--hxSep)">|</span>'+ah+'<span style="color:var(--hxSep)">|</span></div>';
  }).join(''))||'<span class="note">(empty)</span>';}
async function hexLoad(off){var p=(val('hxPath')||'').trim();if(!p){$('hxStatus').textContent='enter a file path';return;}
  window._hex.path=p;window._hex.offset=Math.max(0,off|0);$('hxStatus').textContent='reading...';
  try{var r=await api('/api/agent/hex',{json:{path:p,offset:window._hex.offset,length:window._hex.page}});
    if(r.error){$('hxStatus').textContent='error: '+r.error;$('hxView').innerHTML='<span class="note">'+esc(r.error)+'</span>';return;}
    window._hex.size=r.size;window._hex.rows=r.rows||[];
    $('hxStatus').textContent=esc(r.path)+' -- '+r.size+' bytes, offset 0x'+(r.offset).toString(16)+' ('+((r.rows||[]).length*16)+' shown)';
    hexRender();
  }catch(e){$('hxStatus').textContent='read failed';}}
function hexPage(d){var no=window._hex.offset+d*window._hex.page;if(no<0)no=0;if(window._hex.size&&no>=window._hex.size)return;hexLoad(no);}
function hexGoto(){var o=parseInt((val('hxGoto')||'0'),16);if(isNaN(o))o=0;var pg=Math.floor(o/window._hex.page)*window._hex.page;window._hex.hl=o;hexLoad(pg).then(function(){hexInspect(o);});}
async function hexFind(){var q=(val('hxFind')||'').trim();if(!q){$('hxStatus').textContent='enter a search';return;}
  var from=(window._hex.hl>=0?window._hex.hl+1:0);$('hxStatus').textContent='searching...';
  try{var r=await api('/api/agent/hexfind',{json:{path:(window._hex.path||val('hxPath')),query:q,kind:val('hxKind'),from:from}});
    if(r.error){$('hxStatus').textContent='error: '+r.error;return;}
    if(r.offset<0){$('hxStatus').textContent='no match from 0x'+from.toString(16)+' -- clear/reset to search from the top';return;}
    var o=r.offset;var pg=Math.floor(o/window._hex.page)*window._hex.page;window._hex.hl=o;
    await hexLoad(pg);hexInspect(o);$('hxStatus').textContent='match at 0x'+o.toString(16);
  }catch(e){$('hxStatus').textContent='find failed';}}
async function hexInspect(off){if(off===undefined||off===null){off=parseInt((val('hxInsIn')||'0'),16);if(isNaN(off))off=0;}
  window._hex.hl=off;$('hxInsIn').value=off.toString(16);$('hxInsOff').textContent='0x'+off.toString(16);hexRender();
  try{var r=await api('/api/agent/inspect',{json:{path:(window._hex.path||val('hxPath')),offset:off}});
    if(r.error){$('hxInsTab').innerHTML='<tbody><tr><td class="note">'+esc(r.error)+'</td></tr></tbody>';return;}
    $('hxInsTab').innerHTML='<tbody>'+(r.rows||[]).map(function(x){return '<tr><td style="color:var(--dim);padding:1px 8px 1px 0;white-space:nowrap">'+esc(x.n)+'</td><td style="word-break:break-all">'+esc(x.v)+'</td></tr>';}).join('')+'</tbody>';
  }catch(e){}}
async function hexStrings(){var p=(window._hex.path||val('hxPath')||'').trim();if(!p){$('hxStatus').textContent='enter a path and Load first';return;}
  var mn=parseInt(val('hxSMin')||'4',10);if(isNaN(mn)||mn<2)mn=4;
  $('hxSInfo').textContent='scanning...';
  try{var r=await api('/api/agent/strings',{json:{path:p,min:mn,filter:(val('hxSFilter')||''),kind:val('hxSKind')}});
    if(r.error){$('hxSInfo').textContent=r.error;return;}
    var it=r.items||[];$('hxSPanel').style.display='block';
    $('hxSList').innerHTML=it.length?it.map(function(x){var oh='0x'+x.offset.toString(16);
      return '<div onclick="hexJump('+x.offset+')" style="cursor:pointer;padding:2px 4px;border-bottom:1px solid var(--line);white-space:nowrap;overflow:hidden;text-overflow:ellipsis"><span style="color:var(--dim)">'+oh+'</span> <span style="color:var(--muted)">'+x.kind+'</span> <span style="color:var(--accent)">'+esc(x.text)+'</span></div>';
    }).join(''):'<div class="note">no strings matched'+(val('hxSFilter')?' the filter':'')+'</div>';
    $('hxSInfo').textContent=r.total+' match'+(r.total===1?'':'es')+(r.capped?(' (showing first '+it.length+')'):'');
  }catch(e){$('hxSInfo').textContent='scan failed';}}
function hexJump(o){var pg=Math.floor(o/window._hex.page)*window._hex.page;window._hex.hl=o;hexLoad(pg).then(function(){hexInspect(o);});}
function confClass(c){c=(c||'').toLowerCase();if(c.indexOf('il')>=0)return 'il';if(c.indexOf('dynamic')>=0)return 'dyn';if(c.indexOf('llm')>=0)return 'llm';if(c.indexOf('confirmed')>=0)return 'conf';return '';}
function toggleFilter(k){if(FILTER[k]){delete FILTER[k];}else{FILTER[k]=true;}
  document.querySelectorAll('.fchip').forEach(function(c){c.classList.toggle('on',!!FILTER[c.dataset.k]);});renderTriage();}
function renderTriage(){var tb=$('triageBody');tb.innerHTML='';var active=Object.keys(FILTER);
  var rows=FINDINGS.filter(function(f){return active.length===0||FILTER[sevKey(f.sev)];});
  if(!rows.length){tb.innerHTML='<tr><td colspan="4" class="note" style="padding:14px">'+(FINDINGS.length?'no findings for this filter':'no findings yet -- run an audit.')+'</td></tr>';return;}
  rows.forEach(function(f){var k=sevKey(f.sev),cc=confClass(f.conf),tr=document.createElement('tr');
    tr.innerHTML='<td><span class="pill '+k+'">'+esc(f.sev)+'</span></td><td><span class="cb '+cc+'">'+esc(f.conf)+'</span></td><td>'+esc(f.rule)+'</td><td class="ttl">'+esc(f.title)+'</td>';tb.appendChild(tr);});}
function dScore(f){var m=((f&&f.cvss)?(''+f.cvss):'').match(/^\s*([0-9]+(?:\.[0-9])?)\s*\(/);return m?parseFloat(m[1]):null;}
function mConf(c){c=(''+c);if(/Likely-FP/i.test(c))return 'fp';if(/dyn/i.test(c))return 'dyn';if(/Confirmed/i.test(c))return 'il';return 'inf';}
function renderDash(){
  var SC={crit:'--crit',high:'--high',med:'--med',low:'--low',info:'--info'},LB={crit:'Critical',high:'High',med:'Medium',low:'Low',info:'Info'},PL={crit:'Crit',high:'High',med:'Med',low:'Low',info:'Info'};
  var order=['crit','high','med','low','info'],total=FINDINGS.length;
  var maxc=null;FINDINGS.forEach(function(f){var s=dScore(f);if(s!=null&&(maxc==null||s>maxc))maxc=s;});
  var kh='';order.forEach(function(k){kh+='<div class="tile"><div class="stripe" style="background:var('+SC[k]+')"></div><div class="k"><span class="dot" style="background:var('+SC[k]+')"></span>'+LB[k]+'</div><div class="v" style="color:var('+SC[k]+')">'+(counts[k]||0)+'</div></div>';});
  kh+='<div class="tile accent"><div class="stripe" style="background:var(--accent)"></div><div class="k">Max CVSS</div><div class="v">'+(maxc!=null?maxc.toFixed(1):'-')+'</div></div>';
  $('kpis').innerHTML=kh;
  $('sevTotal').textContent=total+' total';
  var sb='';order.forEach(function(k){var c=counts[k]||0;if(c>0)sb+='<i style="background:var('+SC[k]+');flex:'+c+'"></i>';});
  $('sevbarStack').innerHTML=sb||'<i style="background:var(--line);flex:1"></i>';
  var mx=Math.max(1,counts.crit,counts.high,counts.med,counts.low,counts.info);
  var lg='';order.forEach(function(k){var c=counts[k]||0,w=Math.round(100*c/mx);lg+='<div class="lrow"><span class="sw" style="background:var('+SC[k]+')"></span><span class="nm">'+LB[k]+'</span><span class="ct">'+c+'</span><span></span><span class="bar"><i style="width:'+w+'%;background:var('+SC[k]+')"></i></span></div>';});
  $('sevLegend').innerHTML=lg;
  var proven=0,leads=0,fp=0;FINDINGS.forEach(function(f){var c=(f.conf||'');if(/^Confirmed/i.test(c))proven++;else if(/^Likely-FP/i.test(c))fp++;else leads++;});
  var tot=proven+leads+fp,pct=tot?Math.round(100*proven/tot):0;
  $('donut').style.setProperty('--p',pct);$('donutPct').textContent=pct+'%';
  $('akey').innerHTML='<div class="r"><span class="d" style="background:var(--accent)"></span>Proven <span style="color:var(--faint)">&nbsp;Confirmed IL / dyn</span><b>'+proven+'</b></div><div class="r"><span class="d" style="background:var(--line)"></span>Leads <span style="color:var(--faint)">&nbsp;Inferred, triage</span><b>'+leads+'</b></div><div class="r"><span class="d" style="background:var(--faint)"></span>Likely-FP <span style="color:var(--faint)">&nbsp;IL-demoted</span><b>'+fp+'</b></div>';
  var band={crit:0,high:0,med:0,low:0};FINDINGS.forEach(function(f){var k=sevKey(f.sev),s=dScore(f);if(s!=null&&band[k]!==undefined&&s>band[k])band[k]=s;});
  var cb='';['crit','high','med','low'].forEach(function(k){var h=Math.round(band[k]/10*100);cb+='<div class="b"><div class="cbar" style="height:'+h+'%;background:var('+SC[k]+')"></div><div class="lb">'+k.charAt(0).toUpperCase()+'</div></div>';});
  $('cvssBand').innerHTML=cb;
  var rank={CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3,INFO:4};
  var sorted=FINDINGS.slice().sort(function(a,b){var ra=rank[(a.sev||'').toUpperCase()];var rb=rank[(b.sev||'').toUpperCase()];ra=(ra==null?9:ra);rb=(rb==null?9:rb);if(ra!==rb)return ra-rb;return (dScore(b)||0)-(dScore(a)||0);});
  var th='';sorted.slice(0,12).forEach(function(f){var k=sevKey(f.sev),sc=dScore(f),cc=mConf(f.conf),loc=f.file?(''+f.file).split(/[\\/]/).pop():'-',dim=/^Likely-FP/i.test(f.conf||'');
    th+='<tr'+(dim?' style="opacity:.55"':'')+'><td class="sevcell" style="--s:var('+SC[k]+')"><span class="dpill" style="background:color-mix(in srgb,var('+SC[k]+') 16%,transparent);color:var('+SC[k]+')">'+PL[k]+'</span></td><td class="rid">'+esc(f.rule)+'</td><td class="fttl">'+esc(f.title)+'</td><td><span class="conf '+cc+'">'+esc(f.conf)+'</span></td><td class="score" style="color:var('+(sc!=null?SC[k]:'--faint')+')">'+(sc!=null?sc.toFixed(1):'-')+'</td><td class="dfile">'+esc(loc)+'</td></tr>';});
  $('dashTop').innerHTML=th||'<tr><td colspan="6" class="fttl" style="padding:16px">no findings yet -- run an audit (step 3).</td></tr>';
  var t=(window._target||val('target')||'');t=t?(''+t).split(/[\\/]/).pop():'';
  $('dashSub').innerHTML=total?(esc(t)+' &middot; <b>'+total+' findings</b> &middot; '+proven+' proven, '+leads+' leads, '+fp+' likely-FP'):'Run an audit (step 3) to populate the security posture overview.';
}
function showReports(){var box=$('reports');if(!result||!result.reports||!result.reports.length){box.innerHTML='<div class="note">no report files were produced.</div>';return;}
  box.innerHTML='<div class="note">click to download:</div>';
  result.reports.forEach(function(r){var a=document.createElement('a');a.className='dl';a.textContent=r.label;a.onclick=function(){dl(r.file);};box.appendChild(a);});}
async function dl(file){try{var res=await fetch('/api/report?job='+JOB+'&file='+encodeURIComponent(file),{headers:{'X-TCPK-Token':T}});var b=await res.blob();var u=URL.createObjectURL(b);var a=document.createElement('a');a.href=u;a.download=file;a.click();URL.revokeObjectURL(u);}catch(e){alert('download failed');}}
function log(m,cls){var el=$('console');var line=cls?('<span class="'+cls+'">'+esc(m)+'</span>'):esc(m);el.innerHTML+=line+'\n';el.scrollTop=el.scrollHeight;}
function toggleDock(){$('dock').classList.toggle('collapsed');}
function openDock(){$('dock').classList.remove('collapsed');}
// ---- phase 8: interception (review a mitmproxy/frida capture) ----
async function loadCapture(){var f=val('icFile').trim();var kind=val('icKind');var box=$('icFindings');var st=$('icStatus');
  if(!f){st.textContent='enter a capture file path';return;}
  st.textContent='parsing...';box.innerHTML='';
  try{var r=await api('/api/agent/intercept',{json:{file:f,kind:kind}});
    if(r.error){st.textContent=r.error;return;}
    st.textContent=r.count+' finding'+(r.count===1?'':'s')+' from the '+esc(r.kind)+' capture';
    if(!r.findings||!r.findings.length){box.innerHTML='<div class="note">no interception findings in this capture.</div>';return;}
    r.findings.forEach(function(f){var k=sevKey(f.sev),cc=confClass(f.conf);var d=document.createElement('div');d.className='panel';d.style.margin='6px 0';
      d.innerHTML='<div><span class="pill '+k+'">'+esc(f.sev)+'</span> <span class="cb '+cc+'">'+esc(f.conf)+'</span> <b>'+esc(f.title)+'</b></div><div class="note" style="margin-top:4px">'+esc(f.rule)+' -- '+esc(f.evidence)+'</div>';box.appendChild(d);});
  }catch(e){st.textContent='parse failed';}}
// ---- phase 4: decompile / IL view ----
function fmtSize(b){b=b||0;if(b<1024)return b+' B';if(b<1048576)return (b/1024).toFixed(0)+' KB';return (b/1048576).toFixed(1)+' MB';}
function mkModRow(path,badge,name,sub,onopen){
  var d=document.createElement('div');d.className='file';d.style.display='flex';d.style.alignItems='flex-start';d.style.gap='6px';
  var cb=document.createElement('input');cb.type='checkbox';cb.className='msel-cb';cb.style.marginTop='2px';cb._path=path;cb.onclick=function(e){e.stopPropagation();updAuditBtn();};
  var sp=document.createElement('div');sp.style.flex='1';sp.style.minWidth='0';sp.innerHTML=badge+' '+esc(name)+'<br><span style="color:var(--dim);font-size:10px">'+sub+'</span>';
  d.appendChild(cb);d.appendChild(sp);d.onclick=function(){onopen(d);};return d;}
function selectedModulePaths(){return [].slice.call(document.querySelectorAll('#dcModules .msel-cb')).filter(function(c){return c.checked;}).map(function(c){return c._path;});}
function updAuditBtn(){var n=selectedModulePaths().length;var b=$('dcAuditBtn');if(b){b.disabled=(n===0);b.textContent='Audit selected ('+n+')';}}
function toggleSelAll(){var on=$('dcSelAll').checked;[].slice.call(document.querySelectorAll('#dcModules .msel-cb')).forEach(function(c){c.checked=on;});updAuditBtn();}
async function loadModules(){var t=(window._target||val('target')||'').trim();
  if(!t){$('dcStatus').textContent='no target -- pick one in step 2 first';return;}
  $('dcStatus').textContent='enumerating modules...';$('dcModules').innerHTML='<div class="note">loading...</div>';
  if($('dcSelAll'))$('dcSelAll').checked=false;
  try{var r=await api('/api/agent/modules?target='+encodeURIComponent(t));var ms=r.modules||[],ns=r.nativeModules||[];
    $('dcModules').innerHTML='';
    if(!ms.length&&!ns.length){var sc=r.scanned||0;$('dcModules').innerHTML='<div class="note" style="line-height:1.5">no .dll / .exe found under this target (scanned '+sc+' file'+(sc===1?'':'s')+')</div>';$('dcStatus').textContent='0 modules';updAuditBtn();return;}
    var nMs=ms.length,nNs=ns.length;
    $('dcStatus').textContent=nMs+' .NET module(s) to decompile'+(nNs?(' -- '+nNs+' native binaries hidden'):'');
    ms.forEach(function(m){$('dcModules').appendChild(mkModRow(m.path,'<span class="mtag net">.NET</span>',m.name,m.types+' types / '+m.methods+' methods -- decompile IL',function(el){selectModule(m.path,el);}));});
    if(!nMs){var nd=document.createElement('div');nd.className='note';nd.style.lineHeight='1.5';nd.textContent='no decompilable .NET modules under this target'+(nNs?' -- it looks like a native app; its binaries are below':'');$('dcModules').appendChild(nd);}
    if(nNs){window._natives=ns;var tg=document.createElement('div');tg.className='note';tg.style.cssText='cursor:pointer;margin-top:6px;color:var(--accent)';tg.textContent='+ show '+nNs+' native binary(ies) (PE / hardening only -- not decompilable)';tg.onclick=function(){this.remove();window._natives.forEach(function(m){$('dcModules').appendChild(mkModRow(m.path,'<span class="mtag nat">native</span>',m.name,fmtSize(m.size)+' -- PE / hardening / imports',function(el){selectNative(m.path,el);}));});};$('dcModules').appendChild(tg);}
    updAuditBtn();
    if(nMs===1&&!nNs){selectModule(ms[0].path,$('dcModules').firstChild);}
  }catch(e){$('dcModules').innerHTML='<div class="note">load failed</div>';}}
function sleep(ms){return new Promise(function(r){setTimeout(r,ms);});}
async function dlJob(job,file){try{var res=await fetch('/api/report?job='+job+'&file='+encodeURIComponent(file),{headers:{'X-TCPK-Token':T}});var b=await res.blob();var u=URL.createObjectURL(b);var a=document.createElement('a');a.href=u;a.download=file;a.click();URL.revokeObjectURL(u);}catch(e){alert('download failed');}}
async function auditSelected(){var paths=selectedModulePaths();if(!paths.length)return;
  $('dcAudit').style.display='block';$('dcAuditBody').innerHTML='';$('dcAuditBtn').disabled=true;
  openDock();log('[step] focused per-binary audit on '+paths.length+' selected module(s)','c-step');
  for(var i=0;i<paths.length;i++){await auditOneDll(paths[i],i+1,paths.length);}
  $('dcAuditBtn').disabled=false;log('[step] selected-module audit complete','c-step');}
// Focused per-BINARY audit: runs only the file-scoped checks against the one module, so the
// results are about THAT binary (not the whole app). Synchronous -- no full-audit job.
async function auditOneDll(path,idx,total){
  var name=(path.split('\\').pop());
  var card=document.createElement('div');card.className='vcard';card.style.borderLeftColor='var(--dim)';
  card.innerHTML='<div class="h"><span class="pill" style="background:var(--dim);color:#08130a">'+idx+'/'+total+'</span> '+esc(name)+'</div><div class="note" id="au'+idx+'">auditing binary...</div>';
  $('dcAuditBody').appendChild(card);
  try{var r=await api('/api/agent/audit-binary',{json:{dll:path}});
    if(r.error){$('au'+idx).textContent='error: '+esc(r.error);return;}
    var fs=r.findings||[],c={crit:0,high:0,med:0,low:0,info:0};
    fs.forEach(function(f){var kk=sevKey(f.sev);if(c[kk]!==undefined)c[kk]++;});
    $('au'+idx).innerHTML='<b>'+fs.length+' finding'+(fs.length===1?'':'s')+'</b> -- '+c.crit+' critical, '+c.high+' high, '+c.med+' medium, '+c.low+' low, '+c.info+' info';
    if(fs.length){var top=fs.slice(0,15).map(function(f){var kc=sevKey(f.sev);return '<div style="font:11px var(--mono);margin-top:3px"><span class="mtag" style="background:var(--'+kc+');color:#08130a">'+esc(f.sev)+'</span> '+esc(f.rule)+' <span style="color:var(--dim)">('+esc(f.conf)+')</span> -- '+esc(f.title)+'</div>';}).join('');card.innerHTML+='<div style="margin-top:8px;border-top:1px solid var(--border);padding-top:6px">'+top+(fs.length>15?('<div class="note">... +'+(fs.length-15)+' more</div>'):'')+'</div>';}
    else{$('au'+idx).innerHTML+=' <span class="note">(nothing flagged in this binary)</span>';}
  }catch(e){$('au'+idx).textContent='audit error';}}
async function selectNative(path,el){window._dcDll=path;window._dcMethod='';document.querySelectorAll('#dcModules .file').forEach(function(f){f.classList.remove('on');});if(el)el.classList.add('on');
  $('dcMethods').innerHTML='<div class="note">native PE -- no .NET methods to list</div>';$('dcToReview').disabled=true;
  $('dcMethodTitle').textContent='native PE analysis';$('dcCode').innerHTML='<span class="note">reading PE headers...</span>';$('dcSinks').innerHTML='<div class="note">-</div>';
  try{var r=await api('/api/agent/native',{json:{dll:path}});if(r.error){$('dcCode').innerHTML='<span class="note">'+esc(r.error)+'</span>';return;}
    $('dcStatus').textContent=r.file+': '+r.arch+' native PE';
    var h=r.hardening||{};function yn(v){return v?'<span style="color:var(--accent)">YES</span>':'<span style="color:var(--crit)">NO </span>';}
    var ss=(r.signing&&r.signing.status)||'unknown';var sok=(ss.toLowerCase()==='valid');
    var html='';
    html+='FILE       '+esc(r.file)+'   ('+esc(r.arch)+', native / non-.NET)\n';
    html+='SIGNING    <span style="color:var('+(sok?'--accent':'--high')+')">'+esc(ss)+'</span>'+((r.signing&&r.signing.signer)?('\n           '+esc(r.signing.signer)):'')+'\n';
    var hc=(r.hardeningStatus==='HARDENED')?'--ok':(r.hardeningStatus==='WEAK')?'--crit':'--high';
    html+='HARDENING  <span style="color:var('+hc+')">'+esc(r.hardeningStatus)+'</span>'+(r.missing?('   missing: '+esc(r.missing)):'')+'\n';
    html+='   ASLR '+yn(h.ASLR)+'  DEP '+yn(h.DEP)+'  CFG '+yn(h.CFG)+'  HighEntropyVA '+yn(h.HighEntropyVA)+'\n';
    html+='   GS '+esc(h.GS||'N/A')+'   SafeSEH '+esc(h.SafeSEH||'N/A')+'   ForceIntegrity '+yn(h.ForceIntegrity)+'\n';
    html+='IMPORTS    '+r.importsTotal+' imported / '+r.exportsTotal+' exported\n';
    if((r.exportsSample||[]).length){html+='EXPORTS    '+esc(r.exportsSample.join(', '))+((r.exportsTotal>r.exportsSample.length)?' ...':'')+'\n';}
    $('dcCode').innerHTML=html;
    var ri=r.riskyImports||[];
    $('dcSinks').innerHTML=ri.length?ri.map(function(x){return '<div class="vcard high"><div class="h"><span class="pill high">API</span> '+esc(x.api)+'</div>'+esc(x.note)+'</div>';}).join(''):'<div class="note">no high-risk imported APIs flagged</div>';
    $('dcMethodTitle').textContent='native PE: '+esc(r.file);
  }catch(e){$('dcCode').innerHTML='<span class="note">PE analysis failed</span>';}}
async function selectModule(path,el){window._dcDll=path;document.querySelectorAll('#dcModules .file').forEach(function(f){f.classList.remove('on');});if(el)el.classList.add('on');
  $('dcMethods').innerHTML='<div class="note">decompiling...</div>';$('dcCode').innerHTML='<span class="note">pick a method</span>';$('dcSinks').innerHTML='<div class="note">-</div>';$('dcToReview').disabled=true;
  try{var r=await api('/api/agent/decompile',{json:{dll:path}});if(r.error){$('dcMethods').innerHTML='<div class="note">'+esc(r.error)+'</div>';return;}
    $('dcStatus').textContent=r.module+': '+r.types+' types / '+r.methods+' methods / '+((r.interesting||[]).length)+' sink-bearing';
    var im=r.interesting||[];if(!im.length){$('dcMethods').innerHTML='<div class="note">no sink-bearing methods in this module</div>';return;}
    $('dcMethods').innerHTML='';im.forEach(function(m){var d=document.createElement('div');d.className='file';var leaf=m.name.split('::').pop();d.title=m.name;d.innerHTML=esc(leaf)+'<br><span style="color:var(--high);font-size:10px">'+esc((m.sinks||[]).join(', '))+'</span>';d.onclick=function(){selectMethod(path,m.name,d);};$('dcMethods').appendChild(d);});
  }catch(e){$('dcMethods').innerHTML='<div class="note">decompile failed</div>';}}
async function selectMethod(path,method,el){document.querySelectorAll('#dcMethods .file').forEach(function(f){f.classList.remove('on');});if(el)el.classList.add('on');
  window._dcMethod=method;$('dcMethodTitle').textContent='IL: '+method.split('::').pop();$('dcCode').innerHTML='<span class="note">decompiling...</span>';
  try{var r=await api('/api/agent/decompile',{json:{dll:path,method:method}});if(r.error){$('dcCode').innerHTML='<span class="note">'+esc(r.error)+'</span>';return;}
    var html='',sinks=[];(r.il||[]).forEach(function(x){var ln=x.off+'  '+x.op+(x.arg?('  '+x.arg):'');ln=esc(ln);if(x.sink){ln='<span class="vuln">'+ln+'</span>';var lf=(x.arg.split('::').pop()||x.arg);sinks.push(lf);}html+=ln+'\n';});
    $('dcCode').innerHTML=html||'<span class="note">(no IL body -- abstract/extern method)</span>';
    var us=sinks.filter(function(v,i){return sinks.indexOf(v)===i;});
    $('dcSinks').innerHTML=us.length?us.map(function(s){return '<div class="vcard crit"><div class="h"><span class="pill crit">SINK</span></div>'+esc(s)+'</div>';}).join(''):'<div class="note">no sink call in this body</div>';
    $('dcToReview').disabled=false;
  }catch(e){$('dcCode').innerHTML='<span class="note">decompile failed</span>';}}
// ---- phase 5: AI line-by-line review ----
function sendToReview(){if(!window._dcMethod){return;}prepReview();go(5);setTimeout(runReview,300);}
function prepReview(){var mm=window._dcMethod||'';$('arMethod').innerHTML=mm?('method: <b>'+esc(mm.split('::').pop())+'</b> in '+esc((window._dcDll||'').split('\\').pop())):'no method selected -- open step 4 (Decompile), pick a method, then click "Send to AI review"';$('arRun').disabled=!mm;}
async function runReview(){if(!window._dcDll||!window._dcMethod){return;}
  var ag=getAgent();var body={dll:window._dcDll,method:window._dcMethod,provider:ag.provider,model:ag.model,apiKey:ag.apiKey,baseUrl:ag.baseUrl,allowCloud:ag.allowCloud};
  $('arVerdict').innerHTML='<div class="note"><span class="dot ok" style="display:inline-block"></span> agent reviewing via '+esc(ag.provider)+' ... (can take a few seconds)</div>';$('arRun').disabled=true;
  log('[step] AI review: '+window._dcMethod.split('::').pop()+' via '+ag.provider,'c-step');openDock();
  try{var r=await api('/api/agent/review',{json:body});
    if(r.il){$('arCode').textContent=r.il;}
    if(r.error){var ec='<div class="vcard med"><div class="h"><span class="pill med">NOTE</span></div>'+esc(r.error)+'</div>';
      if(r.reachable!==undefined){ec+='<div class="note">IL facts still computed -- reachable: <b>'+r.reachable+'</b>, sinks: '+esc((r.sinks||[]).join(', ')||'none')+'</div>';}
      $('arVerdict').innerHTML=ec;log('[warn] '+r.error,'c-warn');$('arRun').disabled=false;return;}
    var ai=r.ai||{};var sk=sevKey(ai.severity||'info');
    var card='<div class="vcard '+(sk==='crit'||sk==='high'?'crit':'med')+'">';
    card+='<div class="h"><span class="pill '+sk+'">'+esc((ai.verdict||'?').toUpperCase())+'</span><span class="cb llm">AI ('+esc(ai.severity||'?')+')</span> <span class="cb '+(r.reachable?'il':'')+'">IL reachable: '+r.reachable+'</span></div>';
    card+='<div style="margin:7px 0"><b>sink:</b> '+esc(ai.sink||(r.sinks||[]).join(', ')||'-')+'</div>';
    card+='<div style="margin:7px 0"><b>risk:</b> '+esc(ai.risk||'-')+'</div>';
    card+='<div style="margin:7px 0"><b>exploit:</b> '+esc(ai.exploit||'-')+'</div>';
    card+='<div style="margin:7px 0"><b>fix:</b> '+esc(ai.fix||'-')+'</div></div>';
    if(ai.lines&&ai.lines.length){card+='<div class="vcard"><div class="h"><b>line notes</b></div>'+ai.lines.slice(0,8).map(function(x){return '<div>'+esc(x.il||'')+' -- '+esc(x.note||'')+'</div>';}).join('')+'</div>';}
    if((ai.verdict==='vulnerable')&&!r.reachable){card+='<div class="vcard med"><div class="h"><span class="pill med">CROSS-CHECK</span></div>AI flags risk, but the IL prover finds this method is NOT reachable (not public/virtual, no caller) -- likely lower priority.</div>';}
    else if(ai.verdict==='vulnerable'){card+='<div class="note" style="color:var(--il)">IL cross-check: method is reachable -- the AI verdict is backed by the evidence.</div>';}
    $('arVerdict').innerHTML=card;
    log('[find] AI '+(ai.verdict||'?')+' ('+(ai.severity||'?')+') '+(ai.sink||''),'c-find');$('arRun').disabled=false;
  }catch(e){$('arVerdict').innerHTML='<div class="note">review failed</div>';$('arRun').disabled=false;}}
// ---- phase 7: autonomous agent ----
var AUTOJOB=null,autoTimer=null;
async function runAuto(){var t=(window._target||val('target')||'').trim();if(!t){go(2);$('ident').textContent='pick a target first';return;}
  var ag=getAgent();
  if(ag.provider!=='ollama'){$('autoStatus').innerHTML='<span style="color:var(--med)">the autonomous agent is local-ollama-only in this build -- select ollama in step 1.</span>';return;}
  $('autoTranscript').innerHTML='';$('autoFindings').innerHTML='<div class="note">agent working...</div>';$('autoStatus').textContent='starting agent...';$('autoRun').disabled=true;openDock();
  try{var r=await api('/api/agent/auto',{json:{target:t,goal:val('autoGoal'),provider:'ollama',model:ag.model}});
    if(r.error){$('autoStatus').innerHTML='<span style="color:var(--crit)">'+esc(r.error)+'</span>';$('autoRun').disabled=false;return;}
    AUTOJOB=r.jobId;$('autoStatus').textContent='agent running (model: '+esc(r.model)+') -- this takes a minute or two...';log('[step] autonomous agent started on '+t,'c-step');autoTimer=setInterval(pollAuto,1500);
  }catch(e){$('autoStatus').textContent='failed to start agent';$('autoRun').disabled=false;}}
async function pollAuto(){if(!AUTOJOB)return;var s;try{s=await api('/api/agent/auto-status?job='+AUTOJOB);}catch(e){return;}
  (s.steps||[]).forEach(renderAutoStep);
  if(s.done){clearInterval(autoTimer);autoTimer=null;$('autoRun').disabled=false;$('autoStatus').textContent='agent finished.';renderAutoFindings(s.findings,s.summary);log('[step] autonomous agent finished','c-step');}}
function renderAutoStep(st){var box=$('autoTranscript');var label=st.type==='tool'?('TOOL '+esc(st.tool||'')):(st.type==='observation'?('obs <- '+esc(st.tool||'')):(''+st.type));
  var html='<div style="margin:7px 0;border-left:2px solid var(--border);padding-left:9px">';
  html+='<div style="font:700 11px var(--mono);color:var(--accent)">step '+esc(''+(st.step||''))+' &middot; '+label+'</div>';
  if(st.thought){html+='<div style="font:11px var(--mono);color:var(--muted)">'+esc(st.thought)+'</div>';}
  if(st.args){html+='<div style="font:11px var(--mono);color:var(--dim)">args: '+esc(JSON.stringify(st.args))+'</div>';}
  if(st.text){var tx=''+st.text;if(tx.length>320)tx=tx.substring(0,320)+'...';html+='<div class="code" style="margin-top:3px">'+esc(tx)+'</div>';}
  html+='</div>';box.innerHTML+=html;box.scrollTop=box.scrollHeight;
  if(st.type==='tool')log('[step] agent -> '+st.tool+(st.thought?(' ('+st.thought+')'):''),'c-step');
  if(st.type==='final')log('[step] agent done','c-step');}
// The deterministic gate result -- the agent PROPOSES, the IL prover DISPOSES.
// confirmed (green) = the prover proved a tainted path to the sink; review (amber) =
// reachable but the taint source is unproven; refuted (grey) = the prover ruled it out.
function autoVerdict(v){v=(v||'').toLowerCase();
  if(v==='confirmed')return '<span class="pill" style="background:#2ea043;color:#fff">CONFIRMED by IL prover</span>';
  if(v==='review')   return '<span class="pill" style="background:#d29922;color:#111">NEEDS REVIEW</span>';
  if(v==='refuted')  return '<span class="pill" style="background:#6e7681;color:#fff">REFUTED by IL prover</span>';
  return '<span class="pill" style="background:#6e7681;color:#fff">unverified</span>';}
function renderAutoFindings(f,summary){var box=$('autoFindings');f=(f||[]).slice();
  var rank={confirmed:0,review:1,refuted:2};
  f.sort(function(a,b){var ra=rank[(a.verdict_class||'').toLowerCase()];var rb=rank[(b.verdict_class||'').toLowerCase()];
    if(ra===undefined)ra=3;if(rb===undefined)rb=3;return ra-rb;});
  var html='';
  if(summary){html+='<div class="note" style="color:var(--text);margin-bottom:8px">'+esc(summary)+'</div>';}
  if(!f.length){html+='<div class="note">no findings recorded.</div>';}
  else{f.forEach(function(x){var sk=sevKey(x.severity);
    html+='<div class="vcard '+(sk==='crit'||sk==='high'?'crit':'med')+'">'
      +'<div class="h">'+autoVerdict(x.verdict_class)
      +'<span class="pill '+sk+'">'+esc((x.severity||'?').toUpperCase())+'</span>'
      +'<span class="cb '+(x.il_reachable?'il':'')+'">IL reachable: '+x.il_reachable+'</span></div>'
      +'<div style="margin:5px 0"><b>'+esc(x.title||'')+'</b></div>'
      +'<div style="font:11px var(--mono);color:var(--dim)">'+esc(x.method||'')+'</div>'
      +'<div style="margin-top:4px">'+esc(x.rationale||'')+'</div>'
      +(x.taint_verdict?'<div class="note" style="margin-top:4px">IL prover verdict: '+esc(x.taint_verdict)+'</div>':'')
      +'</div>';});}
  box.innerHTML=html;}
</script>
</body></html>
'@
