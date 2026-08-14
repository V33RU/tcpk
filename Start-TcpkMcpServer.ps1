#requires -Version 5.1
<#
.SYNOPSIS
    TCPK MCP server -- exposes TCPK's audit/recon/CVE/exploit capabilities as
    Model Context Protocol tools over stdio (JSON-RPC 2.0).

.DESCRIPTION
    ADDITIVE + READ-ONLY w.r.t. the existing tool: this script only *imports*
    the TCPK module and calls its public cmdlets. It changes nothing in the
    module or GUI -- if you never run this file, TCPK behaves exactly as before.

    An MCP client (Claude Code / Claude Desktop / Cursor / any MCP host) launches
    this script and talks newline-delimited JSON-RPC over stdin/stdout. The
    client's LLM can then drive TCPK and compose it with any other MCP server.

    Transport: stdio. stdout carries ONLY JSON-RPC messages; all TCPK cmdlet
    output streams are suppressed so the protocol channel stays clean. Server
    diagnostics go to stderr.

    See docs/MCP-USAGE.md for setup.
#>
[CmdletBinding()]
param()

# ---------------------------------------------------------------------------
# Keep stdout pristine for JSON-RPC. Use UTF-8 both ways.
# ---------------------------------------------------------------------------
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { }
try { [Console]::InputEncoding  = [System.Text.Encoding]::UTF8 } catch { }
$ErrorActionPreference = 'Stop'

$script:Out = [Console]::Out
function Send-Rpc($obj)      { $script:Out.WriteLine(($obj | ConvertTo-Json -Compress -Depth 25)); $script:Out.Flush() }
function Send-Result($id, $result) { if ($null -ne $id) { Send-Rpc @{ jsonrpc = '2.0'; id = $id; result = $result } } }
function Send-Error($id, $code, $message) { if ($null -ne $id) { Send-Rpc @{ jsonrpc = '2.0'; id = $id; error = @{ code = $code; message = "$message" } } } }
function Log-Stderr($m)      { try { [Console]::Error.WriteLine("[tcpk-mcp] $m") } catch { } }

# ---------------------------------------------------------------------------
# Locate + import the TCPK module (quietly -- never write to stdout).
# ---------------------------------------------------------------------------
$tcpkPsd1 = $null
foreach ($cand in @(
    (Join-Path $PSScriptRoot 'TCPK\TCPK.psd1'),
    (Join-Path $PSScriptRoot '..\TCPK\TCPK\TCPK.psd1'),
    (Join-Path $PSScriptRoot 'TCPK.psd1')
)) { if (Test-Path $cand) { $tcpkPsd1 = (Resolve-Path $cand).Path; break } }

if (-not $tcpkPsd1) { Log-Stderr "TCPK module not found near $PSScriptRoot"; exit 1 }
try { Import-Module $tcpkPsd1 -Force *>$null } catch { Log-Stderr "Import-Module failed: $($_.Exception.Message)"; exit 1 }
$script:TcpkVersion = try { "$((Get-Module TCPK | Select-Object -First 1).Version)" } catch { '0.0.0' }
# Module handle: the decompiler bridge (Get-TcpkAgentModules / Get-TcpkAgentDecompile) and the
# intel model (Get-TcpkIntelModel) are module-PRIVATE, so reach them with `& $mod { ... }`
# rather than duplicating that logic here. Same engine the reports + agentic UI use.
$script:TcpkMod = @(Get-Module TCPK)[0]
Log-Stderr "TCPK module loaded from $tcpkPsd1 (v$script:TcpkVersion)"

# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------
function Get-Arg($arguments, [string]$name, $default = $null) {
    if ($null -eq $arguments) { return $default }
    $p = $arguments.PSObject.Properties[$name]
    if ($p -and $null -ne $p.Value -and "$($p.Value)" -ne '') { return $p.Value }
    return $default
}
function Read-JsonFile([string]$path) {
    if (-not (Test-Path -LiteralPath $path)) { return $null }
    $raw = Get-Content -LiteralPath $path -Raw
    # assign-then-wrap (PS 5.1 collapses @(... | ConvertFrom-Json) for arrays)
    $parsed = ConvertFrom-Json $raw
    return $parsed
}
function New-DefaultOutDir {
    $stamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
    # Under the tool folder, not %TEMP%: an audit output can contain recovered secrets and
    # must travel with the tool rather than persist in the operator's profile.
    Join-Path $PSScriptRoot "work\out\mcp-audit-$stamp"
}

# JSON booleans arrive typed, but a client is free to send the STRING "false", and [bool]
# on any non-empty string is $true in PowerShell. Every gate in this file therefore has to
# compare explicitly. It was written correctly once, inline, for tcpk_generate_poc and then
# NOT reused: 'verbose' used a bare [bool] cast and flipped open on the string "false".
# One implementation, so the next gate cannot get it wrong.
function Get-BoolArg($arguments, [string]$name, [bool]$default = $false) {
    $v = Get-Arg $arguments $name $null
    if ($null -eq $v) { return $default }
    if ($v -is [bool]) { return $v }
    return ("$v".Trim() -ieq 'true')
}

# Validate a caller-supplied outDir. The model chooses this value, and the model reads
# untrusted content: strings carved out of the target, CVE text, decompiled code.
#
# Reading and writing are gated differently, on purpose.
#
# UNC and device paths are refused for BOTH. That is the actual harm: opening \\host\share
# makes the Windows filesystem provider perform SMB session setup and hand the operator's
# Net-NTLMv2 to whatever host the model named, before the file-exists check even returns.
# The tool then answers with an ordinary empty result, so nothing on screen indicates an
# outbound authentication happened.
#
# CONFINEMENT to the tool folder applies only where TCPK CREATES things (tcpk_audit,
# tcpk_generate_poc), which is exactly what the project rule covers, and stops
# tcpk_generate_poc dropping build.bat or a .reg into, say, a Startup folder.
#
# Reads are deliberately NOT confined. An operator can legitimately point at output from a
# CLI run, an older version, or another machine, and the existing MCP tests read a fixture
# from %TEMP% for that reason. Confining reads would have broken a real workflow to close
# a hole that the UNC refusal already closes: what is left is a local file read whose
# content flows into model context, and the operator chose the client and the target.
function Resolve-SafeOutDir([string]$path, [string]$toolName, [switch]$ForWrite) {
    if (-not $path) { throw "$toolName requires an outDir." }
    if ($path -match '^(\\\\|//)') {
        throw "$toolName refused outDir '$path': UNC and device paths authenticate this machine to the named host. Use a local path."
    }
    $rootFull = [IO.Path]::GetFullPath($PSScriptRoot)
    $full = $null
    try { $full = [IO.Path]::GetFullPath([IO.Path]::Combine($rootFull, $path)) }
    catch { throw "$toolName could not resolve outDir '$path': $($_.Exception.Message)" }

    if ($ForWrite) {
        # Trailing separator before comparing, so a sibling like '<root>_evil' cannot pass
        # a naive StartsWith on '<root>'.
        $rootCmp = $rootFull.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
        if (-not $full.StartsWith($rootCmp, [StringComparison]::OrdinalIgnoreCase)) {
            throw "$toolName refused outDir '$path': it resolves to '$full', outside the tool folder. Everything TCPK creates stays under '$rootFull'."
        }
    }
    return $full
}

# ---------------------------------------------------------------------------
# Tool implementations. Each returns a STRING (text content for the client).
# All TCPK calls suppress streams 2-6 so only the return value is used.
# ---------------------------------------------------------------------------
$script:ToolHandlers = @{

    'tcpk_info' = {
        param($a)
        $info = Get-TcpkInfo 2>$null 3>$null 4>$null 5>$null 6>$null
        return ($info | ConvertTo-Json -Depth 5)
    }

    'tcpk_recon_profile' = {
        param($a)
        $target = Get-Arg $a 'target'
        if (-not $target) { throw "Missing required argument: target" }
        $findings = @()
        $p = Get-TcpkTargetProfile -Path $target -Findings $findings 2>$null 3>$null 4>$null 5>$null 6>$null
        return ($p | ConvertTo-Json -Depth 8)
    }

    'tcpk_strings' = {
        param($a)
        $target = Get-Arg $a 'target'
        if (-not $target) { throw "Missing required argument: target" }
        $s = Get-TcpkReconStrings -Path $target 2>$null 3>$null 4>$null 5>$null 6>$null
        return ($s | ConvertTo-Json -Depth 5)
    }

    'tcpk_cve_match' = {
        param($a)
        $target = Get-Arg $a 'target'
        if (-not $target) { throw "Missing required argument: target" }
        $incl = Get-BoolArg $a 'includePatched' $false
        $m = if ($incl) { Get-TcpkCveMatches -Path $target -IncludePatched 2>$null 3>$null 4>$null 5>$null 6>$null }
             else       { Get-TcpkCveMatches -Path $target               2>$null 3>$null 4>$null 5>$null 6>$null }
        return (@($m) | ConvertTo-Json -Depth 6)
    }

    'tcpk_list_modules' = {
        param($a)
        $target = Get-Arg $a 'target'
        if (-not $target) { throw "Missing required argument: target" }
        $r = & $script:TcpkMod { param($t) Get-TcpkAgentModules -Target $t -Summary } $target
        return ($r | ConvertTo-Json -Depth 6)
    }

    'tcpk_decompile' = {
        param($a)
        $dll = Get-Arg $a 'dll'
        if (-not $dll) { throw "Missing required argument: dll" }
        $method = Get-Arg $a 'method'
        # With a method -> its IL, each instruction flagged when it calls a sink.
        if ($method) {
            $r = & $script:TcpkMod { param($d, $m) Get-TcpkAgentDecompile -Dll $d -Method $m } $dll $method
            return ($r | ConvertTo-Json -Depth 8)
        }
        # No method -> the module's SINK-BEARING methods (matched against the shared sink map,
        # i.e. exactly what the IL verifier proves). The shared engine names that list
        # 'interesting' and uses 'methods' for a COUNT -- too ambiguous for an API an LLM reads,
        # so republish it here with self-describing names. Engine is left untouched (the
        # agentic workbench consumes the original shape).
        $r = & $script:TcpkMod { param($d) Get-TcpkAgentDecompile -Dll $d } $dll
        if ($r.error) { return ($r | ConvertTo-Json -Depth 4) }
        $sink = if ($null -eq $r.interesting) { @() } else { @($r.interesting) }
        return ([ordered]@{
            module          = $r.module
            typeCount       = $r.types
            methodCount     = $r.methods
            sinkMethodCount = $sink.Count
            sinkMethods     = $sink
        } | ConvertTo-Json -Depth 8)
    }

    'tcpk_audit' = {
        param($a)
        $target = Get-Arg $a 'target'
        if (-not $target) { throw "Missing required argument: target" }

        # Unpacking an .msi means RUNNING it. Expand-TcpkTarget routes '^\.msi$' to
        # Expand-TcpkMsiFile, which shells out to `msiexec /a`, and an administrative
        # install executes the package's AdminExecuteSequence, i.e. the MSI author's own
        # custom actions, as the invoking user. _Expand.ps1 says so itself: "/a can still
        # run an MSI's custom actions -- extract untrusted installers in a VM".
        #
        # On the CLI that is survivable, because Invoke-TcpkAudit stops at a Read-Host
        # authorization prompt and prints "Extracting MSI via 'msiexec /a'" as it goes.
        # This handler removed BOTH: it passes Acknowledge = $true, which skips the prompt,
        # and pipes the call through *>$null, which swallows the notice. So a model that
        # was steered to a .msi executed the sample's code with nothing shown to anyone.
        #
        # The target is chosen by a model reading untrusted content, so this needs the same
        # explicit opt-in tcpk_generate_poc uses rather than an inference from the path.
        # Decide "is this an .msi" the SAME WAY Expand-TcpkTarget decides it, by asking
        # Get-Item for the extension, rather than by regexing the path string. A gate that
        # parses its input differently from the code it guards is only ever as good as the
        # edge cases its author thought of; matching the dispatcher's own predicate makes
        # the two agree by construction. Get-Item failing is fine and needs no gate:
        # Expand-TcpkTarget opens with the same Test-Path and returns the path untouched,
        # so msiexec is never reached either.
        $isMsi = $false
        try {
            $ti = Get-Item -LiteralPath $target -ErrorAction SilentlyContinue
            if ($ti -and -not $ti.PSIsContainer) { $isMsi = ($ti.Extension.ToLowerInvariant() -eq '.msi') }
        } catch { $isMsi = $false }

        if ($isMsi) {
            if (-not (Get-BoolArg $a 'runInstaller' $false)) {
                throw ("Refused: '$target' is an .msi, and TCPK unpacks one by running it (msiexec /a), " +
                       "which executes the installer's own custom actions on this machine. Re-send with " +
                       "runInstaller=true only if you have authorization AND are in a disposable VM. " +
                       "To audit without running it, extract the .msi yourself and pass the folder.")
            }
            Log-Stderr "tcpk_audit: runInstaller=true, .msi will be unpacked via 'msiexec /a' (executes vendor custom actions)"
        }

        $outDir = Resolve-SafeOutDir (Get-Arg $a 'outDir' (New-DefaultOutDir)) 'tcpk_audit' -ForWrite
        $params = @{ Target = $target; Acknowledge = $true; OutDir = $outDir; InformationAction = 'SilentlyContinue' }
        $pkg  = Get-Arg $a 'packageName';  if ($pkg)  { $params.PackageName = $pkg }
        # No wildcards: Get-Process treats * and ? as patterns, so a model-supplied
        # 'YourApp*' or plain '*' would attach the live-process checks to whatever else
        # happens to be running rather than to the target.
        $proc = Get-Arg $a 'processName'
        if ($proc) {
            if ("$proc" -match '[\*\?\[\]]') {
                throw "Refused: processName '$proc' contains a wildcard. Name one process exactly; Get-Process would otherwise match unrelated processes."
            }
            $params.ProcessName = $proc
        }
        Log-Stderr "tcpk_audit start: $target -> $outDir"
        Invoke-TcpkAudit @params *>$null
        Log-Stderr "tcpk_audit done"
        $findings = @(Read-JsonFile (Join-Path $outDir 'findings.json'))
        $profile  = Read-JsonFile (Join-Path $outDir 'profile.json')
        $sev = @{}
        foreach ($s in 'CRITICAL','HIGH','MEDIUM','LOW','INFO') { $sev[$s] = @($findings | Where-Object { $_.Severity -eq $s }).Count }
        $summary = [ordered]@{
            outDir      = $outDir
            target      = $target
            application = if ($profile) { "$($profile.Name) $($profile.Version)" } else { $null }
            totalFindings = @($findings).Count
            severity    = $sev
            reports     = @{
                html = Join-Path $outDir 'index.html'
                json = Join-Path $outDir 'findings.json'
                markdown = Join-Path $outDir 'report.md'
                profile = Join-Path $outDir 'profile.json'
                strings = Join-Path $outDir 'strings.json'
                exploits = Join-Path $outDir 'exploits.json'
                runlog  = Join-Path $outDir 'run.jsonl'
            }
            note = "Use tcpk_get_findings/tcpk_exploit_plan with this outDir for details."
        }
        return ($summary | ConvertTo-Json -Depth 6)
    }

    'tcpk_get_findings' = {
        param($a)
        $outDir = Resolve-SafeOutDir (Get-Arg $a 'outDir') 'tcpk_get_findings'
        # Where-Object drops the $null that Read-JsonFile returns for a missing file -- otherwise
        # @($null) is a 1-element array and the fallback below materializes one blank finding.
        $raw  = @(Read-JsonFile (Join-Path $outDir 'findings.json') | Where-Object { $_ })
        $prof = Read-JsonFile (Join-Path $outDir 'profile.json')
        # Enrich through the SAME intel model the HTML/Excel reports use, so an agent gets the
        # computed CVSS + ATT&CK + TASVS + how-to-verify -- not just the raw finding record.
        $recs = $null
        try {
            $model = & $script:TcpkMod { param($f, $p) Get-TcpkIntelModel -Findings $f -Target '' -Profile $p } $raw $prof
            if ($model -and $model.findings) { $recs = @($model.findings) }
        } catch { }
        if (-not $recs -or -not @($recs).Count) {
            $recs = @($raw | ForEach-Object { [ordered]@{ sev = "$($_.Severity)"; conf = "$($_.Confidence)"; rule = "$($_.RuleId)"; title = "$($_.Title)"; file = "$($_.File)" } })
        }
        $sevFilter = Get-Arg $a 'severity'
        $ruleFilter = Get-Arg $a 'ruleId'
        $limit = [int](Get-Arg $a 'limit' 50)
        # Get-BoolArg, not [bool]: the string "false" is truthy in PowerShell.
        $full = Get-BoolArg $a 'verbose' $false
        $res = $recs
        if ($sevFilter)  { $res = @($res | Where-Object { "$($_.sev)" -eq $sevFilter }) }
        if ($ruleFilter) { $res = @($res | Where-Object { "$($_.rule)" -like "*$ruleFilter*" }) }
        $res = @($res | Select-Object -First $limit)
        if (-not $full) {
            # Compact projection (built explicitly -- these records are ordered dictionaries).
            $res = @($res | ForEach-Object { [ordered]@{
                sev = $_.sev; conf = $_.conf; rule = $_.rule; title = $_.title; file = $_.file
                cvss = $_.cvss; cwe = $_.cwe; attack = $_.attack; tasvs = $_.tasvs; verify = $_.verify
            } })
        }
        return ([ordered]@{ count = @($res).Count; total = @($recs).Count; findings = $res } | ConvertTo-Json -Depth 6)
    }

    'tcpk_exploit_plan' = {
        param($a)
        $outDir = Resolve-SafeOutDir (Get-Arg $a 'outDir') 'tcpk_get_findings'
        $plan = @(Read-JsonFile (Join-Path $outDir 'exploits.json'))
        return (@($plan) | ConvertTo-Json -Depth 6)
    }

    'tcpk_file_structure' = {
        param($a)
        # Parse a header with a declarative field table. Read-only and takes no outDir, so
        # it needs no gate beyond the path check every tool does.
        $pattern = Get-Arg $a 'pattern'
        if (-not $pattern) {
            return ((Get-TcpkFileStructure -ListPatterns | Select-Object Name, Fields) | ConvertTo-Json -Depth 4)
        }
        $target = Get-Arg $a 'target'
        if (-not $target) { throw "Missing required argument: target" }
        $base = [int64]0
        $bt = "$(Get-Arg $a 'baseOffset' 0)"
        if ($bt) { $base = if ($bt -match '^0x') { [Convert]::ToInt64($bt.Substring(2), 16) } else { [int64]$bt } }
        $rows = @(Get-TcpkFileStructure -Path $target -Pattern $pattern -BaseOffset $base 2>$null)
        return (($rows | Select-Object Name, Offset, Size, Type, Value, Status) | ConvertTo-Json -Depth 4)
    }

    'tcpk_embedded_blobs' = {
        param($a)
        $target = Get-Arg $a 'target'
        if (-not $target) { throw "Missing required argument: target" }
        $f = @(Test-TcpkEmbeddedBlobs -Path $target 2>$null 3>$null 4>$null 5>$null 6>$null)
        return (($f | Select-Object RuleId, Severity, Title, File, Evidence) | ConvertTo-Json -Depth 5)
    }

    'tcpk_byte_search' = {
        param($a)
        $target = Get-Arg $a 'target'
        if (-not $target) { throw "Missing required argument: target" }
        $q = Get-Arg $a 'query'
        if (-not $q) { throw "Missing required argument: query" }
        $kind = "$(Get-Arg $a 'kind' 'auto')"
        $max  = [int]"$(Get-Arg $a 'maxMatches' 200)"
        $res = & $script:TcpkMod {
            param($p, $qq, $k, $m) Find-TcpkByteMatches -Path $p -Query $qq -Kind $k -MaxMatches $m
        } $target $q $kind $max
        $hits = @($res.Matches | ForEach-Object {
            [ordered]@{ offset = [int64]$_.Offset; hex = ('0x' + ([int64]$_.Offset).ToString('x')); kind = $_.Kind }
        })
        return ([ordered]@{ count = $hits.Count; truncated = [bool]$res.Truncated; matches = $hits } | ConvertTo-Json -Depth 4)
    }

    'tcpk_file_diff' = {
        param($a)
        $x = Get-Arg $a 'target'
        $y = Get-Arg $a 'compareTo'
        if (-not $x -or -not $y) { throw "tcpk_file_diff needs both target and compareTo." }
        $r = & $script:TcpkMod { param($p, $q) Get-TcpkFileDiffSummary -PathA $p -PathB $q } $x $y
        return ([ordered]@{
            identical = [bool]$r.Identical; lengthA = [int64]$r.LengthA; lengthB = [int64]$r.LengthB
            commonLength = [int64]$r.CommonLength; differingBytes = [int64]$r.DifferingBytes
            firstDifference = [int64]$r.FirstDifference
            firstDifferenceHex = $(if ($r.FirstDifference -ge 0) { '0x' + ([int64]$r.FirstDifference).ToString('x') } else { $null })
            lengthDelta = [int64]$r.LengthDelta; truncated = [bool]$r.Truncated
        } | ConvertTo-Json -Depth 3)
    }

    'tcpk_generate_poc' = {
        param($a)
        # Gated: requires explicit authorization. Generates a PoC artifact only.
        # NB: compare EXPLICITLY -- do NOT [bool]-coerce the raw arg. A JSON client that sends
        # the boolean as a string ("false"/"no"/"0") would otherwise open the gate, because
        # [bool] on any non-empty string is $true. Accept only real $true or the literal 'true'.
        $authorized = Get-BoolArg $a 'authorized' $false
        if (-not $authorized) { throw "Refused: set authorized=true (a real boolean, or the string 'true') to confirm you have written authorization to test the target." }
        $module = Get-Arg $a 'module'
        $outDir = Resolve-SafeOutDir (Get-Arg $a 'outDir' (Join-Path (New-DefaultOutDir) 'poc')) 'tcpk_generate_poc' -ForWrite
        if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }
        Enable-TcpkExploit -Acknowledge *>$null
        $result = switch ("$module") {
            'New-TcpkFridaTlsBypass' {
                $o = Join-Path $outDir 'tls-bypass.js'
                New-TcpkFridaTlsBypass -OutFile $o -TargetExe (Get-Arg $a 'targetExe' 'target.exe') *>$null
                "Frida TLS-bypass script: $o"
            }
            'New-TcpkPoisonedUpdateManifest' {
                $o = Join-Path $outDir 'poisoned-update.json'
                New-TcpkPoisonedUpdateManifest -OutFile $o -ProductName (Get-Arg $a 'productName' 'product') *>$null
                "Poisoned update manifest: $o"
            }
            'New-TcpkProxyDll' {
                $victim = Get-Arg $a 'componentPath'
                if (-not $victim) { throw "New-TcpkProxyDll requires componentPath (the victim DLL)." }
                New-TcpkProxyDll -Path $victim -OutDir $outDir *>$null
                "Proxy-DLL scaffold in: $outDir"
            }
            'New-TcpkComHijackTemplate' {
                $clsid = Get-Arg $a 'clsid'
                if (-not $clsid) { throw "New-TcpkComHijackTemplate requires clsid." }
                New-TcpkComHijackTemplate -Clsid $clsid -OutDir $outDir *>$null
                "COM-hijack template in: $outDir (CLSID $clsid)"
            }
            default { throw "Unknown or unsupported module: $module" }
        }
        return ([ordered]@{ module = $module; outDir = $outDir; result = $result; note = "PoC artifact generated for AUTHORIZED testing only." } | ConvertTo-Json -Depth 4)
    }
}

# ---------------------------------------------------------------------------
# Tool schema definitions (advertised via tools/list)
# ---------------------------------------------------------------------------
$script:ToolDefs = @(
    [ordered]@{ name = 'tcpk_info'; description = 'TCPK version, host environment, and implemented test-case bucket counts. No arguments.';
        inputSchema = [ordered]@{ type = 'object'; properties = @{} } },

    [ordered]@{ name = 'tcpk_recon_profile'; description = 'Fingerprint a target (app type, version, publisher, runtime, UI frameworks, third-party SDKs, signing, attack-surface counts) without running a full audit.';
        inputSchema = [ordered]@{ type = 'object'; properties = [ordered]@{ target = @{ type = 'string'; description = 'MSIX file or extracted install directory' } }; required = @('target') } },

    [ordered]@{ name = 'tcpk_strings'; description = 'Extract + categorize interesting literals (URLs, file paths, registry keys, IPs, emails, command refs, secret-ish) from the target first-party binaries.';
        inputSchema = [ordered]@{ type = 'object'; properties = [ordered]@{ target = @{ type = 'string'; description = 'Install directory' } }; required = @('target') } },

    [ordered]@{ name = 'tcpk_cve_match'; description = 'Match the target shipped components against LIVE online CVE data (OSV for managed/JS/native ecosystems, NVD by CPE for native libraries). Online-only; needs network. Returns vulnerable / present matches.';
        inputSchema = [ordered]@{ type = 'object'; properties = [ordered]@{ target = @{ type = 'string' }; includePatched = @{ type = 'boolean'; description = 'Also return components matched but already patched' } }; required = @('target') } },

    [ordered]@{ name = 'tcpk_list_modules'; description = 'List the target''s own code modules: managed .NET assemblies (with type/method counts -- these are decompilable) and native PE binaries. Framework/runtime files are filtered out. Call this before tcpk_decompile to choose a module.';
        inputSchema = [ordered]@{ type = 'object'; properties = [ordered]@{ target = @{ type = 'string'; description = 'Install directory, or a single .dll/.exe' } }; required = @('target') } },

    [ordered]@{ name = 'tcpk_decompile'; description = 'Decompile a managed .NET module with Mono.Cecil. WITHOUT method: returns {module, typeCount, methodCount, sinkMethodCount, sinkMethods[]} where each sinkMethods entry is {name, sinks[]} -- the methods that call a dangerous API, per the same sink map the IL verifier uses. Pass a sinkMethods[].name back as "method" to inspect it. WITH method (format "Namespace.Type::Method"): returns {method, sig, il[]} where each il entry is {off, op, arg, sink} and sink=true marks an instruction calling a dangerous API. This is the bytecode evidence behind TCPK Confirmed (IL) findings.';
        inputSchema = [ordered]@{ type = 'object'; properties = [ordered]@{
            dll = @{ type = 'string'; description = 'Path to the managed .NET assembly (from tcpk_list_modules)' }
            method = @{ type = 'string'; description = 'Optional "Namespace.Type::Method". Omit to list sink-bearing methods first.' }
        }; required = @('dll') } },

    [ordered]@{ name = 'tcpk_audit'; description = 'Run the full TCPK audit (static + manifest + OS + creds + network + webview2 + logging + memory + anti-debug + recon + CVE). Writes reports and returns a summary with the outDir. Takes ~1-3 minutes. NOTE: an .msi target is unpacked by RUNNING the installer (msiexec /a), so it additionally requires runInstaller=true.';
        inputSchema = [ordered]@{ type = 'object'; properties = [ordered]@{
            target = @{ type = 'string'; description = 'MSIX file or install directory' }
            packageName = @{ type = 'string'; description = 'e.g. YourApp -- enables OS/registry/service checks' }
            processName = @{ type = 'string'; description = 'e.g. "YourApp" -- enables live-process checks if running' }
            outDir = @{ type = 'string'; description = 'Output directory. Must resolve inside the TCPK tool folder; UNC paths are refused.' }
            runInstaller = @{ type = 'boolean'; description = 'Required ONLY for an .msi target. TCPK unpacks an .msi by running it (msiexec /a), which executes the installer''s own custom actions on this machine. Leave unset for any other target type.' }
        }; required = @('target') } },

    [ordered]@{ name = 'tcpk_get_findings'; description = 'Read findings from a completed audit outDir, ENRICHED through the same intel model the HTML/Excel reports use: each finding carries its computed CVSS v4.0, CWE, ATT&CK technique, OWASP TASVS control and a how-to-verify hint, plus the confidence ladder (Inferred / Confirmed / Confirmed (IL) / Confirmed (dynamic)). Filter by severity or ruleId.';
        inputSchema = [ordered]@{ type = 'object'; properties = [ordered]@{
            outDir = @{ type = 'string' }
            severity = @{ type = 'string'; enum = @('CRITICAL','HIGH','MEDIUM','LOW','INFO') }
            ruleId = @{ type = 'string'; description = 'Substring match on RuleId' }
            limit = @{ type = 'integer'; description = 'Max findings to return (default 50)' }
            verbose = @{ type = 'boolean'; description = 'Also include the long description + raw evidence (default false keeps responses compact)' }
        }; required = @('outDir') } },

    [ordered]@{ name = 'tcpk_exploit_plan'; description = 'Read the actionable exploit/CVE plan (matched CVEs + exploitable findings mapped to framework PoC modules) from a completed audit outDir.';
        inputSchema = [ordered]@{ type = 'object'; properties = [ordered]@{ outDir = @{ type = 'string' } }; required = @('outDir') } },

    [ordered]@{ name = 'tcpk_file_structure'; description = 'Parse a binary header into named, decoded fields using a byte pattern (a flat table of name/offset/size/type). Call WITHOUT "pattern" to list the shipped patterns. Use baseOffset to parse a structure that is not at the start of the file, for example one located by tcpk_embedded_blobs. A field that does not fit the file is returned with status "out-of-range" and no value, never decoded from the following bytes.';
        inputSchema = [ordered]@{ type = 'object'; properties = [ordered]@{
            target = @{ type = 'string'; description = 'File to parse' }
            pattern = @{ type = 'string'; description = 'Shipped pattern name, or a path to a pattern .json. Omit to list what is available.' }
            baseOffset = @{ type = 'string'; description = 'Decimal or 0x-prefixed offset to apply the pattern at (default 0)' }
        }; required = @() } },

    [ordered]@{ name = 'tcpk_embedded_blobs'; description = 'Signature-scan a file or folder for formats embedded at arbitrary offsets: a PE, SQLite database, archive or private key sitting inside an installer or config blob, none of which appears in a directory listing. Every hit is structurally validated (a candidate PE must have an e_lfanew pointing at PE\0\0), and candidates that fail validation are counted rather than reported.';
        inputSchema = [ordered]@{ type = 'object'; properties = [ordered]@{
            target = @{ type = 'string'; description = 'File or folder to scan' }
        }; required = @('target') } },

    [ordered]@{ name = 'tcpk_byte_search'; description = 'Find every offset in a file matching a query. Kinds: auto (UTF-8 AND UTF-16LE, the default), ascii, utf16le, hex (e.g. "4D 5A"), regex. Prefer auto on a Windows binary: string literals are stored as UTF-16LE there, so an ASCII-only search reports nothing for text the file demonstrably contains.';
        inputSchema = [ordered]@{ type = 'object'; properties = [ordered]@{
            target = @{ type = 'string'; description = 'File to search' }
            query = @{ type = 'string'; description = 'Text, hex bytes, or a regex' }
            kind = @{ type = 'string'; description = 'auto | ascii | utf16le | hex | regex (default auto)' }
            maxMatches = @{ type = 'integer'; description = 'Cap on matches returned (default 200); the reply says whether it truncated' }
        }; required = @('target', 'query') } },

    [ordered]@{ name = 'tcpk_file_diff'; description = 'Compare two files and report how many bytes differ, where the first difference is, and any length difference. A size mismatch is reported as lengthDelta rather than counted as differing bytes, so three changed bytes plus a 4 KB tail does not read as 4099 differences. "identical" requires equal length, no differing byte, and a complete scan.';
        inputSchema = [ordered]@{ type = 'object'; properties = [ordered]@{
            target = @{ type = 'string'; description = 'First file' }
            compareTo = @{ type = 'string'; description = 'Second file' }
        }; required = @('target', 'compareTo') } },

    [ordered]@{ name = 'tcpk_generate_poc'; description = 'GATED. Generate a proof-of-concept artifact (Frida TLS-bypass, proxy DLL, poisoned update manifest, COM-hijack template) for an authorized target. Requires authorized=true. Generates files only; does not attack.';
        inputSchema = [ordered]@{ type = 'object'; properties = [ordered]@{
            module = @{ type = 'string'; enum = @('New-TcpkFridaTlsBypass','New-TcpkPoisonedUpdateManifest','New-TcpkProxyDll','New-TcpkComHijackTemplate') }
            authorized = @{ type = 'boolean'; description = 'Must be true: confirms written authorization' }
            outDir = @{ type = 'string'; description = 'Where to write the PoC' }
            componentPath = @{ type = 'string'; description = 'Victim DLL path (New-TcpkProxyDll)' }
            targetExe = @{ type = 'string'; description = 'Target exe name (New-TcpkFridaTlsBypass)' }
            productName = @{ type = 'string'; description = 'Product name (New-TcpkPoisonedUpdateManifest)' }
            clsid = @{ type = 'string'; description = 'CLSID (New-TcpkComHijackTemplate)' }
        }; required = @('module','authorized') } }
)

# ---------------------------------------------------------------------------
# Tool annotations -- MCP clients use these to decide what may run without prompting.
# TCPK has a clean split: everything here is READ-ONLY analysis of files on disk,
# EXCEPT tcpk_audit (writes report files) and tcpk_generate_poc (gated, writes PoC
# artifacts). Only tcpk_cve_match reaches the network (OSV / NVD).
# ---------------------------------------------------------------------------
$script:ToolWrites      = @('tcpk_audit')
$script:ToolDestructive = @('tcpk_generate_poc')
$script:ToolNetwork     = @('tcpk_cve_match')
foreach ($d in $script:ToolDefs) {
    $n = "$($d.name)"
    $isDestructive = [bool]($script:ToolDestructive -contains $n)
    $isWriter      = [bool]($script:ToolWrites -contains $n)
    $d['annotations'] = [ordered]@{
        title           = $n
        readOnlyHint    = (-not $isDestructive -and -not $isWriter)
        destructiveHint = $isDestructive
        idempotentHint  = (-not $isDestructive)
        openWorldHint   = [bool]($script:ToolNetwork -contains $n)
    }
}

# ---------------------------------------------------------------------------
# JSON-RPC dispatch loop
# ---------------------------------------------------------------------------
function Invoke-ToolCall($id, $params) {
    $name = $params.name
    $arguments = $params.arguments
    if (-not $script:ToolHandlers.ContainsKey("$name")) {
        Send-Result $id @{ content = @(@{ type = 'text'; text = "Unknown tool: $name" }); isError = $true }
        return
    }
    try {
        $text = & $script:ToolHandlers["$name"] $arguments
        if ($null -eq $text) { $text = '(no output)' }
        Send-Result $id @{ content = @(@{ type = 'text'; text = "$text" }); isError = $false }
    } catch {
        Log-Stderr "tool '$name' error: $($_.Exception.Message)"
        Send-Result $id @{ content = @(@{ type = 'text'; text = "Error: $($_.Exception.Message)" }); isError = $true }
    }
}

Log-Stderr "TCPK MCP server ready (stdio). Waiting for JSON-RPC..."
$reader = [Console]::In
while ($true) {
    $line = $null
    try { $line = $reader.ReadLine() } catch { break }
    if ($null -eq $line) { break }                 # EOF -> client closed
    if (-not "$line".Trim()) { continue }

    $msg = $null
    try { $msg = ConvertFrom-Json $line } catch { Log-Stderr "bad JSON: $line"; continue }
    $id = $null; if ($msg.PSObject.Properties['id']) { $id = $msg.id }
    $method = "$($msg.method)"

    try {
        switch ($method) {
            'initialize' {
                Send-Result $id ([ordered]@{
                    protocolVersion = '2024-11-05'
                    capabilities    = @{ tools = @{} }
                    serverInfo      = @{ name = 'tcpk'; version = $script:TcpkVersion }
                })
            }
            'notifications/initialized' { }          # notification -> no reply
            'notifications/cancelled'   { }
            'ping'           { Send-Result $id @{} }
            'tools/list'     { Send-Result $id @{ tools = $script:ToolDefs } }
            'tools/call'     { Invoke-ToolCall $id $msg.params }
            'resources/list' { Send-Result $id @{ resources = @() } }
            'prompts/list'   { Send-Result $id @{ prompts = @() } }
            default {
                if ($null -ne $id) { Send-Error $id -32601 "Method not found: $method" }
            }
        }
    } catch {
        Log-Stderr "dispatch error ($method): $($_.Exception.Message)"
        if ($null -ne $id) { Send-Error $id -32603 "Internal error: $($_.Exception.Message)" }
    }
}
Log-Stderr "TCPK MCP server: stdin closed, exiting."
