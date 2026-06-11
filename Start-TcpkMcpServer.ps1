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
Log-Stderr "TCPK module loaded from $tcpkPsd1"

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
    Join-Path $env:TEMP "tcpk-mcp\audit-$stamp"
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
        $incl = [bool](Get-Arg $a 'includePatched' $false)
        $m = if ($incl) { Get-TcpkCveMatches -Path $target -IncludePatched 2>$null 3>$null 4>$null 5>$null 6>$null }
             else       { Get-TcpkCveMatches -Path $target               2>$null 3>$null 4>$null 5>$null 6>$null }
        return (@($m) | ConvertTo-Json -Depth 6)
    }

    'tcpk_audit' = {
        param($a)
        $target = Get-Arg $a 'target'
        if (-not $target) { throw "Missing required argument: target" }
        $outDir = Get-Arg $a 'outDir' (New-DefaultOutDir)
        $params = @{ Target = $target; Acknowledge = $true; OutDir = $outDir; InformationAction = 'SilentlyContinue' }
        $pkg  = Get-Arg $a 'packageName';  if ($pkg)  { $params.PackageName = $pkg }
        $proc = Get-Arg $a 'processName';  if ($proc) { $params.ProcessName = $proc }
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
                markdown = Join-Path $outDir 'findings.md'
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
        $outDir = Get-Arg $a 'outDir'
        if (-not $outDir) { throw "Missing required argument: outDir" }
        $findings = @(Read-JsonFile (Join-Path $outDir 'findings.json'))
        $sevFilter = Get-Arg $a 'severity'
        $ruleFilter = Get-Arg $a 'ruleId'
        $limit = [int](Get-Arg $a 'limit' 50)
        $res = $findings
        if ($sevFilter)  { $res = @($res | Where-Object { $_.Severity -eq $sevFilter }) }
        if ($ruleFilter) { $res = @($res | Where-Object { "$($_.RuleId)" -like "*$ruleFilter*" }) }
        $res = @($res | Select-Object -First $limit)
        return ([ordered]@{ count = @($res).Count; total = @($findings).Count; findings = $res } | ConvertTo-Json -Depth 6)
    }

    'tcpk_exploit_plan' = {
        param($a)
        $outDir = Get-Arg $a 'outDir'
        if (-not $outDir) { throw "Missing required argument: outDir" }
        $plan = @(Read-JsonFile (Join-Path $outDir 'exploits.json'))
        return (@($plan) | ConvertTo-Json -Depth 6)
    }

    'tcpk_generate_poc' = {
        param($a)
        # Gated: requires explicit authorization. Generates a PoC artifact only.
        $authorized = [bool](Get-Arg $a 'authorized' $false)
        if (-not $authorized) { throw "Refused: set authorized=true to confirm you have written authorization to test the target." }
        $module = Get-Arg $a 'module'
        $outDir = Get-Arg $a 'outDir' (Join-Path (New-DefaultOutDir) 'poc')
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

    [ordered]@{ name = 'tcpk_cve_match'; description = 'Match the target shipped components against the offline CVE catalog. Returns vulnerable / present / possibly-embedded matches.';
        inputSchema = [ordered]@{ type = 'object'; properties = [ordered]@{ target = @{ type = 'string' }; includePatched = @{ type = 'boolean'; description = 'Also return components matched but already patched' } }; required = @('target') } },

    [ordered]@{ name = 'tcpk_audit'; description = 'Run the full TCPK audit (static + manifest + OS + creds + network + webview2 + logging + memory + anti-debug + recon + CVE). Writes reports and returns a summary with the outDir. Takes ~1-3 minutes.';
        inputSchema = [ordered]@{ type = 'object'; properties = [ordered]@{
            target = @{ type = 'string'; description = 'MSIX file or install directory' }
            packageName = @{ type = 'string'; description = 'e.g. YourApp -- enables OS/registry/service checks' }
            processName = @{ type = 'string'; description = 'e.g. "YourApp" -- enables live-process checks if running' }
            outDir = @{ type = 'string'; description = 'Output directory (default: temp)' }
        }; required = @('target') } },

    [ordered]@{ name = 'tcpk_get_findings'; description = 'Read findings from a completed audit outDir, optionally filtered by severity or ruleId.';
        inputSchema = [ordered]@{ type = 'object'; properties = [ordered]@{
            outDir = @{ type = 'string' }
            severity = @{ type = 'string'; enum = @('CRITICAL','HIGH','MEDIUM','LOW','INFO') }
            ruleId = @{ type = 'string'; description = 'Substring match on RuleId' }
            limit = @{ type = 'integer'; description = 'Max findings to return (default 50)' }
        }; required = @('outDir') } },

    [ordered]@{ name = 'tcpk_exploit_plan'; description = 'Read the actionable exploit/CVE plan (matched CVEs + exploitable findings mapped to framework PoC modules) from a completed audit outDir.';
        inputSchema = [ordered]@{ type = 'object'; properties = [ordered]@{ outDir = @{ type = 'string' } }; required = @('outDir') } },

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
                    serverInfo      = @{ name = 'tcpk'; version = '1.4.1' }
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
