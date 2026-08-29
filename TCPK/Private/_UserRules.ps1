#requires -Version 5.1
# User-authored check loader.
#
# WHY THIS EXISTS. Adding a detection to TCPK meant writing a full Test-TcpkX.ps1 cmdlet.
# A stranger who spots a new class of hardcoded credential or a new dangerous config key
# could not contribute without understanding PowerShell 5.1, the finding model and the load
# order. Phase 1 lets them drop a JSON rule file into TCPK/Data/rules/ and have TCPK run it
# alongside the built-in checks.
#
# JSON, not YAML, on purpose. PowerShell 5.1 has ConvertFrom-Json built-in. YAML would need
# vendoring YamlDotNet, which is a non-system DLL inside a tool that flags non-system DLLs.
# The community writes nuclei templates in YAML, but for a tool that lives on customer
# machines the calculus is different: fewer moving pieces, smaller supply-chain surface.
#
# SANDBOXED. A rule can pattern-match. It cannot execute anything, load a DLL, spawn a
# process, or reach the network. That property is enforced by construction: the schema
# supports "match" and no "script" or "run" field exists. This is deliberate. A community
# rule format that can shell out becomes a code-execution primitive that any TCPK user
# would ship in their audit tool.
#
# Phase 1 supports the ONE check type that covers ~80% of what people would want: a file
# glob plus a regex over the content. If Phase 1 gets any uptake, Phase 2 can add IL
# call-site, registry, PE-import and MSIX-capability check types under the same schema.

function Read-TcpkUserRule {
<#
.SYNOPSIS
    Load and VALIDATE one user rule from a JSON string. Never throws.
.DESCRIPTION
    Returns @{ Rule = <object|$null>; Errors = <string[]> }. A rule with any error is refused
    whole, not partially loaded, so a bad rule never fires with default field values that read
    like an intentional finding.
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Json, [string]$SourceLabel = '<inline>')

    if ([string]::IsNullOrWhiteSpace($Json)) {
        return @{ Rule = $null; Errors = @("$SourceLabel : rule is empty") }
    }
    $obj = $null
    try { $obj = ConvertFrom-Json $Json }
    catch { return @{ Rule = $null; Errors = @("$SourceLabel : not valid JSON ($($_.Exception.Message))") } }

    $errors = New-Object 'System.Collections.Generic.List[string]'
    $get = { param($n) if ($obj.PSObject.Properties[$n]) { $obj.$n } else { $null } }

    $id       = "$(& $get 'id')".Trim()
    $sev      = "$(& $get 'severity')".Trim().ToUpperInvariant()
    $type     = "$(& $get 'type')".Trim().ToLowerInvariant()
    $desc     = "$(& $get 'description')".Trim()
    $fix      = "$(& $get 'fix')".Trim()
    $title    = "$(& $get 'title')".Trim()
    $cwe      = @(& $get 'cwe')
    $cwe      = @($cwe | Where-Object { $_ })
    $match    = & $get 'match'

    if (-not $id)   { $errors.Add("$SourceLabel : 'id' is required") }
    if ($id -and $id -notmatch '^[a-z][a-z0-9_.\-]{2,80}$') {
        $errors.Add("$SourceLabel : 'id' must be lowercase, contain a dot, and use only [a-z0-9_.-] (got '$id')")
    }
    if (-not $sev) { $errors.Add("$SourceLabel : 'severity' is required") }
    elseif ($sev -notin 'CRITICAL','HIGH','MEDIUM','LOW','INFO') {
        $errors.Add("$SourceLabel : 'severity' must be CRITICAL / HIGH / MEDIUM / LOW / INFO (got '$sev')")
    }
    if (-not $type) { $type = 'file-regex' }
    if ($type -ne 'file-regex') {
        $errors.Add("$SourceLabel : 'type' must be 'file-regex' (got '$type'). More types will land in later phases.")
    }
    if (-not $desc) { $errors.Add("$SourceLabel : 'description' is required so a report reader knows what the finding means") }
    if (-not $fix)  { $errors.Add("$SourceLabel : 'fix' is required so a report reader knows what to do about it") }
    if (-not $title) { $title = $id }

    # Deliberately reject any field that could imply execution. If you add a new field later,
    # add it here first; refusing everything unknown is safer than allowing everything unknown.
    $allowed = @('id','severity','type','description','fix','title','cwe','match')
    foreach ($p in $obj.PSObject.Properties.Name) {
        if ($p -notin $allowed) {
            $errors.Add("$SourceLabel : unknown field '$p'. Allowed: $($allowed -join ', ')")
        }
    }

    # Validate match block for file-regex
    $glob = ''; $regex = ''; $ignoreCase = $true; $maxHits = 8; $prefilter = @()
    if ($type -eq 'file-regex') {
        if (-not $match) {
            $errors.Add("$SourceLabel : 'match' block is required for type file-regex")
        } else {
            $glob      = "$($match.glob)".Trim()
            $regex     = "$($match.regex)"
            if ($match.PSObject.Properties['ignoreCase']) { $ignoreCase = [bool]$match.ignoreCase }
            if ($match.PSObject.Properties['maxHits'])    { $maxHits    = [int]$match.maxHits }
            if ($match.PSObject.Properties['prefilter'])  { $prefilter  = @($match.prefilter | Where-Object { $_ }) }
            if (-not $glob)  { $errors.Add("$SourceLabel : match.glob is required (e.g. '**/*.config')") }
            if (-not $regex) { $errors.Add("$SourceLabel : match.regex is required") }
            # Attempt to compile the regex so a malformed one is refused now, not at scan time.
            if ($regex) {
                try { [void][regex]::new($regex) }
                catch { $errors.Add("$SourceLabel : match.regex is not a valid .NET regex ($($_.Exception.Message))") }
            }
            $allowedMatch = @('glob','regex','ignoreCase','maxHits','prefilter')
            foreach ($mp in $match.PSObject.Properties.Name) {
                if ($mp -notin $allowedMatch) {
                    $errors.Add("$SourceLabel : match.'$mp' is not a recognised field. Allowed: $($allowedMatch -join ', ')")
                }
            }
        }
    }

    if ($errors.Count) { return @{ Rule = $null; Errors = $errors.ToArray() } }

    $rule = [pscustomobject]@{
        Id          = $id
        Title       = $title
        Severity    = $sev
        Type        = $type
        Description = $desc
        Fix         = $fix
        Cwe         = $cwe
        Glob        = $glob
        Regex       = $regex
        IgnoreCase  = $ignoreCase
        MaxHits     = $maxHits
        Prefilter   = $prefilter
        Source      = $SourceLabel
    }
    return @{ Rule = $rule; Errors = @() }
}

function Get-TcpkUserRules {
<#
.SYNOPSIS
    Load every user rule under TCPK/Data/rules/ (and optionally -ExtraPath).
.DESCRIPTION
    Returns @{ Rules = <object[]>; Errors = <string[]> }. Errors are surfaced to the caller
    so the audit can emit a Skipped finding rather than silently dropping a broken rule.
#>
    [CmdletBinding()]
    param([string[]]$ExtraPath = @())

    $dirs = New-Object 'System.Collections.Generic.List[string]'
    if ($script:TcpkRoot) {
        $shipped = Join-Path $script:TcpkRoot 'Data\rules'
        if (Test-Path -LiteralPath $shipped -PathType Container) { $dirs.Add($shipped) }
    }
    foreach ($p in $ExtraPath) {
        if ($p -and (Test-Path -LiteralPath $p -PathType Container)) { $dirs.Add($p) }
    }

    $rules = New-Object 'System.Collections.Generic.List[object]'
    $errors = New-Object 'System.Collections.Generic.List[string]'
    $seenIds = New-Object 'System.Collections.Generic.HashSet[string]'

    foreach ($d in $dirs) {
        $files = @()
        try { $files = Get-ChildItem -LiteralPath $d -Recurse -File -Filter '*.json' -ErrorAction SilentlyContinue }
        catch { continue }
        foreach ($f in $files) {
            $body = ''
            try { $body = [IO.File]::ReadAllText($f.FullName) } catch { continue }
            $r = Read-TcpkUserRule -Json $body -SourceLabel $f.FullName
            foreach ($e in $r.Errors) { $errors.Add($e) }
            if ($r.Rule) {
                if (-not $seenIds.Add($r.Rule.Id)) {
                    $errors.Add("$($f.FullName) : rule id '$($r.Rule.Id)' is already defined; second occurrence ignored")
                } else {
                    $rules.Add($r.Rule)
                }
            }
        }
    }

    return @{ Rules = $rules.ToArray(); Errors = $errors.ToArray() }
}

function Convert-TcpkGlobToRegex {
<#
.SYNOPSIS
    Turn a shell glob into a case-insensitive .NET regex over a forward-slashed path.
.DESCRIPTION
    Recognised tokens: '**' any depth including zero, '*' one path segment, '?' one char.
    Everything else is escaped literally. Anchored to the whole path.
#>
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Glob)
    # Normalise separators
    $g = $Glob -replace '\\','/'
    # Tokenise around ** first, then * and ?
    $sb = New-Object System.Text.StringBuilder
    $i = 0; $n = $g.Length
    while ($i -lt $n) {
        if ($i + 1 -lt $n -and $g[$i] -eq '*' -and $g[$i+1] -eq '*') {
            # ** matches any depth including nothing (so '**/*.json' matches 'a.json' at root)
            [void]$sb.Append('.*'); $i += 2
            # optional trailing / after ** just gets swallowed by .*
            if ($i -lt $n -and $g[$i] -eq '/') { $i++ }
        } elseif ($g[$i] -eq '*') {
            [void]$sb.Append('[^/]*'); $i++
        } elseif ($g[$i] -eq '?') {
            [void]$sb.Append('[^/]'); $i++
        } else {
            [void]$sb.Append([regex]::Escape([string]$g[$i])); $i++
        }
    }
    return '(?i)^' + $sb.ToString() + '$'
}
