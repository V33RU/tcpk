# Shared process-resolution helpers for the Runtime bucket.

function Get-TcpkProcess {
<#
Resolves -ProcessName or -ProcessId into a list of Process objects.
Returns an empty array if neither is supplied or nothing matches.
#>
    [CmdletBinding()]
    param(
        [string]$ProcessName,
        [Nullable[int]]$ProcessId
    )
    if ($ProcessId) {
        $p = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
        if ($p) { return @($p) }
        return @()
    }
    if ($ProcessName) {
        return @(Get-Process -Name $ProcessName -ErrorAction SilentlyContinue)
    }
    return @()
}

# Convenience for "this check returns Skipped if we're not admin and admin is required"
function New-TcpkSkippedFinding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$RuleId,
        [Parameter(Mandatory)][string]$Title,
        [string]$Reason = 'Admin elevation required.'
    )
    New-TcpkFinding -Module 'runtime' -RuleId $RuleId `
        -Severity 'INFO' -Confidence 'Skipped' `
        -Title $Title -Evidence $Reason
}

# Resolve which RUNNING process belongs to the audit target, so the live-process (Bucket E)
# checks can attach automatically when the caller did not pass -ProcessName. Read-only:
# enumerates the target's shipped *.exe basenames and intersects them with the running
# process list. Never starts, stops, or modifies any process. Returns $null if none match.
function Resolve-TcpkTargetProcess {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [string[]]$IdTerms = @()
    )

    # exes shipped under the install dir -> candidate process base names
    $exeBases = @()
    try {
        $exeBases = @(Get-ChildItem -LiteralPath $Path -Recurse -File -Filter '*.exe' -ErrorAction SilentlyContinue |
            ForEach-Object { $_.BaseName } | Sort-Object -Unique)
    } catch { }
    if (-not $exeBases.Count) { return $null }

    # currently-running processes, indexed by lowercased name
    $running = @{}
    try {
        foreach ($p in (Get-Process -ErrorAction SilentlyContinue)) {
            $n = "$($p.ProcessName)"
            if (-not $n) { continue }
            $lk = $n.ToLowerInvariant()
            if (-not $running.ContainsKey($lk)) { $running[$lk] = $p }
        }
    } catch { }
    if (-not $running.Count) { return $null }

    # candidate = a shipped exe whose process is currently running
    $candidates = @($exeBases | Where-Object { $running.ContainsKey($_.ToLowerInvariant()) })
    if (-not $candidates.Count) { return $null }

    # prefer a candidate matching an identity term (the main app exe), else the first running one
    $best = $null
    foreach ($c in $candidates) {
        foreach ($t in @($IdTerms)) {
            $tt = "$t"
            if (-not $tt) { continue }
            if ($c -like "*$tt*" -or $tt -like "*$c*") { $best = $c; break }
        }
        if ($best) { break }
    }
    if (-not $best) { $best = $candidates[0] }

    $proc = $running[$best.ToLowerInvariant()]
    [pscustomobject]@{
        Name       = $best
        ProcId     = $(if ($proc) { $proc.Id } else { $null })
        Count      = @($candidates).Count
        Candidates = @($candidates)
    }
}
