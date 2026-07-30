function Test-TcpkReparseLoops {
<#
.SYNOPSIS
    Detect NTFS junction / reparse-point LOOPS (GhostTree / GhostBranch) under a target: a
    directory junction whose target is its own ancestor, which makes recursive scanners follow
    the loop forever and miss the real files -- a scanner-evasion / DoS trick (Varonis).

.DESCRIPTION
    A standard user (no admin) can run `mklink /J C:\App\sub C:\App` to point a child folder at
    its parent. Any recursive scan (AV / EDR / a naive audit tool) then follows the loop and
    never finishes, so malware placed in the parent goes unexamined. This walks the target
    SAFELY (never descending into a reparse point, TCPK's own defense) and reports each junction
    whose target is an ancestor of the junction itself.

    Cross-platform: it detects Windows junctions/symlinks and Linux symlinks (the ReparsePoint
    attribute), so the loop logic is verifiable off Windows too.

.PARAMETER Path
    Directory (or file) to inspect.

.PARAMETER MaxDepth
    Depth cap for the safe walk (default 40).

.OUTPUTS
    [TcpkFinding] -- reparse.* findings.
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path, [int]$MaxDepth = 40)

    if (-not (Test-Path -LiteralPath $Path)) {
        return (New-TcpkFinding -Module 'discovery' -RuleId 'reparse.path-missing' -Severity 'INFO' `
                -Confidence 'Skipped' -Title "Path not found: $Path")
    }

    $info = @(Get-TcpkReparseInfo -Path $Path -MaxDepth $MaxDepth)
    $loops = @($info | Where-Object { $_.IsLoop })
    $plain = @($info | Where-Object { -not $_.IsLoop })

    foreach ($l in $loops) {
        New-TcpkFinding -Module 'discovery' -RuleId 'reparse.recursive-junction' -Severity 'HIGH' `
            -Confidence 'Confirmed' -Cwe @('CWE-59', 'CWE-400') `
            -Title "Recursive directory junction (GhostTree): $(Split-Path $l.Link -Leaf)" `
            -File $l.Link `
            -Evidence "$($l.Link) -> $($l.Target)  (target is an ancestor of the junction)" `
            -Impact 'A recursive scanner (AV/EDR or a naive audit) follows this loop forever and never examines the real files in the parent -- files placed alongside the junction can evade scanning, and the scan can hang (DoS).' `
            -Description 'A directory junction/symlink points back to one of its own ancestors, creating an unbounded set of valid paths (GhostBranch/GhostTree). No admin rights are required to create it. TCPK''s own scans skip reparse points; other tools may not.' `
            -Fix 'Remove the junction (rmdir the reparse point). Scan with reparse-point-aware enumeration (do not follow junctions); alert on junction creation in user-writable app directories.'
    }

    if ($plain.Count) {
        $sample = ($plain | Select-Object -First 8 | ForEach-Object { "$($_.Link) -> $($_.Target)" }) -join ' ; '
        New-TcpkFinding -Module 'discovery' -RuleId 'reparse.junction' -Severity 'INFO' `
            -Confidence 'Confirmed' `
            -Title "$($plain.Count) non-recursive junction/reparse point(s) present" `
            -Evidence $sample `
            -Description 'Directory reparse points that redirect elsewhere without looping. Often legitimate (backward-compat redirects); review that the targets are expected and not attacker-writable.'
    }
}
