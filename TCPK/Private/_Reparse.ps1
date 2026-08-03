# NTFS reparse-point (junction / symlink) safety + detection. A GhostTree/GhostBranch attack
# (Varonis) creates a directory junction that loops back to an ancestor, so a naive recursive
# scan follows the loop forever (scanner DoS -> the parent's real payload goes unexamined).
# Windows PowerShell 5.1's Get-ChildItem -Recurse follows junctions; PS7 does not. TCPK targets
# both, so the SAFE walker below never descends into a reparse point and caps depth, and the
# DETECTOR flags the loops.

# Is this item a reparse point (junction / mount point / symlink)? Cross-platform: the
# ReparsePoint attribute is set for Windows junctions+symlinks and for Linux symlinks.
function Test-TcpkIsReparse {
    [CmdletBinding()] param([Parameter(Mandatory)]$Item)
    try { return [bool]($Item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) } catch { return $false }
}

# Resolve a link's target path (best effort across PS versions): .LinkTarget (PS7) /
# .Target / ResolveLinkTarget. Returns $null if not a link or unresolved.
function Get-TcpkLinkTarget {
    [CmdletBinding()] param([Parameter(Mandatory)]$Item)
    foreach ($p in 'LinkTarget', 'Target') {
        try { $v = $Item.$p; if ($v) { return "$([array]$v | Select-Object -First 1)" } } catch {}
    }
    try { $r = $Item.ResolveLinkTarget($true); if ($r) { return "$($r.FullName)" } } catch {}
    return $null
}

# --- scan-coverage accounting -------------------------------------------------------------
# The safe walker silently drops three classes of subtree: directories it cannot enumerate
# (ACL), subtrees past the depth cap, and reparse points it refuses to follow. Without
# accounting, a scan that read a tenth of the target looks identical to one that read all of
# it, and every static detector downstream reports a clean result. These counters make the
# blind spots reportable instead of invisible. Accumulates across a whole audit; call
# Reset-TcpkScanStats at the start of one.
$script:TcpkScanStats = $null
$script:TcpkScanSampleCap = 25

function Reset-TcpkScanStats {
    [CmdletBinding()] param()
    $script:TcpkScanStats = [pscustomobject]@{
        DirsWalked          = 0
        UnreadableCount     = 0
        UnreadableSample    = (New-Object 'System.Collections.Generic.List[string]')
        DepthSkippedCount   = 0
        DepthSkippedSample  = (New-Object 'System.Collections.Generic.List[string]')
        ReparseSkippedCount = 0
        ReparseSkippedSample= (New-Object 'System.Collections.Generic.List[string]')
        MaxDepthSeen        = 0
        # Degraded READS, as opposed to skipped directories. A file above the
        # streaming threshold is fully read but yields printable runs rather than
        # verbatim text, and above the dedup threshold repeated runs are collapsed.
        # Both change what downstream checks see, and only one check out of 65 ever
        # inspected the per-file flags -- so they are accumulated here instead and
        # reported once for the whole audit.
        ViewCappedCount     = 0
        ViewCappedSample    = (New-Object 'System.Collections.Generic.List[string]')
        ViewDedupedCount    = 0
        ViewDedupedSample   = (New-Object 'System.Collections.Generic.List[string]')
    }
}

function Get-TcpkScanStats {
    [CmdletBinding()] param()
    if (-not $script:TcpkScanStats) { Reset-TcpkScanStats }
    return $script:TcpkScanStats
}

# Bounded recorder: keeps a capped sample so a pathological tree cannot balloon memory,
# while the count stays exact.
function Add-TcpkScanSkip {
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Kind, [string]$ItemPath)
    if (-not $script:TcpkScanStats) { Reset-TcpkScanStats }
    $s = $script:TcpkScanStats
    switch ($Kind) {
        'Unreadable' {
            $s.UnreadableCount++
            if ($ItemPath -and $s.UnreadableSample.Count -lt $script:TcpkScanSampleCap) { $s.UnreadableSample.Add($ItemPath) }
        }
        'Depth' {
            $s.DepthSkippedCount++
            if ($ItemPath -and $s.DepthSkippedSample.Count -lt $script:TcpkScanSampleCap) { $s.DepthSkippedSample.Add($ItemPath) }
        }
        'Reparse' {
            $s.ReparseSkippedCount++
            if ($ItemPath -and $s.ReparseSkippedSample.Count -lt $script:TcpkScanSampleCap) { $s.ReparseSkippedSample.Add($ItemPath) }
        }
        'ViewCapped' {
            $s.ViewCappedCount++
            if ($ItemPath -and $s.ViewCappedSample.Count -lt $script:TcpkScanSampleCap) { $s.ViewCappedSample.Add($ItemPath) }
        }
        'ViewDeduped' {
            $s.ViewDedupedCount++
            if ($ItemPath -and $s.ViewDedupedSample.Count -lt $script:TcpkScanSampleCap) { $s.ViewDedupedSample.Add($ItemPath) }
        }
    }
}

# GhostTree-SAFE recursive enumerator: like Get-ChildItem -Recurse, but it NEVER descends into
# a reparse-point directory, caps depth ($MaxDepth), and tracks visited full paths. So a
# junction loop cannot hang the scan. -File / -Directory filter the emitted items.
# Every skipped subtree is accounted for via Add-TcpkScanSkip so Test-TcpkScanCoverage can
# report what the scan could not see.
function Get-TcpkChildItemSafe {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path, [switch]$File, [switch]$Directory, [int]$MaxDepth = 40)
    $root = $null
    try { $root = Get-Item -LiteralPath $Path -Force -ErrorAction Stop } catch {
        Add-TcpkScanSkip -Kind 'Unreadable' -ItemPath $Path
        return
    }
    if (-not $root.PSIsContainer) { if (-not $Directory) { $root }; return }

    $stats = Get-TcpkScanStats
    $stack = New-Object System.Collections.Stack
    $stack.Push([pscustomobject]@{ Dir = $root; Depth = 0 })
    $visited = New-Object 'System.Collections.Generic.HashSet[string]'
    while ($stack.Count -gt 0) {
        $cur = $stack.Pop()
        $canon = try { "$($cur.Dir.FullName)".TrimEnd('\', '/').ToLowerInvariant() } catch { $null }
        if ($canon -and -not $visited.Add($canon)) { continue }   # already walked this real dir
        $stats.DirsWalked++
        if ($cur.Depth -gt $stats.MaxDepthSeen) { $stats.MaxDepthSeen = $cur.Depth }

        # -ErrorVariable rather than try/catch: Get-ChildItem raises a NON-terminating error
        # on an inaccessible directory, so with -ErrorAction SilentlyContinue the catch block
        # never runs and the failure was previously indistinguishable from an empty directory.
        $enumErr = $null
        $children = @()
        try {
            $children = @(Get-ChildItem -LiteralPath $cur.Dir.FullName -Force -ErrorAction SilentlyContinue -ErrorVariable enumErr)
        } catch {
            $enumErr = $_
        }
        if ($enumErr) { Add-TcpkScanSkip -Kind 'Unreadable' -ItemPath "$($cur.Dir.FullName)" }

        foreach ($c in $children) {
            if ($c.PSIsContainer) {
                if (-not $File) { $c }
                if (Test-TcpkIsReparse $c) {
                    Add-TcpkScanSkip -Kind 'Reparse' -ItemPath "$($c.FullName)"
                } elseif ($cur.Depth -ge $MaxDepth) {
                    Add-TcpkScanSkip -Kind 'Depth' -ItemPath "$($c.FullName)"
                } else {
                    $stack.Push([pscustomobject]@{ Dir = $c; Depth = $cur.Depth + 1 })
                }
            } else {
                if (-not $Directory) { $c }
            }
        }
    }
}

# Enumerate the reparse-point directories under $Path (using the safe walker, so it does not
# loop) and classify each: a loop is one whose target is an ANCESTOR of the link itself
# (GhostBranch/GhostTree). Returns records @{ Link; Target; IsLoop }.
function Get-TcpkReparseInfo {
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Path, [int]$MaxDepth = 40)
    $out = New-Object System.Collections.Generic.List[object]
    $root = $null; try { $root = Get-Item -LiteralPath $Path -Force -ErrorAction Stop } catch { return $out.ToArray() }
    $items = @()
    if ($root.PSIsContainer) { $items = @(Get-TcpkChildItemSafe -Path $Path -Directory -MaxDepth $MaxDepth) } else { return $out.ToArray() }
    # also consider the root itself
    $items = @($root) + $items
    foreach ($d in $items) {
        if (-not (Test-TcpkIsReparse $d)) { continue }
        $tgt = Get-TcpkLinkTarget $d
        $linkFull = try { "$($d.FullName)".TrimEnd('\', '/') } catch { "$($d.FullName)" }
        $isLoop = $false
        if ($tgt) {
            $tgtFull = try { [System.IO.Path]::GetFullPath($tgt).TrimEnd('\', '/') } catch { "$tgt".TrimEnd('\', '/') }
            $sep = [System.IO.Path]::DirectorySeparatorChar
            # loop when the link sits inside (or equals) its own target -> traversing re-enters the tree
            if ($linkFull.Equals($tgtFull, [StringComparison]::OrdinalIgnoreCase) -or
                $linkFull.StartsWith($tgtFull + $sep, [StringComparison]::OrdinalIgnoreCase)) { $isLoop = $true }
        }
        $out.Add([pscustomobject]@{ Link = $linkFull; Target = $tgt; IsLoop = $isLoop })
    }
    return $out.ToArray()
}
