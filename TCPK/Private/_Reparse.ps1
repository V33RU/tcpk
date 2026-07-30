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

# GhostTree-SAFE recursive enumerator: like Get-ChildItem -Recurse, but it NEVER descends into
# a reparse-point directory, caps depth ($MaxDepth), and tracks visited full paths. So a
# junction loop cannot hang the scan. -File / -Directory filter the emitted items.
function Get-TcpkChildItemSafe {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path, [switch]$File, [switch]$Directory, [int]$MaxDepth = 40)
    $root = $null
    try { $root = Get-Item -LiteralPath $Path -Force -ErrorAction Stop } catch { return }
    if (-not $root.PSIsContainer) { if (-not $Directory) { $root }; return }

    $stack = New-Object System.Collections.Stack
    $stack.Push([pscustomobject]@{ Dir = $root; Depth = 0 })
    $visited = New-Object 'System.Collections.Generic.HashSet[string]'
    while ($stack.Count -gt 0) {
        $cur = $stack.Pop()
        $canon = try { "$($cur.Dir.FullName)".TrimEnd('\', '/').ToLowerInvariant() } catch { $null }
        if ($canon -and -not $visited.Add($canon)) { continue }   # already walked this real dir
        $children = @()
        try { $children = @(Get-ChildItem -LiteralPath $cur.Dir.FullName -Force -ErrorAction SilentlyContinue) } catch {}
        foreach ($c in $children) {
            if ($c.PSIsContainer) {
                if (-not $File) { $c }
                if (-not (Test-TcpkIsReparse $c) -and $cur.Depth -lt $MaxDepth) {
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
