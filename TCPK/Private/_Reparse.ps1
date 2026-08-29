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

# ---------------------------------------------------------------------------
# PER-CHECK WALL-CLOCK BUDGET.
#
# The extractor already bounds a single FILE. That is not enough: a check that spends 20
# seconds per binary across 400 binaries runs for hours without any one file misbehaving.
# Test-TcpkStrings is the worst case -- it concatenates the three extracted views into one
# string (up to ~144 MB) and runs three regexes over it, PER PE. An audit sat at 4% on two
# different targets because of exactly that aggregate, and nothing anywhere had a bound.
#
# PowerShell cannot interrupt a running scriptblock from outside without a separate runspace,
# so the budget is COOPERATIVE: _RunCheck arms it, and any check with a per-file loop calls
# Test-TcpkCheckBudgetExpired once per iteration and stops cleanly. A check that stops early
# keeps the findings it already produced -- unlike an exception, which would discard them all
# because _RunCheck collects output with `$r = & $Block`.
$script:TcpkCheckDeadline  = $null
$script:TcpkCheckBudgetSec = 300

# ---------------------------------------------------------------------------
# HEARTBEAT.
#
# Three separate stalls were diagnosed by guesswork -- extractor, then regex backtracking,
# then aggregate per-file cost -- and the first two guesses were WRONG, because a stalled
# audit emitted nothing at all. No check name, no file, no counter. That silence is the
# release blocker: a tool that goes quiet under load cannot be handed to anyone, whatever
# its findings are worth.
#
# Any loop that can run long calls Write-TcpkHeartbeat once per iteration. It is throttled
# to one line every TcpkHeartbeatSec, so the cost is a DateTime compare per file and the
# output stays readable. A stall now describes itself:
#
#   [heartbeat] Test-TcpkStrings  120s  412/638  current: xul.dll (130 MB)
#
# which turns a multi-round guessing game into one line of log.
$script:TcpkHeartbeatSec  = 15
$script:TcpkHeartbeatLast = $null
$script:TcpkHeartbeatFrom = $null

function Reset-TcpkHeartbeat {
    [CmdletBinding()] param()
    $script:TcpkHeartbeatLast = $null
    $script:TcpkHeartbeatFrom = Get-Date
}

function Write-TcpkHeartbeat {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Component,
        [int]$Index = 0,
        [int]$Total = 0,
        [string]$Current = '',
        [long]$CurrentBytes = 0
    )
    $now = Get-Date
    if (-not $script:TcpkHeartbeatFrom) { $script:TcpkHeartbeatFrom = $now }
    if ($script:TcpkHeartbeatLast -and (($now - $script:TcpkHeartbeatLast).TotalSeconds -lt $script:TcpkHeartbeatSec)) { return }
    $script:TcpkHeartbeatLast = $now

    $el = [int]($now - $script:TcpkHeartbeatFrom).TotalSeconds
    $pos = if ($Total -gt 0) { "$Index/$Total" } else { "$Index" }
    $cur = ''
    if ($Current) {
        $sz = if ($CurrentBytes -gt 0) { " ({0} MB)" -f [math]::Round($CurrentBytes / 1MB, 1) } else { '' }
        $cur = "  current: $Current$sz"
    }
    $msg = "{0,-30} {1,5}s  {2}{3}" -f $Component, $el, $pos, $cur
    try { Write-Information -MessageData "  [heartbeat] $msg" -InformationAction Continue } catch { }
    try { Write-TcpkLog -Level DEBUG -Component $Component -Message "heartbeat $pos$cur" | Out-Null } catch { }
}

function Start-TcpkCheckBudget {
    [CmdletBinding()] param([int]$Seconds = 0)
    $s = if ($Seconds -gt 0) { $Seconds } else { $script:TcpkCheckBudgetSec }
    $script:TcpkCheckDeadline = (Get-Date).AddSeconds($s)
}

function Clear-TcpkCheckBudget {
    [CmdletBinding()] param()
    $script:TcpkCheckDeadline = $null
}

# $true once the current check has overrun. Cheap enough to call per file.
function Test-TcpkCheckBudgetExpired {
    [CmdletBinding()] param()
    if (-not $script:TcpkCheckDeadline) { return $false }
    return ((Get-Date) -gt $script:TcpkCheckDeadline)
}

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
        # A check that ran out of wall-clock budget and stopped enumerating early. Counted
        # here because the check itself cannot know it happened -- Get-TcpkPeFiles simply
        # stops yielding, so the caller sees a short list and returns normally.
        BudgetStoppedCount  = 0
        BudgetStoppedSample = (New-Object 'System.Collections.Generic.List[string]')
        # A WMI/CIM query that timed out or failed. Without this the audit reads as
        # clean-on-services when in fact it never got an answer: every service check
        # catches its own error and returns zero findings, which is indistinguishable
        # from "no service is misconfigured" unless the gap is recorded here.
        WmiFailedCount      = 0
        WmiFailedSample     = (New-Object 'System.Collections.Generic.List[string]')
        # ---- Conditions that make a whole FAMILY of results meaningless -------------
        # The three above record parts of the tree that were not read. These three record
        # something worse: the file WAS read, every check ran to completion, and the
        # results are still not evidence of anything, because the bytes the checks saw
        # do not contain the application's code or strings.
        #
        # PackedOpaque   the binary is packed / obfuscated, so its strings are encrypted
        #                or generated at runtime. Every text-level check (secrets,
        #                endpoints, callsites, entropy) returns few or zero findings on
        #                it, which is byte-for-byte identical to a clean binary.
        # BundleTooLarge a .NET single-file apphost above the extractor's size ceiling.
        #                Test-TcpkSingleFileExe returns $null for it, which is the same
        #                value it returns for "this is not a bundle", so the bundled
        #                assemblies are never carved and the entire managed attack
        #                surface is silently absent from the audit.
        # NativeOnly     the target carries no managed assembly, so the IL-based provers
        #                (crypto verdicts, TLS callback verdicts, taint) cannot run at
        #                all. Their silence is a capability limit, not a clean verdict.
        PackedOpaqueCount   = 0
        PackedOpaqueSample  = (New-Object 'System.Collections.Generic.List[string]')
        BundleTooLargeCount = 0
        BundleTooLargeSample= (New-Object 'System.Collections.Generic.List[string]')
        NativeOnlyCount     = 0
        NativeOnlySample    = (New-Object 'System.Collections.Generic.List[string]')
        # A CVE lookup that could not reach OSV or NVD. Same shape as WmiFailed and for the
        # same reason: on a network failure the CVE layer returns nothing, and a report with
        # no dependency CVEs is byte-for-byte what an application with no vulnerable
        # dependencies produces. TCPK ships no offline CVE data, so a failed lookup means the
        # supply-chain surface was not tested at all, not that it came back clean.
        CveLookupFailedCount  = 0
        CveLookupFailedSample = (New-Object 'System.Collections.Generic.List[string]')
        # Mono.Cecil could not be loaded, so every IL-based verdict (crypto misuse, TLS
        # accept-all, taint) silently returned nothing. The report should say so rather than
        # ship without the flagship Confirmed (IL) findings and read as clean.
        CecilMissingCount    = 0
        CecilMissingSample   = (New-Object 'System.Collections.Generic.List[string]')
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
        'BudgetStopped' {
            $s.BudgetStoppedCount++
            if ($ItemPath -and $s.BudgetStoppedSample.Count -lt $script:TcpkScanSampleCap) { $s.BudgetStoppedSample.Add($ItemPath) }
        }
        'WmiFailed' {
            $s.WmiFailedCount++
            if ($ItemPath -and $s.WmiFailedSample.Count -lt $script:TcpkScanSampleCap) { $s.WmiFailedSample.Add($ItemPath) }
        }
        'PackedOpaque' {
            $s.PackedOpaqueCount++
            if ($ItemPath -and $s.PackedOpaqueSample.Count -lt $script:TcpkScanSampleCap) { $s.PackedOpaqueSample.Add($ItemPath) }
        }
        'BundleTooLarge' {
            $s.BundleTooLargeCount++
            if ($ItemPath -and $s.BundleTooLargeSample.Count -lt $script:TcpkScanSampleCap) { $s.BundleTooLargeSample.Add($ItemPath) }
        }
        'NativeOnly' {
            $s.NativeOnlyCount++
            if ($ItemPath -and $s.NativeOnlySample.Count -lt $script:TcpkScanSampleCap) { $s.NativeOnlySample.Add($ItemPath) }
        }
        'CveLookupFailed' {
            $s.CveLookupFailedCount++
            if ($ItemPath -and $s.CveLookupFailedSample.Count -lt $script:TcpkScanSampleCap) { $s.CveLookupFailedSample.Add($ItemPath) }
        }
        'CecilMissing' {
            $s.CecilMissingCount++
            if ($ItemPath -and $s.CecilMissingSample.Count -lt $script:TcpkScanSampleCap) { $s.CecilMissingSample.Add($ItemPath) }
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
