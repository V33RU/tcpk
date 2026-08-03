function Test-TcpkScanCoverage {
<#
.SYNOPSIS
    A44. Report what the scan could NOT read, so a partial scan cannot be mistaken
    for a clean result.

.DESCRIPTION
    Every static detector in TCPK enumerates files through Get-TcpkChildItemSafe.
    That walker deliberately drops three classes of subtree:

      Unreadable  the directory could not be enumerated, almost always an ACL.
                  This matters most for the primary target type: MSIX packages
                  live under C:\Program Files\WindowsApps, which is restricted by
                  default and unreadable even to administrators until ownership is
                  taken.
      Depth       the subtree sat past the depth cap.
      Reparse     the child was a junction or symlink, which the walker refuses to
                  follow so a GhostTree loop cannot hang the scan.

    Previously all three were silent. A scan that read a tenth of the target
    produced the same output as one that read all of it, every downstream detector
    reported a clean result, and nothing indicated why. That is a false negative
    with no signal attached.

    This check turns the accounting into a finding. It says nothing about the
    application's security posture: it is a statement about the completeness of
    the audit itself, which is why the severity stays low. It reports only when
    something was actually skipped.

    Run it AFTER the other checks. Invoke-TcpkAudit resets the counters at the
    start of a run and calls this at the end, so the numbers cover the whole audit.

    Note the reparse count is expected to be non-zero on many real targets and is
    not a problem by itself. Test-TcpkReparseLoops is what decides whether any of
    those junctions are a GhostTree loop.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param()

    # Direct call: this function already runs inside the module, so the private
    # accounting helpers are in scope.
    $s = Get-TcpkScanStats
    if (-not $s) { return }

    $unreadable = [int]$s.UnreadableCount
    $depth      = [int]$s.DepthSkippedCount
    $reparse    = [int]$s.ReparseSkippedCount
    # Degraded READS, not skipped directories: a file large enough to be streamed is
    # read in full but yields printable runs instead of verbatim text, and past the
    # dedup threshold repeated runs are kept once. Both change what every downstream
    # check saw, and the per-file flags were inspected by one check out of 65, so they
    # are accumulated centrally and reported here for the whole audit.
    $viewCap    = [int]$s.ViewCappedCount
    $viewDedup  = [int]$s.ViewDedupedCount
    # A check that ran out of wall-clock budget and stopped enumerating. The check cannot
    # report this itself -- Get-TcpkPeFiles just stops yielding and the caller returns
    # normally with a short list -- so it is counted centrally and surfaced here.
    $budgetOut  = [int]$s.BudgetStoppedCount
    if (($unreadable + $depth + $reparse + $viewCap + $viewDedup + $budgetOut) -eq 0) { return }

    $parts = New-Object 'System.Collections.Generic.List[string]'
    if ($unreadable) { $parts.Add("$unreadable directory(ies) unreadable") }
    if ($depth)      { $parts.Add("$depth subtree(s) past the depth cap") }
    if ($reparse)    { $parts.Add("$reparse reparse point(s) not followed") }
    if ($viewCap)    { $parts.Add("$viewCap file(s) whose extracted text hit its ceiling") }
    if ($viewDedup)  { $parts.Add("$viewDedup file(s) read with repeated strings collapsed") }
    if ($budgetOut)  { $parts.Add("$budgetOut check(s) stopped early on the time budget") }
    $summary = $parts -join '; '

    $sample = New-Object 'System.Collections.Generic.List[string]'
    foreach ($p in @($s.UnreadableSample))     { $sample.Add("unreadable: $p") }
    foreach ($p in @($s.DepthSkippedSample))   { $sample.Add("depth-capped: $p") }
    foreach ($p in @($s.ReparseSkippedSample)) { $sample.Add("reparse: $p") }
    foreach ($p in @($s.ViewCappedSample))     { $sample.Add("text-capped: $p") }
    foreach ($p in @($s.ViewDedupedSample))    { $sample.Add("deduped: $p") }
    foreach ($p in @($s.BudgetStoppedSample)) { $sample.Add("budget-stopped: $p") }
    $sampleTxt = (@($sample) | Select-Object -First 12) -join ' ; '

    # Unreadable directories and a capped text view are the classes that represent an
    # UNKNOWN. A depth cap, a refused reparse point and dedup are deliberate, bounded
    # decisions: dedup keeps every distinct string and loses only repeat counts.
    $sev = 'INFO'
    if ($unreadable -gt 0 -or $viewCap -gt 0 -or $budgetOut -gt 0) { $sev = 'LOW' }

    $advice = 'Reparse points and depth-capped subtrees are deliberate limits, not errors.'
    if ($viewDedup -gt 0 -and $unreadable -eq 0 -and $viewCap -eq 0) {
        $advice = ('Every byte of those files was read and every distinct string kept. Only the ' +
            'REPEAT COUNT of an identical string was collapsed, so any finding that reports an ' +
            'occurrence count for one of these files counts distinct strings, not total ' +
            'appearances. Presence and content are unaffected.')
    }
    if ($budgetOut -gt 0) {
        $advice = ('One or more checks ran out of wall-clock budget and stopped part-way through ' +
            'the target. The files they did not reach were NOT examined, so a clean result for ' +
            'those paths is unknown rather than verified. Re-run with a larger -CheckBudgetSec, ' +
            'or point the audit at a narrower -Path. A signature check is the usual one to hit ' +
            'this, because Authenticode chain building can block on a CRL/OCSP fetch.')
    }
    if ($viewCap -gt 0) {
        $advice = ('The extracted-text view for those files reached its ceiling, so text past that ' +
            'point was never handed to the rules. Treat those files as unknown rather than clean, ' +
            'and review them directly with: strings -a <file>')
    }
    if ($unreadable -gt 0) {
        $advice = ('Re-run elevated, or take ownership of the unreadable paths, then compare the ' +
            'finding set. Any static result for those paths is currently unknown rather than clean. ' +
            'For MSIX targets, extract the package and scan the extracted tree instead of scanning ' +
            'WindowsApps in place.')
    }

    New-TcpkFinding -Module 'discovery' -RuleId 'scan.incomplete-coverage' `
        -Severity $sev -Confidence 'Confirmed' `
        -Title "Scan coverage was incomplete: $summary" `
        -File '(scan coverage)' `
        -Evidence ("walked $($s.DirsWalked) directory(ies), max depth $($s.MaxDepthSeen); $summary" +
            $(if ($sampleTxt) { " -- $sampleTxt" } else { '' })) `
        -Description ('Parts of the target were not read during this audit, so the absence of a ' +
            'finding for those paths does not mean they are clean. Unreadable directories are ' +
            'usually an ACL: WindowsApps in particular is restricted by default. Depth-capped and ' +
            'reparse-point subtrees are deliberate safety limits in the walker. Files large enough ' +
            'to be streamed are read in full, but the rules then see extracted printable runs ' +
            'rather than verbatim bytes; where a view hit its ceiling, part of even that was not ' +
            'evaluated. This is a statement about the completeness of the audit, not about the ' +
            'application.') `
        -Fix $advice
}
