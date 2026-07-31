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
    if (($unreadable + $depth + $reparse) -eq 0) { return }

    $parts = New-Object 'System.Collections.Generic.List[string]'
    if ($unreadable) { $parts.Add("$unreadable directory(ies) unreadable") }
    if ($depth)      { $parts.Add("$depth subtree(s) past the depth cap") }
    if ($reparse)    { $parts.Add("$reparse reparse point(s) not followed") }
    $summary = $parts -join '; '

    $sample = New-Object 'System.Collections.Generic.List[string]'
    foreach ($p in @($s.UnreadableSample))     { $sample.Add("unreadable: $p") }
    foreach ($p in @($s.DepthSkippedSample))   { $sample.Add("depth-capped: $p") }
    foreach ($p in @($s.ReparseSkippedSample)) { $sample.Add("reparse: $p") }
    $sampleTxt = (@($sample) | Select-Object -First 12) -join ' ; '

    # Unreadable directories are the only class that represents an unknown. A depth cap
    # and a refused reparse point are deliberate, bounded decisions.
    $sev = 'INFO'
    if ($unreadable -gt 0) { $sev = 'LOW' }

    $advice = 'Reparse points and depth-capped subtrees are deliberate limits, not errors.'
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
            'reparse-point subtrees are deliberate safety limits in the walker. This is a statement ' +
            'about the completeness of the audit, not about the application.') `
        -Fix $advice
}
