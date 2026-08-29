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
    # A WMI/CIM query that timed out or errored. This one matters more than it looks: every
    # service check catches its own WMI error and returns zero findings, which is byte-for-byte
    # identical to "no service is misconfigured". Without this counter an audit on a box with a
    # sick WMI service reads as a clean bill of health for the entire service attack surface.
    $wmiFail    = [int]$s.WmiFailedCount
    # The three below are a different class from everything above. Those record parts of the
    # tree that were not read; these record a target that WAS read in full, where every check
    # ran to completion, and the results still are not evidence. A packed binary hands the
    # text rules its decompression stub, an oversized single-file apphost is skipped by the
    # extractor and its bundled assemblies never exist on disk to be scanned, and a native
    # target gives the IL provers nothing to parse. In all three the checks return few or
    # zero findings, which is byte-for-byte what a genuinely clean target produces.
    $packed     = [int]$s.PackedOpaqueCount
    $bigBundle  = [int]$s.BundleTooLargeCount
    $nativeOnly = [int]$s.NativeOnlyCount
    # A CVE lookup that could not reach OSV or NVD. Same failure shape as WmiFailed: the CVE
    # layer returns nothing, and a report with no dependency CVEs is what an application with
    # no vulnerable dependencies produces. TCPK ships no offline CVE data, so there is no
    # fallback -- an unreachable lookup means the supply-chain surface was never tested.
    $cveFail    = [int]$s.CveLookupFailedCount
    # Mono.Cecil could not be loaded; the flagship IL prover produced nothing this run.
    # Every Confirmed (IL) verdict class (crypto misuse, TLS accept-all, taint) is absent.
    $cecilMiss  = [int]$s.CecilMissingCount
    if (($unreadable + $depth + $reparse + $viewCap + $viewDedup + $budgetOut + $wmiFail +
         $packed + $bigBundle + $nativeOnly + $cveFail + $cecilMiss) -eq 0) { return }

    $parts = New-Object 'System.Collections.Generic.List[string]'
    if ($unreadable) { $parts.Add("$unreadable directory(ies) unreadable") }
    if ($depth)      { $parts.Add("$depth subtree(s) past the depth cap") }
    if ($reparse)    { $parts.Add("$reparse reparse point(s) not followed") }
    if ($viewCap)    { $parts.Add("$viewCap file(s) whose extracted text hit its ceiling") }
    if ($viewDedup)  { $parts.Add("$viewDedup file(s) read with repeated strings collapsed") }
    if ($budgetOut)  { $parts.Add("$budgetOut check(s) stopped early on the time budget") }
    if ($wmiFail)    { $parts.Add("$wmiFail WMI/CIM query(ies) failed or timed out") }
    if ($packed)     { $parts.Add("$packed packed/protected binary(ies) whose strings are opaque to static analysis") }
    if ($bigBundle)  { $parts.Add("$bigBundle single-file bundle(s) above the extractor size ceiling, so their assemblies were never carved") }
    if ($nativeOnly) { $parts.Add("$nativeOnly non-managed stack(s) the IL provers cannot read") }
    if ($cveFail)    { $parts.Add("$cveFail CVE lookup(s) could not reach OSV/NVD, so those components were never checked") }
    if ($cecilMiss)  { $parts.Add("Mono.Cecil unavailable, IL-prover verdicts (crypto, TLS callback, taint) were not produced") }
    $summary = $parts -join '; '

    $sample = New-Object 'System.Collections.Generic.List[string]'
    foreach ($p in @($s.UnreadableSample))     { $sample.Add("unreadable: $p") }
    foreach ($p in @($s.DepthSkippedSample))   { $sample.Add("depth-capped: $p") }
    foreach ($p in @($s.ReparseSkippedSample)) { $sample.Add("reparse: $p") }
    foreach ($p in @($s.ViewCappedSample))     { $sample.Add("text-capped: $p") }
    foreach ($p in @($s.ViewDedupedSample))    { $sample.Add("deduped: $p") }
    foreach ($p in @($s.BudgetStoppedSample)) { $sample.Add("budget-stopped: $p") }
    foreach ($p in @($s.WmiFailedSample))     { $sample.Add("wmi-failed: $p") }
    foreach ($p in @($s.PackedOpaqueSample))  { $sample.Add("packed: $p") }
    foreach ($p in @($s.BundleTooLargeSample)){ $sample.Add("bundle-too-large: $p") }
    foreach ($p in @($s.NativeOnlySample))    { $sample.Add("native-only: $p") }
    foreach ($p in @($s.CveLookupFailedSample)){ $sample.Add("cve-lookup-failed: $p") }
    foreach ($p in @($s.CecilMissingSample))  { $sample.Add("cecil-missing: $p") }
    $sampleTxt = (@($sample) | Select-Object -First 12) -join ' ; '

    # Unreadable directories and a capped text view are the classes that represent an
    # UNKNOWN. A depth cap, a refused reparse point and dedup are deliberate, bounded
    # decisions: dedup keeps every distinct string and loses only repeat counts.
    $sev = 'INFO'
    if ($unreadable -gt 0 -or $viewCap -gt 0 -or $budgetOut -gt 0 -or $wmiFail -gt 0) { $sev = 'LOW' }
    # A packed binary or a skipped bundle invalidates a whole FAMILY of results rather than
    # leaving a gap in one subtree, so it outranks the classes above. The measured fact
    # backing this is the count itself: N binaries were confirmed packed, or N bundles were
    # confirmed above the ceiling. NativeOnly alone stays LOW, because a native target is a
    # correct and expected use of the tool rather than a degraded run of it -- the native
    # checks (PE hardening, unsafe CRT, imports) do apply and did run.
    if ($packed -gt 0 -or $bigBundle -gt 0 -or $cveFail -gt 0 -or $cecilMiss -gt 0) { $sev = 'MEDIUM' }
    elseif ($nativeOnly -gt 0 -and $sev -eq 'INFO') { $sev = 'LOW' }

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
    # Last, so it wins when several classes fired: this is the one that silently turns into a
    # false clean bill of health for an entire attack surface rather than a partial result.
    if ($wmiFail -gt 0) {
        $advice = ('A WMI/CIM query failed or hit its 30s timeout. Every check that reads WMI ' +
            '(services, unquoted paths, service binary ACLs, WMI persistence, process owners, ' +
            'child processes) returns ZERO findings on that failure, which looks exactly like a ' +
            'clean result. Treat the service and persistence surface as UNTESTED for this run. ' +
            'Check the Winmgmt service is running, then re-run: winmgmt /verifyrepository')
    }
    if ($nativeOnly -gt 0) {
        $advice = ('The target is a non-managed stack, so the IL provers (crypto verdicts, TLS ' +
            'callback verdicts, TypeNameHandling, interprocedural taint) had no assembly to read ' +
            'and returned nothing. That is a capability limit of the managed layer, not a clean ' +
            'verdict. The native checks (PE hardening, unsafe CRT, imports/exports, packer, ' +
            'signature) DID run and their results stand. Cover the application logic with a native ' +
            'disassembler (Ghidra / IDA / radare2), or for a frozen Python target decompile the ' +
            'recovered bytecode and re-scan the sources.')
    }
    if ($cecilMiss -gt 0) {
        $advice = ('Mono.Cecil could not be loaded, so the flagship IL prover produced nothing ' +
            'this run: no Confirmed (IL) crypto verdicts, no accept-all TLS callback proofs, no ' +
            'interprocedural taint. Every check that emits Confirmed (IL) fell back to Inferred ' +
            'or emitted nothing at all, which is byte-for-byte what a clean managed target ' +
            'looks like. Confirm the DLLs sit at TCPK\lib\Cecil\Mono.Cecil.dll (they ship ' +
            'with the module), or install ILSpy which is checked as a fallback. Then re-run.')
    }
    # These two are last, so they win when several classes fired. Both mean the checks ran to
    # completion against bytes that are not the application, which is the failure mode most
    # easily mistaken for a clean result.
    if ($bigBundle -gt 0) {
        $advice = ('A .NET single-file apphost was larger than the extractor ceiling, so its ' +
            'bundled assemblies were never carved and never existed on disk for the static ' +
            'checks to read. The managed attack surface of that target is ABSENT from this ' +
            'audit, not clean. Re-run with a higher ceiling, or extract the bundle yourself ' +
            'and point the audit at the extracted folder: Expand-TcpkSingleFile -Path <exe> ' +
            '-OutDir <dir>, then run the audit against <dir>.')
    }
    if ($cveFail -gt 0) {
        $advice = ('The CVE lookup could not reach OSV or NVD, so the components it was going to ' +
            'query were never checked against any vulnerability source. TCPK ships NO offline CVE ' +
            'database, so there was nothing to fall back to: the dependency and supply-chain ' +
            'surface is UNTESTED for this run, not clean. A report with no dependency CVEs after ' +
            'a failed lookup looks identical to one for an application with no vulnerable ' +
            'packages. Re-run with network access to api.osv.dev and services.nvd.nist.gov. If ' +
            'NVD rate-limiting is the cause, set an NVD_API_KEY environment variable, which ' +
            'raises the limit from about 5 to 50 requests per 30 seconds.')
    }
    if ($packed -gt 0) {
        $advice = ('A packer or protector was confirmed on the target. Its strings and code are ' +
            'compressed or encrypted until it runs, so the secret, endpoint, callsite, entropy ' +
            'and string checks read the packer stub rather than the application. A low or zero ' +
            'finding count from those checks on this target is NOT evidence that it is clean, ' +
            'because they never saw the real bytes. Unpack first, then re-run the audit against ' +
            'the unpacked copy (for UPX, re-run with -Unpack; for a commercial protector, dump ' +
            'the process image at runtime). Read the packer.detected finding for which protector.')
    }

    # Lead the title with the condition that invalidates results, not with whichever class
    # happened to be counted first. A reader who sees only the title must still learn that
    # the static results for this target cannot be trusted.
    $title = "Scan coverage was incomplete: $summary"
    if ($nativeOnly -gt 0) { $title = "Static results are PARTIAL: non-managed target, IL analysis unavailable -- $summary" }
    if ($cecilMiss -gt 0)  { $title = "IL prover was NOT LOADED: Mono.Cecil missing, every Confirmed (IL) verdict absent -- $summary" }
    if ($bigBundle -gt 0)  { $title = "Static results are INCOMPLETE: single-file bundle skipped for size, managed assemblies never scanned -- $summary" }
    if ($cveFail -gt 0)    { $title = "Dependency CVE surface was NOT tested: the CVE lookup could not reach OSV/NVD -- $summary" }
    if ($packed -gt 0)     { $title = "Static results are UNRELIABLE: target is packed, text-level checks never saw the real code -- $summary" }

    New-TcpkFinding -Module 'discovery' -RuleId 'scan.incomplete-coverage' `
        -Severity $sev -Confidence 'Confirmed' `
        -Title $title `
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
            'application. Three of the classes counted here go further than a gap in one ' +
            'subtree: a packed binary, a single-file bundle above the extractor ceiling, and a ' +
            'non-managed stack all let every check run to completion against bytes that are not ' +
            'the application code. Those checks then report few or zero findings, which is ' +
            'identical to what a genuinely clean target produces, so where any of them is ' +
            'counted above, read the affected results as NOT YET EXAMINED rather than clean.') `
        -Fix $advice
}
