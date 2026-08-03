function Test-TcpkStrings {
<#
.SYNOPSIS
    A06. Strings extraction with summary classification.

.DESCRIPTION
    Per-binary summary of interesting strings (URLs, paths, IPs) found
    across UTF-8 and UTF-16LE views. Returns INFO findings only -- this is
    a triage aid, not a vulnerability check. Use Test-TcpkSecrets /
    Test-TcpkEndpoints / Test-TcpkCallsites for the actual rule-based scans.

.PARAMETER Path
    File or directory.

.PARAMETER FirstParty
    Skip framework-prefix files (Microsoft.*, System.*, etc.) to focus on
    first-party / vendor-authored DLLs.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [switch]$FirstParty
    )

    $urlRx  = [regex]'https?://[A-Za-z0-9./?_=&%:#@~+\-]+'
    $winRx  = [regex]'[A-Za-z]:\\[A-Za-z0-9_.\-\\ ]{4,}\.(dll|exe|sys|config|json|xml|txt|log)'
    $ipRx   = [regex]'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'

    $scanned = 0
    $skippedBudget = 0
    $peList = @(Get-TcpkPeFiles -Path $Path)
    foreach ($pe in $peList) {
        if ($FirstParty -and (Test-TcpkIsFrameworkFile $pe.Name)) { continue }

        # Cooperative budget. This loop is the single most expensive thing in the audit: each
        # iteration concatenates three extracted views into one string (up to ~144 MB) and
        # runs three regexes over it. At ~20s per binary that is fine for one DLL and hours
        # for a browser install with hundreds. Stop cleanly and report rather than run on.
        if (Test-TcpkCheckBudgetExpired) { $skippedBudget = $peList.Count - $scanned; break }
        $scanned++

        $text = Read-TcpkAllText -Path $pe.FullName
        if (-not $text) { continue }

        $urls = ([regex]::Matches($text, $urlRx)).Count
        $paths = ([regex]::Matches($text, $winRx)).Count
        $ips   = ([regex]::Matches($text, $ipRx)).Count
        if (($urls + $paths + $ips) -eq 0) { continue }

        New-TcpkFinding -Module 'static' -RuleId 'strings.summary' `
            -Severity 'INFO' -Confidence 'Confirmed' `
            -Title "$($pe.Name) contains URLs/paths/IPs (urls=$urls, paths=$paths, ips=$ips)" `
            -File $pe.FullName `
            -Evidence "urls=$urls paths=$paths ips=$ips" `
            -Description 'Triage aid. See Test-TcpkEndpoints for non-prod classification and Test-TcpkSecrets for token-shaped strings.'
    }

    if ($skippedBudget -gt 0) {
        New-TcpkSkippedFinding -RuleId 'strings.budget-exhausted' `
            -Title "String summary stopped early: $skippedBudget of $($peList.Count) binaries not examined" `
            -Reason ("This check hit its wall-clock budget after $scanned binaries. The remaining " +
                "$skippedBudget were NOT examined, so their URL / path / IP counts are unknown rather " +
                "than zero. Re-run against a narrower -Path, or raise the budget, to cover them.")
    }
}
