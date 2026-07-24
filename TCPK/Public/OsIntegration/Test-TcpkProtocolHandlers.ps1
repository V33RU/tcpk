function Test-TcpkProtocolHandlers {
<#
.SYNOPSIS
    C07. HKCR protocol handlers (system-wide URI scheme registrations).

.DESCRIPTION
    Enumerates HKCR\* keys with a 'URL Protocol' value (the marker for a
    URI scheme handler) and emits a finding per match. Unquoted %1 in the
    shell\open\command default = argv injection / command-line injection
    primitive (CVE class).

.PARAMETER NameLike
    Substring to match against the scheme or command (default '*').

.PARAMETER TargetPath
    Install directory of the app under audit. When supplied, only handlers whose
    command executable resolves UNDER this path are reported -- so a machine-wide
    scheme registered by some other app (mailto:, ms-*, ...) is not attributed to
    the target. Omit to survey by -NameLike terms instead.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([string[]]$NameLike = @(), [string]$TargetPath)

    if (-not (Assert-TcpkWindows 'Test-TcpkProtocolHandlers')) { return }

    $hkcr = 'Registry::HKEY_CLASSES_ROOT'
    $terms = Get-TcpkNameTerms -NameLike $NameLike

    # Performance: enumerate HKCR top-level once. When terms are supplied, restrict
    # candidates to keys whose scheme name matches a term BEFORE the per-key Get-ItemProperty
    # (HKCR has thousands of keys; probing each for 'URL Protocol' is the 30s+ scan). The
    # -TargetPath check below is an additional ATTRIBUTION filter on the survivors, not a
    # replacement for this cheap name pre-filter.
    $candidates = Get-ChildItem $hkcr -ErrorAction SilentlyContinue
    if ($terms.Count) {
        $candidates = $candidates | Where-Object { Test-TcpkTermMatch -Text $_.PSChildName -Terms $terms }
    }

    foreach ($k in $candidates) {
        if (-not $k) { continue }
        if ((Get-ItemProperty -LiteralPath $k.PSPath -Name 'URL Protocol' -ErrorAction SilentlyContinue) -eq $null) { continue }
        $scheme = $k.PSChildName
        $cmdPath = Join-Path $k.PSPath 'shell\open\command'
        $cmd = (Get-ItemProperty -LiteralPath $cmdPath -ErrorAction SilentlyContinue).'(default)'
        if (-not $cmd) { continue }

        # Attribution: a handler belongs to the AUDITED app only if its command executable
        # lives under the target dir. Prefer the path check (precise); fall back to a term
        # match on the scheme/command when no target path is available.
        if ($TargetPath) {
            if (-not (Test-TcpkPathUnderTarget -Value $cmd -InstallDir $TargetPath)) { continue }
        } elseif ($terms.Count) {
            if (-not ((Test-TcpkTermMatch -Text $cmd -Terms $terms) -or (Test-TcpkTermMatch -Text $scheme -Terms $terms))) { continue }
        }

        $unquoted = ($cmd -match '%1[^"]' -or $cmd -match '%1\s*$')
        $sev = if ($unquoted) { 'HIGH' } else { 'MEDIUM' }
        $inj = if ($unquoted) {
            "The command passes %1 to argv UNQUOTED, so a crafted ${scheme}:// URL injects extra command-line arguments (argv / command-line injection)."
        } else {
            'The command quotes %1, but the whole URI is still attacker-controlled input.'
        }
        New-TcpkFinding -Module 'os' -RuleId 'protocol-handler' `
            -Severity $sev -Confidence 'Confirmed' `
            -Title "URI-activation handler: ${scheme}:// -> $cmd" `
            -File "HKCR:\$scheme" -Evidence $cmd `
            -Cwe @('CWE-77','CWE-88','CWE-939') `
            -Description ("The app registers the ${scheme}:// URI scheme, so any web page or document can deep-link into it (window.location='${scheme}://<payload>') and launch it with an attacker-controlled URI -- a REMOTE-TRIGGER entry point that fires without the user typing anything. $inj Treat the whole URI as untrusted: it must not choose a navigation target, host, file path, or command argument unchecked.") `
            -Fix 'Quote %1 ("%1"), then parse and allow-list the URI before acting; never route it straight into a navigation target / connection setting / file open / spawned process.'
    }
}
