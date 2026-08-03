#requires -Version 5.1

# TCPK module entry point.
# Loads class definitions, private helpers, and public cmdlets in order.
# Exports only Public cmdlets; Private helpers stay internal.

# Note: deliberately NOT using Set-StrictMode here.
# Audit cmdlets must degrade gracefully on a single missing property
# (CIM/WMI, registry, Get-AppxPackage results vary by Windows build).
# Individual cmdlets enable Set-StrictMode locally if they need it.

$script:TcpkRoot = $PSScriptRoot

# --- runaway-regex seatbelt -----------------------------------------------------------------
# Give every regex constructed in THIS runspace a default match timeout, so a single match that
# will never terminate in useful time throws RegexMatchTimeoutException instead of pegging a
# core indefinitely. Must run before any regex is constructed, hence module load, in whatever
# runspace imports TCPK (CLI, the WinForms GUI, the web-UI Start-Job worker).
#
# THIS IS A SEATBELT, NOT THE FIX, and the distinction matters. An audit that wedged for hours
# was measured to be aggregate LINEAR work, not catastrophic backtracking: a 212 MB binary
# decodes to ~445 M characters across the three views, Test-TcpkSecrets runs 41 rules over each,
# and every rule's cheap pre-filter is String.IndexOf with OrdinalIgnoreCase -- which on .NET
# Framework goes through NLS collation rather than a byte compare. That is ~18 billion character
# comparisons for one file, with no single match anywhere near the timeout. The real fix is
# _StringExtractor.ps1, which cuts the matched text to the printable runs (typically 2-5% of the
# file). This timeout only catches the different, rarer failure where one pattern genuinely
# never returns.
#
# 60s, not 15s: a legitimate Matches() sweep over a large view can take tens of seconds, and a
# timeout that fires on healthy work is worse than none. Invoke-TcpkAudit's _RunCheck collects a
# check's output with `$r = & $Block`, so an escaping exception discards EVERY finding that check
# already produced -- a timeout on file 400 of 900 would throw away files 1-399 too. Checks that
# loop over files therefore catch RegexMatchTimeoutException per file (see Test-TcpkSecrets) and
# keep going; this default is the backstop for everything else.
try {
    if (-not [AppDomain]::CurrentDomain.GetData('REGEX_DEFAULT_MATCH_TIMEOUT')) {
        [AppDomain]::CurrentDomain.SetData('REGEX_DEFAULT_MATCH_TIMEOUT', [TimeSpan]::FromSeconds(60))
    }
} catch { }

# Authenticode cmdlets (Get-AuthenticodeSignature) live in Microsoft.PowerShell.Security.
# In some runspaces -- notably the web UI's background Start-Job -- that module does NOT
# auto-load on first use and throws "command was found in the module ... but the module
# could not be loaded". Import it eagerly here so every signing/integrity check that loads
# TCPK has it available. Best-effort: if the host genuinely cannot load it, the individual
# checks degrade gracefully (see Get-TcpkAuthenticode).
try { Import-Module Microsoft.PowerShell.Security -ErrorAction SilentlyContinue } catch { }

# Exploit-bucket gate. Off by default. Enable-TcpkExploit flips this on
# for the session; each exploit cmdlet calls Assert-TcpkExploitEnabled at entry.
$script:TcpkExploitEnabled = $false

# Cloud-LLM gate. Off by default (local Ollama only). Enable-TcpkLlmCloud
# flips this on for the session.
$script:TcpkLlmCloudEnabled = $false

function Get-TcpkLoadOrder {
    [CmdletBinding()] param([string]$Subfolder)
    $path = Join-Path $script:TcpkRoot $Subfolder
    if (-not (Test-Path $path)) { return @() }
    Get-ChildItem -LiteralPath $path -Recurse -File -Filter '*.ps1' -ErrorAction SilentlyContinue |
        Sort-Object FullName
}

# 1) Class definitions (must load first so other files can reference [TCPK.Finding])
foreach ($f in (Get-TcpkLoadOrder 'Classes')) {
    . $f.FullName
}

# 2) Private helpers (underscore-prefixed, not exported)
foreach ($f in (Get-TcpkLoadOrder 'Private')) {
    . $f.FullName
}

# 3) Public cmdlets (one .ps1 per cmdlet)
$publicFns = @()
foreach ($f in (Get-TcpkLoadOrder 'Public')) {
    . $f.FullName
    # Convention: the cmdlet name equals the file's BaseName (Test-TcpkPeMitigations.ps1
    # defines function Test-TcpkPeMitigations).
    $publicFns += $f.BaseName
}

# Exploit cmdlets ARE exported (so users see them via Get-Command) but each one
# calls Assert-TcpkExploitEnabled at entry. The gate is opt-in via Enable-TcpkExploit.
$exploitFns = (Get-TcpkLoadOrder 'Public\Exploit').BaseName

if ($publicFns.Count -gt 0) {
    Export-ModuleMember -Function $publicFns
}

# Print a quiet load banner only in verbose mode.
Write-Verbose ("TCPK loaded: {0} public cmdlets (incl. {1} gated exploit cmdlets), {2} private helpers." -f `
    $publicFns.Count, $exploitFns.Count, (Get-TcpkLoadOrder 'Private').Count)
