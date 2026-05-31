#requires -Version 5.1

# TCPK module entry point.
# Loads class definitions, private helpers, and public cmdlets in order.
# Exports only Public cmdlets; Private helpers stay internal.

# Note: deliberately NOT using Set-StrictMode here.
# Audit cmdlets must degrade gracefully on a single missing property
# (CIM/WMI, registry, Get-AppxPackage results vary by Windows build).
# Individual cmdlets enable Set-StrictMode locally if they need it.

$script:TcpkRoot = $PSScriptRoot

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
