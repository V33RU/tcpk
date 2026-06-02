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

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([string[]]$NameLike = @())

    if (-not (Assert-TcpkWindows 'Test-TcpkProtocolHandlers')) { return }

    $hkcr = 'Registry::HKEY_CLASSES_ROOT'
    $terms = Get-TcpkNameTerms -NameLike $NameLike

    # Performance: enumerate HKCR top-level once. When terms are supplied, restrict
    # candidates to keys whose scheme name matches a term; otherwise survey all.
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
        if ($terms.Count -and -not ((Test-TcpkTermMatch -Text $cmd -Terms $terms) -or (Test-TcpkTermMatch -Text $scheme -Terms $terms))) { continue }

        $sev = if ($cmd -match '%1[^"]') { 'HIGH' } else { 'MEDIUM' }
        New-TcpkFinding -Module 'os' -RuleId 'protocol-handler' `
            -Severity $sev -Confidence 'Confirmed' `
            -Title "Protocol handler: ${scheme}:// -> $cmd" `
            -File "HKCR:\$scheme" -Evidence $cmd `
            -Cwe @('CWE-77','CWE-88') `
            -Description 'Unquoted %1 hands the entire URI to argv, enabling command-line injection in the handler.' `
            -Fix 'Quote %1 (`"%1`") and validate scheme + arguments before acting.'
    }
}
