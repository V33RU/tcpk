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
    param([string]$NameLike = '*')

    if (-not (Assert-TcpkWindows 'Test-TcpkProtocolHandlers')) { return }

    $hkcr = 'Registry::HKEY_CLASSES_ROOT'

    # Performance: if the caller supplied a specific NameLike, only check
    # that key directly. Full HKCR enumeration takes minutes and is wasted
    # work for a per-product audit.
    if ($NameLike -ne '*') {
        $directKey = Join-Path $hkcr $NameLike
        if (-not (Test-Path -LiteralPath $directKey)) {
            # Fall back to a substring scan but only across top-level keys, not their children.
            $candidates = Get-ChildItem $hkcr -ErrorAction SilentlyContinue |
                Where-Object { $_.PSChildName -like "*$NameLike*" }
        } else {
            $candidates = @(Get-Item -LiteralPath $directKey -ErrorAction SilentlyContinue)
        }
    } else {
        $candidates = Get-ChildItem $hkcr -ErrorAction SilentlyContinue
    }

    foreach ($k in $candidates) {
        if (-not $k) { continue }
        if ((Get-ItemProperty -LiteralPath $k.PSPath -Name 'URL Protocol' -ErrorAction SilentlyContinue) -eq $null) { continue }
        $scheme = $k.PSChildName
        $cmdPath = Join-Path $k.PSPath 'shell\open\command'
        $cmd = (Get-ItemProperty -LiteralPath $cmdPath -ErrorAction SilentlyContinue).'(default)'
        if (-not $cmd) { continue }
        if (-not ($NameLike -eq '*' -or $cmd -like "*$NameLike*" -or $scheme -like "*$NameLike*")) { continue }

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
