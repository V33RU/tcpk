function Test-TcpkIfeoHijack {
<#
.SYNOPSIS
    C11. Image File Execution Options debugger-key hijack.

.DESCRIPTION
    Any executable name under
      HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<exe>
    with a 'Debugger' value will be replaced by that debugger at launch.
    Legitimate uses exist (gflags). Unexpected entries naming the target
    binary are HIGH severity.

.PARAMETER NameLike
    Substring to match against the .exe key name (default '*').

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([string]$NameLike = '*')

    if (-not (Assert-TcpkWindows 'Test-TcpkIfeoHijack')) { return }

    $ifeo = 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
    if (-not (Test-Path $ifeo)) { return }

    foreach ($k in (Get-ChildItem $ifeo -ErrorAction SilentlyContinue)) {
        if ($NameLike -ne '*' -and $k.PSChildName -notlike "*$NameLike*") { continue }
        $debugger = (Get-ItemProperty -LiteralPath $k.PSPath -ErrorAction SilentlyContinue).Debugger
        if (-not $debugger) { continue }

        New-TcpkFinding -Module 'os' -RuleId 'ifeo.debugger-hijack' `
            -Severity 'HIGH' -Confidence 'Confirmed' `
            -Title "IFEO debugger hijack: $($k.PSChildName) -> $debugger" `
            -File $k.PSPath -Evidence $debugger `
            -Cwe @('CWE-732','CWE-426') `
            -Description 'The OS replaces the named executable with the configured Debugger at launch. Unexpected entries are persistence / privesc primitives.' `
            -Fix 'Confirm legitimacy. Remove the Debugger value if unintended.'
    }
}
