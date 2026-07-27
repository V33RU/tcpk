function Test-TcpkWerPolicy {
<#
.SYNOPSIS
    I01. Windows Error Reporting LocalDumps policy.

.DESCRIPTION
    Reads HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps
    and per-app subkeys. Default WER writes full-memory dumps to a
    user-readable %LOCALAPPDATA%\CrashDumps -- any in-memory secret at crash
    time becomes locally exfiltratable.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([string]$ExeName)

    if (-not (Assert-TcpkWindows 'Test-TcpkWerPolicy')) { return }

    $wer = 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps'
    if (-not (Test-Path $wer)) { return }
    if (-not $ExeName) { return }

    if ($ExeName) {
        $perApp = Join-Path $wer $ExeName
        if (Test-Path $perApp) {
            $a = Get-ItemProperty -Path $perApp -ErrorAction SilentlyContinue
            New-TcpkFinding -Module 'memory' -RuleId 'wer.per-app-policy' `
                -Severity 'INFO' -Confidence 'Confirmed' `
                -Title "WER per-app policy for $ExeName" `
                -File $perApp `
                -Evidence "DumpType=$($a.DumpType) DumpFolder=$($a.DumpFolder)"
        }
    }
}
