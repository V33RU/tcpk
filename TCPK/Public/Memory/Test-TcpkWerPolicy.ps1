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
    if (-not (Test-Path $wer)) {
        New-TcpkFinding -Module 'memory' -RuleId 'wer.default-policy' `
            -Severity 'MEDIUM' -Confidence 'Confirmed' `
            -Title 'WER LocalDumps policy not set -- defaults apply' `
            -File 'HKLM:\...\Windows Error Reporting\LocalDumps' `
            -Evidence 'Key not present' `
            -Cwe @('CWE-528') `
            -Description 'Default WER writes full-memory minidumps for unhandled exceptions into %LOCALAPPDATA%\CrashDumps with user-readable ACLs.' `
            -Fix 'Set DumpType=1 (MiniDumpNormal) under HKLM\...\LocalDumps\<exe-name> to limit dump scope, or register a custom SetUnhandledExceptionFilter that writes a sanitized triage log.'
        return
    }

    # Global policy
    $g = Get-ItemProperty -Path $wer -ErrorAction SilentlyContinue
    if ($g) {
        $dt = $g.DumpType
        New-TcpkFinding -Module 'memory' -RuleId 'wer.global-policy' `
            -Severity 'INFO' -Confidence 'Confirmed' `
            -Title "WER LocalDumps global policy: DumpType=$dt DumpFolder=$($g.DumpFolder)" `
            -File $wer `
            -Evidence "DumpType=$dt DumpCount=$($g.DumpCount) DumpFolder=$($g.DumpFolder)"
    }

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
