function Test-TcpkWerPolicy {
<#
.SYNOPSIS
    I01. Windows Error Reporting LocalDumps policy.

.DESCRIPTION
    Reads HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps
    and reports the PER-APP subkey for the target executable, if one exists.

    SCOPE NOTE. Local dump collection is NOT enabled by default: the LocalDumps
    key is absent on a stock Windows install and creating it requires admin
    (Microsoft, "Collecting User-Mode Dumps"). When it is absent this check
    emits nothing, which is correct -- an absent key is machine posture chosen
    by the machine owner, not a defect in the audited application, and the
    vendor cannot fix it.

    What IS attributable to the application is a per-app subkey named for its
    executable, which an installer may create. DumpType=2 means a FULL process
    memory dump, so any secret resident at crash time lands on disk.

    For crash-artifact exposure that exists regardless of this policy, see
    Test-TcpkWerExposure. For Electron targets, crash handling is Crashpad,
    not WER, and this check does not apply.

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
