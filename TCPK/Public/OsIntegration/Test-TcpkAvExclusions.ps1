function Test-TcpkAvExclusions {
<#
.SYNOPSIS
    C17. Microsoft Defender exclusions attributable to the app.

.DESCRIPTION
    An installer that adds its own path/process/extension to Defender's
    exclusion list creates an AV blind spot: malware dropped into that path (or
    renamed to that process) runs unscanned. This check reads Get-MpPreference
    and flags exclusions that match -NameLike or -Path; all other custom
    exclusions are reported once as INFO for situational awareness.

.PARAMETER NameLike
    Vendor/package substring.

.PARAMETER Path
    Optional install dir to match path exclusions.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param(
        [string]$NameLike = '',
        [string]$Path
    )

    if (-not (Assert-TcpkWindows 'Test-TcpkAvExclusions')) { return }
    if (-not (Get-Command Get-MpPreference -ErrorAction SilentlyContinue)) { return }

    $mp = $null
    try { $mp = Get-MpPreference -ErrorAction Stop } catch { return }
    if (-not $mp) { return }

    # Non-admin sessions get a sentinel string instead of the real list.
    $allItems = @($mp.ExclusionPath) + @($mp.ExclusionProcess) + @($mp.ExclusionExtension)
    if ($allItems | Where-Object { $_ -match '(?i)must be an administrator|^N/A:' }) {
        New-TcpkFinding -Module 'os' -RuleId 'avexclusion.not-readable' `
            -Severity 'INFO' -Confidence 'Skipped' `
            -Title 'Defender exclusions require elevation to read' `
            -File 'Get-MpPreference' -Evidence 'Re-run elevated to enumerate Defender exclusions.'
        return
    }

    $sets = @(
        @{ Name='path';      Items=@($mp.ExclusionPath);      Cwe='CWE-693' },
        @{ Name='process';   Items=@($mp.ExclusionProcess);   Cwe='CWE-693' },
        @{ Name='extension'; Items=@($mp.ExclusionExtension); Cwe='CWE-693' }
    )

    foreach ($s in $sets) {
        foreach ($item in $s.Items) {
            if (-not $item) { continue }
            $mine = $false
            if ($NameLike -and $item -like "*$NameLike*") { $mine = $true }
            if ($Path -and $s.Name -eq 'path' -and $item -like "$Path*") { $mine = $true }

            if ($mine) {
                New-TcpkFinding -Module 'os' -RuleId "avexclusion.$($s.Name)" `
                    -Severity 'HIGH' -Confidence 'Confirmed' `
                    -Title "Defender $($s.Name) exclusion attributable to app: $item" `
                    -File 'Get-MpPreference' -Evidence "Exclusion$($s.Name): $item" -Cwe @($s.Cwe) `
                    -Description 'The app excludes its own path/process/extension from Defender scanning. Anything an attacker can write into that location (or name to that process/extension) executes without AV inspection -- a persistence and bypass primitive.' `
                    -Fix 'Remove the exclusion. If a real-time-scan performance issue drove it, fix the root cause instead of excluding the path.'
            } else {
                New-TcpkFinding -Module 'os' -RuleId "avexclusion.other-$($s.Name)" `
                    -Severity 'INFO' -Confidence 'Confirmed' `
                    -Title "Defender $($s.Name) exclusion present: $item" `
                    -File 'Get-MpPreference' -Evidence $item `
                    -Description 'A Defender exclusion exists (not clearly attributable to this app). Listed for awareness.'
            }
        }
    }
}
