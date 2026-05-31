function Test-TcpkAutoStart {
<#
.SYNOPSIS
    C04. Autostart entries (Run / RunOnce keys + scheduled tasks).

.DESCRIPTION
    Surveys per-machine and per-user Run/RunOnce registry keys plus scheduled
    tasks matching -NameLike. Each entry is INFO severity (persistence is
    expected for some apps; this is a hygiene survey).

.PARAMETER NameLike
    Substring to match (default '*' matches all entries).

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([string]$NameLike = '*')

    if (-not (Assert-TcpkWindows 'Test-TcpkAutoStart')) { return }

    $keys = @(
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'
    )
    foreach ($k in $keys) {
        try { $props = Get-ItemProperty -Path $k -ErrorAction SilentlyContinue } catch { continue }
        if (-not $props) { continue }
        foreach ($p in $props.PSObject.Properties) {
            if ($p.Name.StartsWith('PS')) { continue }
            if ($NameLike -eq '*' -or $p.Value -like "*$NameLike*" -or $p.Name -like "*$NameLike*") {
                New-TcpkFinding -Module 'os' -RuleId 'autostart.run-key' `
                    -Severity 'INFO' -Confidence 'Confirmed' `
                    -Title "Autostart: $($p.Name) = $($p.Value)" `
                    -File $k -Evidence $p.Value -Cwe @('CWE-426')
            }
        }
    }
    # Use schtasks.exe rather than Get-ScheduledTask -- CIM-backed Get-ScheduledTask
    # is dramatically slower on systems with many tasks (corporate AV / management tasks).
    try {
        $csv = & schtasks.exe /query /fo CSV /nh 2>$null
        if ($csv) {
            foreach ($line in $csv) {
                $cells = $line -split '","'
                if ($cells.Count -lt 2) { continue }
                $taskName = $cells[0].TrimStart('"')
                if ($NameLike -ne '*' -and $taskName -notlike "*$NameLike*") { continue }
                $task = $cells[1]
                New-TcpkFinding -Module 'os' -RuleId 'autostart.scheduled-task' `
                    -Severity 'INFO' -Confidence 'Confirmed' `
                    -Title "Scheduled task: $taskName" `
                    -File $taskName -Evidence $task
            }
        }
    } catch { }
}
