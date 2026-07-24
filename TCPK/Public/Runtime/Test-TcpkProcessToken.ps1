function Test-TcpkProcessToken {
<#
.SYNOPSIS
    E13. Process token owner / integrity level / impactful privileges.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ParameterSetName='ByName')][string]$ProcessName,
        [Parameter(Mandatory, ParameterSetName='ById')][int]$ProcessId
    )

    if (-not (Assert-TcpkWindows 'Test-TcpkProcessToken')) { return }
    $procs = if ($PSCmdlet.ParameterSetName -eq 'ByName') {
        Get-TcpkProcess -ProcessName $ProcessName
    } else {
        Get-TcpkProcess -ProcessId $ProcessId
    }

    foreach ($p in $procs) {
        # Owner via WMI
        $owner = $null
        try {
            $wp = Get-CimInstance Win32_Process -Filter "ProcessId=$($p.Id)" -ErrorAction Stop
            $ownerInfo = Invoke-CimMethod -InputObject $wp -MethodName GetOwner -ErrorAction Stop
            if ($ownerInfo.ReturnValue -eq 0) {
                $owner = "$($ownerInfo.Domain)\$($ownerInfo.User)"
            }
        } catch { }

        $ownerDisplay = if ($owner) { $owner } else { '(unknown)' }
        New-TcpkFinding -Module 'runtime' -RuleId 'process.identity' `
            -Severity 'INFO' -Confidence 'Confirmed' `
            -Title "$($p.Name) running as: $ownerDisplay" `
            -File "$($p.Name) (PID $($p.Id))" `
            -Evidence "Owner=$owner Start=$($p.StartTime)"

        # Flag SYSTEM-running interactive processes (rare and worth noting)
        if ($owner -eq 'NT AUTHORITY\SYSTEM') {
            New-TcpkFinding -Module 'runtime' -RuleId 'process.running-as-system' `
                -Severity 'HIGH' -Confidence 'Confirmed' `
                -Title "$($p.Name) is running as SYSTEM" `
                -File "$($p.Name) (PID $($p.Id))" `
                -Cwe @('CWE-250') `
                -Description 'SYSTEM is the highest local privilege; any code-exec primitive in this process becomes a full local compromise.'
        }

        # Integrity level (read directly from the live token).
        $rid = Get-TcpkProcessIntegrityRid -ProcessId $p.Id
        if ($rid -ge 0) {
            $intLabel = Get-TcpkIntegrityLabel $rid
            New-TcpkFinding -Module 'runtime' -RuleId 'process.integrity-level' `
                -Severity 'INFO' -Confidence 'Confirmed' `
                -Title "$($p.Name) runs at $intLabel integrity" `
                -File "$($p.Name) (PID $($p.Id))" `
                -Evidence ("Integrity RID=0x{0:X}" -f $rid)
        }

        # Impactful token privileges. A process can enable any privilege it
        # HOLDS via AdjustTokenPrivileges, so "present" is the capability; the
        # finding fires on privileges that are ENABLED in the live token (the
        # active LPE primitive) and lists any present-but-disabled ones for
        # context. This avoids flagging the ~20 dormant privileges every
        # elevated process carries.
        $privRaw = Get-TcpkProcessPrivilegeString -ProcessId $p.Id
        if ($privRaw) {
            $split = Split-TcpkImpactfulPrivileges -PrivRaw $privRaw
            if ($split.Enabled.Count) {
                $sev = if ($split.SawSystemGrade) { 'MEDIUM' } else { 'LOW' }
                $ev = "Enabled: $($split.Enabled -join ', ')"
                if ($split.Present.Count) { $ev += "  |  Present (can self-enable): $($split.Present -join ', ')" }
                New-TcpkFinding -Module 'runtime' -RuleId 'process.impactful-privileges' `
                    -Severity $sev -Confidence 'Confirmed' `
                    -Title "$($p.Name) holds impactful token privileges" `
                    -File "$($p.Name) (PID $($p.Id))" `
                    -Cwe @('CWE-250','CWE-269') `
                    -Evidence $ev `
                    -Description ('The process token has privileges that turn a code-exec primitive into local escalation. ' +
                        'SeImpersonate / SeAssignPrimaryToken / SeTcb / SeCreateToken lead to SYSTEM (potato-style); ' +
                        'SeDebug / SeLoadDriver / SeBackup / SeRestore / SeTakeOwnership grant cross-process or filesystem control.')
            }
        }
    }
}
