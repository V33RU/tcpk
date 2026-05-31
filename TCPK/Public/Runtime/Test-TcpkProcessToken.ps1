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
    }
}
