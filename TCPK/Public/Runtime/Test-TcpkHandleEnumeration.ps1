function Test-TcpkHandleEnumeration {
<#
.SYNOPSIS
    E11. Open handle counts and types for the process (triage summary).

.DESCRIPTION
    Reports the total open handle count plus a few diagnostic counters
    (threads, working set). Detailed per-handle enumeration requires
    sysinternals handle.exe, which is outside the portable surface; this
    cmdlet surfaces the summary and suggests the deep tool when needed.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ParameterSetName='ByName')][string]$ProcessName,
        [Parameter(Mandatory, ParameterSetName='ById')][int]$ProcessId
    )

    if (-not (Assert-TcpkWindows 'Test-TcpkHandleEnumeration')) { return }
    $procs = if ($PSCmdlet.ParameterSetName -eq 'ByName') {
        Get-TcpkProcess -ProcessName $ProcessName
    } else {
        Get-TcpkProcess -ProcessId $ProcessId
    }
    foreach ($p in $procs) {
        New-TcpkFinding -Module 'runtime' -RuleId 'handles.summary' `
            -Severity 'INFO' -Confidence 'Confirmed' `
            -Title "$($p.Name) handles=$($p.HandleCount) threads=$($p.Threads.Count) ws=$([int]($p.WorkingSet64/1MB))MB" `
            -File "$($p.Name) (PID $($p.Id))" `
            -Description 'For detailed per-handle inspection use SysInternals handle.exe -p <pid>.'
    }
}
