function Test-TcpkChildProcesses {
<#
.SYNOPSIS
    E14. Direct child processes spawned by the target.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ParameterSetName='ByName')][string]$ProcessName,
        [Parameter(Mandatory, ParameterSetName='ById')][int]$ProcessId
    )

    if (-not (Assert-TcpkWindows 'Test-TcpkChildProcesses')) { return }
    $procs = if ($PSCmdlet.ParameterSetName -eq 'ByName') {
        Get-TcpkProcess -ProcessName $ProcessName
    } else {
        Get-TcpkProcess -ProcessId $ProcessId
    }
    foreach ($p in $procs) {
        $kids = Get-CimInstance Win32_Process -Filter "ParentProcessId=$($p.Id)" -ErrorAction SilentlyContinue
        if (-not $kids) { continue }
        foreach ($k in $kids) {
            New-TcpkFinding -Module 'runtime' -RuleId 'process.child' `
                -Severity 'INFO' -Confidence 'Confirmed' `
                -Title "Child of $($p.Name) (PID $($p.Id)): $($k.Name) (PID $($k.ProcessId))" `
                -File $k.Name -Evidence ($k.CommandLine -as [string]) `
                -Description 'Inventory of helper / IPC / launched processes -- each is its own attack surface.'
        }
    }
}
