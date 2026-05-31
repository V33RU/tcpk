function Test-TcpkListeningPorts {
<#
.SYNOPSIS
    E03. TCP listeners + UDP endpoints owned by the process.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ParameterSetName='ByName')][string]$ProcessName,
        [Parameter(Mandatory, ParameterSetName='ById')][int]$ProcessId
    )

    if (-not (Assert-TcpkWindows 'Test-TcpkListeningPorts')) { return }
    $procs = if ($PSCmdlet.ParameterSetName -eq 'ByName') {
        Get-TcpkProcess -ProcessName $ProcessName
    } else {
        Get-TcpkProcess -ProcessId $ProcessId
    }

    foreach ($p in $procs) {
        # TCP listeners
        foreach ($c in (Get-NetTCPConnection -OwningProcess $p.Id -State Listen -ErrorAction SilentlyContinue)) {
            $wild = $c.LocalAddress -in '0.0.0.0','::'
            $lb   = $c.LocalAddress -in '127.0.0.1','::1'
            $sev = if ($wild) { 'HIGH' } elseif ($lb) { 'MEDIUM' } else { 'LOW' }
            New-TcpkFinding -Module 'runtime' -RuleId 'ports.tcp-listening' `
                -Severity $sev -Confidence 'Confirmed' `
                -Title "$($p.Name) listening TCP on $($c.LocalAddress):$($c.LocalPort)" `
                -File "$($p.Name) (PID $($p.Id))" `
                -Evidence "$($c.LocalAddress):$($c.LocalPort)" `
                -Cwe @('CWE-668') `
                -Fix 'Verify auth on this listener. Bind to 127.0.0.1 only if local IPC is intended.'
        }
        # UDP endpoints
        foreach ($u in (Get-NetUDPEndpoint -OwningProcess $p.Id -ErrorAction SilentlyContinue)) {
            $wild = $u.LocalAddress -in '0.0.0.0','::'
            $sev = if ($wild) { 'MEDIUM' } else { 'LOW' }
            New-TcpkFinding -Module 'runtime' -RuleId 'ports.udp-endpoint' `
                -Severity $sev -Confidence 'Confirmed' `
                -Title "$($p.Name) UDP endpoint on $($u.LocalAddress):$($u.LocalPort)" `
                -File "$($p.Name) (PID $($p.Id))" `
                -Evidence "$($u.LocalAddress):$($u.LocalPort)" -Cwe @('CWE-668')
        }
    }
}
