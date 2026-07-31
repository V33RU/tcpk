function Test-TcpkProcessVirtualization {
<#
.SYNOPSIS
    E14. UAC file and registry virtualization state of a running process.

.DESCRIPTION
    UAC virtualization silently redirects a process's writes to protected locations
    into a per-user store:

        C:\Program Files\App\config.ini  ->  %LOCALAPPDATA%\VirtualStore\...
        HKLM\Software\App                ->  HKCU\Software\Classes\VirtualStore\...

    It exists as a compatibility shim for pre-Vista applications that assume they
    can write to their own install directory. Windows enables it only for 32-bit
    processes that do NOT declare a requestedExecutionLevel in their manifest.

    A modern application running virtualized is therefore a real posture finding,
    and one the vendor fixes in their manifest rather than the customer fixing on
    the box:

      * the app is unmanifested, so it also gets no other manifest-driven
        hardening
      * its configuration and any security-relevant state it believes it wrote to
        a protected location actually lives in a per-user, user-WRITABLE store
      * an integrity or licensing check that reads back what it wrote is reading
        attacker-controllable data

    Reports the enabled state, and separately the allowed-but-not-enabled state,
    which is the weaker signal that the token would permit it.

    Read-only: opens with PROCESS_QUERY_INFORMATION and reads TokenVirtualization*.

.PARAMETER ProcessName
    Name of the running process (no .exe).

.PARAMETER ProcessId
    Specific PID instead of resolving by name.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ParameterSetName='ByName')][string]$ProcessName,
        [Parameter(Mandatory, ParameterSetName='ById')][int]$ProcessId
    )

    if (-not (Assert-TcpkWindows 'Test-TcpkProcessVirtualization')) { return }
    if (-not ('Tcpk.ObjSec' -as [type])) {
        New-TcpkSkippedFinding -RuleId 'virtualization.unavailable' `
            -Title 'Token virtualization primitive unavailable' `
            -Reason 'Tcpk.ObjSec failed to compile.'
        return
    }

    $procs = if ($PSCmdlet.ParameterSetName -eq 'ByName') {
        Get-TcpkProcess -ProcessName $ProcessName
    } else {
        Get-TcpkProcess -ProcessId $ProcessId
    }

    foreach ($p in $procs) {
        $v = -1
        try { $v = [int][Tcpk.ObjSec]::GetVirtualization($p.Id) } catch { $v = -1 }
        if ($v -lt 0) {
            New-TcpkSkippedFinding -RuleId 'virtualization.unreadable' `
                -Title "Could not read virtualization state for $($p.Name) (PID $($p.Id))" `
                -Reason 'OpenProcessToken/GetTokenInformation denied (likely insufficient rights).'
            continue
        }

        $allowed = (($v -band 2) -ne 0)
        $enabled = (($v -band 1) -ne 0)

        if ($enabled) {
            New-TcpkFinding -Module 'runtime' -RuleId 'virtualization.enabled' `
                -Severity 'MEDIUM' -Confidence 'Confirmed' `
                -Title "$($p.Name) is running with UAC virtualization ENABLED" `
                -File "$($p.Name) (PID $($p.Id))" `
                -Evidence "TokenVirtualizationEnabled=1; TokenVirtualizationAllowed=$([int]$allowed)" `
                -Cwe @('CWE-276', 'CWE-732') `
                -Description ('Writes this process makes to Program Files or HKLM are silently ' +
                    'redirected into a per-user VirtualStore that the user can write to. Windows ' +
                    'only enables this for 32-bit processes with no requestedExecutionLevel in their ' +
                    'manifest, so the application is also unmanifested and gets none of the other ' +
                    'manifest-driven hardening. Any state the app believes it wrote to a protected ' +
                    'location is in fact user-controllable, which breaks integrity or licensing ' +
                    'checks that read back what they wrote.') `
                -Fix 'Ship an application manifest with a requestedExecutionLevel (asInvoker for a normal app). Write per-user state to %LOCALAPPDATA% explicitly rather than relying on redirection, and build 64-bit where possible.'
        } elseif ($allowed) {
            New-TcpkFinding -Module 'runtime' -RuleId 'virtualization.allowed' `
                -Severity 'LOW' -Confidence 'Confirmed' `
                -Title "$($p.Name) token permits UAC virtualization" `
                -File "$($p.Name) (PID $($p.Id))" `
                -Evidence 'TokenVirtualizationAllowed=1; TokenVirtualizationEnabled=0' `
                -Cwe @('CWE-276') `
                -Description ('The token would permit file and registry virtualization, though it is ' +
                    'not currently active. Weaker than the enabled case, but it indicates the process ' +
                    'is in the compatibility class Windows applies the shim to.') `
                -Fix 'Ship a manifest with an explicit requestedExecutionLevel so the compatibility shim never applies.'
        }
    }
}
