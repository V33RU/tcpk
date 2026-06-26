# Live progress / activity heartbeat for long-running checks.
#
# The audit used to print a check's result line only AFTER the check finished, so a slow
# check (e.g. scanning a 200 MB single-file Electron exe) looked frozen. These helpers emit
# a LIVE, in-place progress indicator (Write-Progress) so the operator always sees what the
# tool is doing right now -- which check, which file, how far through.
#
# Nothing is skipped: this is purely visibility. Heavy file-walking scanners call
# Write-TcpkProgress per file; the audit's _RunCheck calls it per check (Id 1, the parent).
#
# A host (web control panel / GUI) can set $script:TcpkProgressHook to a scriptblock to also
# forward the same heartbeat to its own live monitor tab.

function Write-TcpkProgress {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Activity,
        [string]$Status = '',
        [int]$Current = 0,
        [int]$Total = 0,
        [int]$Id = 77,
        [int]$ParentId = -1
    )
    $pct = if ($Total -gt 0) { [int](100 * $Current / $Total) } else { -1 }
    try {
        $sp = @{ Id = $Id; Activity = $Activity; Status = $Status }
        if ($pct -ge 0)      { $sp.PercentComplete = $pct }
        if ($ParentId -ge 0) { $sp.ParentId = $ParentId }
        Write-Progress @sp
    } catch { }
    # Optional host hook (web panel / GUI live monitor). No-op on the CLI.
    if ($script:TcpkProgressHook) { try { & $script:TcpkProgressHook $Activity $Status $Current $Total } catch { } }
}

function Complete-TcpkProgress {
    [CmdletBinding()]
    param([int]$Id = 77, [string]$Activity = 'TCPK')
    try { Write-Progress -Id $Id -Activity $Activity -Completed } catch { }
}
