# Bounded WMI/CIM access.
#
# Get-CimInstance's default -OperationTimeoutSec is 0, which means "use the server default",
# which for local DCOM WMI is effectively unbounded. Ten call sites across the service,
# persistence and runtime checks used that default, and -OperationTimeoutSec appeared zero
# times in the repo -- so on a box with a sick WMI service (repository mid-rebuild, wedged
# winmgmt, a deadlocked third-party root\cimv2 provider from an AV or backup agent) the audit
# stops on a single line and never comes back.
#
# -ErrorAction does not help: it decides what happens to an error that was RAISED, and a call
# that never returns raises nothing. The cooperative check budget does not help either, because
# nothing can poll Test-TcpkCheckBudgetExpired while the pipeline is parked inside a blocking
# cmdlet call.
#
# HONEST LIMIT, stated because a silent one is a bug: -OperationTimeoutSec bounds the CIM
# OPERATION. If the DCOM activation of winmgmt itself hangs before the operation starts, the
# client-side timer is not necessarily armed yet, so this narrows the window rather than
# closing it. Closing it completely needs the call in a separate runspace that can be aborted,
# which costs a runspace per query. This wrapper is the 95% fix; the residual case is a machine
# whose WMI is unusable by every tool on it, not just TCPK.
$script:TcpkCimTimeoutSec = 30

# Every WMI/CIM read in TCPK goes through here. A failure is recorded via Add-TcpkScanSkip so
# Test-TcpkScanCoverage reports "the service checks could not read WMI" instead of the audit
# reading as clean-on-services.
#
# CALLER CONTRACT: PowerShell unrolls a returned empty array to nothing, so on failure an
# assignment receives $null, NOT @(). `foreach ($x in $null)` runs zero times and a pipeline
# receives no items, both of which are fine -- but `$result.Count` on $null is not. Wrap the
# call in @() at any site that needs .Count:
#
#     $svcs = @(Get-TcpkCimSafe -ClassName Win32_Service)
#
function Get-TcpkCimSafe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ClassName,
        [string]$Namespace = '',
        [string]$Filter = '',
        [string[]]$Property = @(),
        [int]$TimeoutSec = 0,
        # Set when the caller has its own catch and wants the error to propagate.
        [switch]$Strict
    )

    $sec = if ($TimeoutSec -gt 0) { $TimeoutSec } else { $script:TcpkCimTimeoutSec }
    $p = @{
        ClassName           = $ClassName
        OperationTimeoutSec = $sec
        ErrorAction         = 'Stop'
    }
    if ($Namespace) { $p.Namespace = $Namespace }
    if ($Filter)    { $p.Filter    = $Filter }
    if ($Property -and $Property.Count) { $p.Property = $Property }

    $label = if ($Namespace) { "$Namespace/$ClassName" } else { $ClassName }
    if ($Filter) { $label = "$label ($Filter)" }

    try {
        return @(Get-CimInstance @p)
    } catch {
        $msg = "$($_.Exception.Message)"
        try { Add-TcpkScanSkip -Kind 'WmiFailed' -ItemPath "$label -- $msg" } catch { }
        try { Write-TcpkLog -Level WARN -Component 'cim' -Message "$label failed after ${sec}s: $msg" | Out-Null } catch { }
        if ($Strict) { throw }
        return @()
    }
}
