# Shared process-resolution helpers for the Runtime bucket.

function Get-TcpkProcess {
<#
Resolves -ProcessName or -ProcessId into a list of Process objects.
Returns an empty array if neither is supplied or nothing matches.
#>
    [CmdletBinding()]
    param(
        [string]$ProcessName,
        [Nullable[int]]$ProcessId
    )
    if ($ProcessId) {
        $p = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
        if ($p) { return @($p) }
        return @()
    }
    if ($ProcessName) {
        return @(Get-Process -Name $ProcessName -ErrorAction SilentlyContinue)
    }
    return @()
}

# Convenience for "this check returns Skipped if we're not admin and admin is required"
function New-TcpkSkippedFinding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$RuleId,
        [Parameter(Mandatory)][string]$Title,
        [string]$Reason = 'Admin elevation required.'
    )
    New-TcpkFinding -Module 'runtime' -RuleId $RuleId `
        -Severity 'INFO' -Confidence 'Skipped' `
        -Title $Title -Evidence $Reason
}
