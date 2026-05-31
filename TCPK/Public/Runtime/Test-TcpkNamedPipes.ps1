function Test-TcpkNamedPipes {
<#
.SYNOPSIS
    E04. Named pipes whose name suggests a relationship to the target.

.DESCRIPTION
    Enumerates \\.\pipe\ and filters by name pattern. The pipes themselves
    are not associated with owning PIDs at this layer -- see
    Test-TcpkNamedPipeDacl for DACL inspection.

.PARAMETER NameLike
    Substring or regex to match pipe names against (case-insensitive).

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$NameLike)

    if (-not (Assert-TcpkWindows 'Test-TcpkNamedPipes')) { return }

    try {
        $pipes = Get-ChildItem '\\.\pipe\' -ErrorAction Stop
    } catch {
        New-TcpkSkippedFinding -RuleId 'named-pipes.enum-fail' `
            -Title 'Cannot enumerate named pipes' -Reason $_.Exception.Message
        return
    }

    $escName = [regex]::Escape($NameLike)
    foreach ($pipe in $pipes) {
        if ($pipe.Name -notmatch $escName) { continue }
        New-TcpkFinding -Module 'runtime' -RuleId 'pipe.exists' `
            -Severity 'INFO' -Confidence 'Confirmed' `
            -Title "Named pipe present: $($pipe.Name)" `
            -File $pipe.FullName -Evidence $pipe.Name `
            -Cwe @('CWE-732','CWE-269') `
            -Description 'Cross-reference with Test-TcpkNamedPipeDacl to inspect the pipe DACL.'
    }
}
