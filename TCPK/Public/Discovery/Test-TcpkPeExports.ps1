function Test-TcpkPeExports {
<#
.SYNOPSIS
    A04. PE export surface enumeration (for proxy-DLL planning).

.DESCRIPTION
    Reads the export directory of each native DLL under the path and emits
    an INFO finding per DLL summarizing its export count. Severity is always
    INFO -- this check feeds the Verify and Exploit layers (e.g. proxy-DLL
    generation needs the export table), not a vulnerability report by itself.

.PARAMETER Path
    File or directory.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    foreach ($pe in Get-TcpkPeFiles -Path $Path) {
        if ($pe.Extension -ne '.dll') { continue }
        $info = Read-TcpkPe -Path $pe.FullName
        if (-not $info) { continue }
        $names = @($info.Exports)
        if ($names.Count -eq 0) { continue }

        $sample = (@($names) | Select-Object -First 25) -join ', '
        if ($names.Count -gt 25) { $sample += ', ...' }
        New-TcpkFinding -Module 'static' -RuleId 'pe-exports.count' `
            -Severity 'INFO' -Confidence 'Confirmed' `
            -Title "$($pe.Name) exports $($names.Count)+ function(s)" `
            -File $pe.FullName -Evidence "exports: $sample" `
            -Description 'Exported functions are a callable surface. Review whether any are sensitive/privileged and reachable without authentication. The list also feeds proxy-DLL generation in the Exploit bucket.'
    }
}
