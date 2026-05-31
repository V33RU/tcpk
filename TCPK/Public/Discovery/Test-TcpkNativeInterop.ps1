function Test-TcpkNativeInterop {
<#
.SYNOPSIS
    A18. Native interop -- unsafe Marshal / pointer patterns.

.DESCRIPTION
    Flags references to interop APIs that historically host memory-safety
    bugs:
      Marshal.Copy / Marshal.WriteByte / Marshal.PtrToStructure
      Marshal.AllocHGlobal / Marshal.AllocCoTaskMem
      unsafe blocks (stackalloc, fixed)
      GCHandle.Alloc with Pinned flag

    Reference != bug, but every appearance in first-party code deserves a
    quick review of the size/length argument.

.PARAMETER Path
    File or directory.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $needles = @(
        'Marshal.Copy','Marshal.WriteByte','Marshal.PtrToStructure',
        'Marshal.AllocHGlobal','Marshal.AllocCoTaskMem','Marshal.ReadIntPtr',
        'GCHandle.Alloc','stackalloc'
    )

    foreach ($pe in Get-TcpkPeFiles -Path $Path) {
        if (Test-TcpkIsFrameworkFile $pe.Name) { continue }
        $text = Read-TcpkAllText -Path $pe.FullName
        if (-not $text) { continue }

        $hits = @()
        foreach ($n in $needles) {
            $c = ([regex]::Matches($text, [regex]::Escape($n))).Count
            if ($c -gt 0) { $hits += "$n(x$c)" }
        }
        if ($hits.Count -eq 0) { continue }

        New-TcpkFinding -Module 'static' -RuleId 'interop.unsafe-marshal' `
            -Severity 'INFO' -Confidence 'Inferred' `
            -Title "$($pe.Name) uses native interop primitives" `
            -File $pe.FullName -Evidence ($hits -join ', ') `
            -Cwe @('CWE-119','CWE-787') `
            -Description 'Triage hint -- the bug class here is buffer over/under-read in size arguments. Manual review of each call site is appropriate for high-risk code.'
    }
}
