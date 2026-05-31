function Test-TcpkAntiDebugRefs {
<#
.SYNOPSIS
    J01. Anti-debug API references (IsDebuggerPresent etc.).

.DESCRIPTION
    Inventory only -- presence of anti-debug calls is informational, neither
    a vulnerability nor a hardening signal at the static-string level. Used
    to scope reverse-engineering effort during a deeper engagement.

.PARAMETER Path
    File or directory.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $apis = @(
        'IsDebuggerPresent','CheckRemoteDebuggerPresent','NtQueryInformationProcess',
        'OutputDebugString','GetTickCount','QueryPerformanceCounter'
    )
    foreach ($pe in Get-TcpkPeFiles -Path $Path) {
        if (Test-TcpkIsFrameworkFile $pe.Name) { continue }
        $text = Read-TcpkAllText -Path $pe.FullName
        if (-not $text) { continue }
        $hits = @()
        foreach ($a in $apis) {
            $c = ([regex]::Matches($text, "\b$a\b")).Count
            if ($c -gt 0) { $hits += "$a(x$c)" }
        }
        if ($hits.Count -eq 0) { continue }
        New-TcpkFinding -Module 'antidebug' -RuleId 'antidebug.api-refs' `
            -Severity 'INFO' -Confidence 'Inferred' `
            -Title "$($pe.Name) references anti-debug APIs" `
            -File $pe.FullName -Evidence ($hits -join ', ') `
            -Description 'Informational. Presence does not mean active anti-debug protection -- many .NET apps reference these indirectly via diagnostics code.'
    }
}
