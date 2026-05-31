function Test-TcpkTimingAntiDebug {
<#
.SYNOPSIS
    J04. Timing-based anti-debug markers (RDTSC, QueryPerformanceCounter).

.DESCRIPTION
    Counts references to high-resolution timing APIs that anti-debug code
    typically uses for stall-detection. Informational only -- many
    legitimate uses exist (perf counters, benchmarking).

.PARAMETER Path
    File or directory.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $markers = @('QueryPerformanceCounter','Stopwatch','GetTickCount','rdtsc')
    foreach ($pe in Get-TcpkPeFiles -Path $Path) {
        if (Test-TcpkIsFrameworkFile $pe.Name) { continue }
        $text = Read-TcpkAllText -Path $pe.FullName
        if (-not $text) { continue }
        $hits = @()
        foreach ($m in $markers) {
            $c = ([regex]::Matches($text, "\b$m\b")).Count
            if ($c -gt 0) { $hits += "$m(x$c)" }
        }
        if ($hits.Count -eq 0) { continue }
        New-TcpkFinding -Module 'antidebug' -RuleId 'timing.markers' `
            -Severity 'INFO' -Confidence 'Inferred' `
            -Title "$($pe.Name) uses high-resolution timing APIs" `
            -File $pe.FullName -Evidence ($hits -join ', ') `
            -Description 'Most uses are performance / instrumentation. Anti-debug uses stall-detection patterns -- confirm in ILSpy if hardening claims rely on it.'
    }
}
