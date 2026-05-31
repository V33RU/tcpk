function Test-TcpkMemoryDump {
<#
.SYNOPSIS
    E09. Dump the process and scan the dump for secrets.

.DESCRIPTION
    Wraps procdump.exe (-ma full memory dump), then runs Test-TcpkSecrets
    over the .dmp. Secrets found in a live-process dump are post-decryption
    runtime values, so any hits are promoted to HIGH severity. Cleans up
    the dump file when done.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ProcessName,
        [string]$Procdump,
        [string]$DumpPath
    )

    if (-not (Assert-TcpkWindows 'Test-TcpkMemoryDump')) { return }
    if (-not (Test-TcpkIsAdmin)) {
        New-TcpkSkippedFinding -RuleId 'memory-dump.skipped-no-admin' `
            -Title 'Memory dump skipped (admin recommended)'
        return
    }

    if (-not $Procdump) {
        $cmd = Get-Command procdump.exe -ErrorAction SilentlyContinue
        if (-not $cmd) {
            # Try the bundled tools path
            $bundled = Join-Path $script:TcpkRoot '..\..\tools\Procdump\procdump.exe'
            if (Test-Path $bundled) { $Procdump = (Resolve-Path $bundled).Path }
        } else { $Procdump = $cmd.Source }
    }
    if (-not $Procdump -or -not (Test-Path $Procdump)) {
        New-TcpkSkippedFinding -RuleId 'memory-dump.no-procdump' `
            -Title 'procdump.exe not on PATH; install via .\Scripts\Install-Requirements.ps1'
        return
    }
    if (-not $DumpPath) {
        $DumpPath = Join-Path $env:TEMP "tcpk-$ProcessName-$([Guid]::NewGuid().ToString().Substring(0,8)).dmp"
    }

    & $Procdump -accepteula -ma $ProcessName $DumpPath 2>&1 | Out-Null
    if (-not (Test-Path $DumpPath)) {
        New-TcpkSkippedFinding -RuleId 'memory-dump.failed' -Title 'procdump did not produce a dump'
        return
    }
    try {
        $findings = Test-TcpkSecrets -Path $DumpPath
        foreach ($f in $findings) {
            $f.Module = 'memory'
            if ((Get-TcpkSeverityRank $f.Severity) -lt (Get-TcpkSeverityRank 'HIGH')) {
                $f.Severity = 'HIGH'
            }
            $f
        }
    } finally {
        Remove-Item $DumpPath -Force -ErrorAction SilentlyContinue
    }
}
