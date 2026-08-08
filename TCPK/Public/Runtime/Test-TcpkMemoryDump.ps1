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
    # Track whether TCPK chose this path. When the operator supplies -DumpPath, the file is
    # theirs: it may already exist and may be evidence they want to keep, so the cleanup
    # below must not delete it. Only a dump TCPK created is TCPK's to remove.
    $tcpkOwnsDump = $false
    if (-not $DumpPath) {
        $DumpPath = New-TcpkWorkPath -Kind 'dump' -Prefix "$ProcessName" -Extension 'dmp'
        $tcpkOwnsDump = $true
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
        # A full -ma dump of a thick client holds whatever was in its memory, including any
        # credential the app had decrypted. Delete it as soon as the scan is done. Only when
        # TCPK created it: an operator-supplied -DumpPath is not ours to remove.
        if ($tcpkOwnsDump) {
            Remove-Item $DumpPath -Force -ErrorAction SilentlyContinue
        }
    }
}
