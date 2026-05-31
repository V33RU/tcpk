function Test-TcpkDnsLeakage {
<#
.SYNOPSIS
    F05. DNS pre-resolution / hostname leakage indicators.

.DESCRIPTION
    Inspects first-party code for patterns that resolve hostnames before
    TLS is established (e.g. Dns.GetHostEntry, DnsQuery, GetHostAddresses).
    These leak the destination hostname to a passive observer / corporate
    DNS even when the connection itself is TLS-secured.

.PARAMETER Path
    File or directory.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $needles = @(
        'Dns.GetHostEntry','Dns.GetHostAddresses','Dns.GetHostByName',
        'DnsQuery','DnsQueryEx','GetHostByName'
    )
    foreach ($pe in Get-TcpkPeFiles -Path $Path) {
        if (Test-TcpkIsFrameworkFile $pe.Name) { continue }
        $text = Read-TcpkAllText -Path $pe.FullName
        if (-not $text) { continue }
        $hits = @()
        foreach ($n in $needles) {
            if ($text.Contains($n)) { $hits += $n }
        }
        if ($hits.Count -gt 0) {
            New-TcpkFinding -Module 'network' -RuleId 'dns.pre-resolution' `
                -Severity 'LOW' -Confidence 'Inferred' `
                -Title "$($pe.Name) references DNS resolution APIs" `
                -File $pe.FullName -Evidence ($hits -join ', ') `
                -Cwe @('CWE-200') `
                -Description 'Pre-resolution leaks hostnames to passive observers. For privacy-sensitive flows prefer letting HttpClient/SocketsHttpHandler handle resolution inside the connection logic.' `
                -Fix 'For non-diagnostic flows, remove explicit DNS calls and pass the hostname directly to HttpClient.'
        }
    }
}
