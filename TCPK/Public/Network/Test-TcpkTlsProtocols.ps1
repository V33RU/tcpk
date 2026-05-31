function Test-TcpkTlsProtocols {
<#
.SYNOPSIS
    F04. TLS protocol version markers (1.0 / 1.1 fallback?).

.DESCRIPTION
    Scans first-party PEs for explicit references to SecurityProtocolType.Tls
    / Tls11 (deprecated) and emits MEDIUM findings. Modern apps should pin
    Tls12 or Tls13 (or let the OS pick via SystemDefault).

.PARAMETER Path
    File or directory.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $bad = @(
        @{ Marker='SecurityProtocolType.Tls,';   Sev='HIGH';   Desc='Explicit TLS 1.0 enablement (deprecated)' }
        @{ Marker='SecurityProtocolType.Tls11';  Sev='HIGH';   Desc='Explicit TLS 1.1 enablement (deprecated)' }
        @{ Marker='SecurityProtocolType.Ssl3';   Sev='CRITICAL'; Desc='Explicit SSLv3 (POODLE-vulnerable)' }
        @{ Marker='SslProtocols.Tls11';          Sev='HIGH';   Desc='SslProtocols.Tls11 (deprecated)' }
        @{ Marker='SslProtocols.Ssl3';           Sev='CRITICAL'; Desc='SslProtocols.Ssl3 (POODLE-vulnerable)' }
    )

    # Cap severity at HIGH for substring-only matches: any .NET binary that
    # references the SslProtocols / SecurityProtocolType enum will contain
    # these strings in its metadata table even if the enum value is never
    # assigned. Confidence is Unverified for the same reason.
    foreach ($pe in Get-TcpkPeFiles -Path $Path) {
        if (Test-TcpkIsFrameworkFile $pe.Name) { continue }
        $text = Read-TcpkAllText -Path $pe.FullName
        if (-not $text) { continue }
        foreach ($b in $bad) {
            if ($text.Contains($b.Marker)) {
                $sev = if ($b.Sev -eq 'CRITICAL') { 'HIGH' } else { $b.Sev }
                New-TcpkFinding -Module 'network' -RuleId ("tls.protocol." + ($b.Marker -replace '\W','_')) `
                    -Severity $sev -Confidence 'Unverified' `
                    -Title "$($pe.Name) references $($b.Marker)" `
                    -File $pe.FullName -Evidence $b.Marker `
                    -Cwe @('CWE-326') `
                    -Description ($b.Desc + ' NOTE: substring match against .NET enum metadata. Decompile to confirm the enum value is actually assigned to a SecurityProtocol property -- otherwise this is a false positive from the enum type being referenced anywhere.') `
                    -Fix 'If real, pin to SecurityProtocolType.Tls12 | Tls13 or use SystemDefault.'
            }
        }
    }
}
