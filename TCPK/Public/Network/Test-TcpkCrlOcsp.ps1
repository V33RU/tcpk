function Test-TcpkCrlOcsp {
<#
.SYNOPSIS
    F06. CRL / OCSP revocation-checking behavior.

.DESCRIPTION
    Flags first-party code that disables revocation checks
    (X509RevocationMode.NoCheck, ChainPolicy.RevocationMode=NoCheck) -- a
    silent downgrade of TLS validation.

.PARAMETER Path
    File or directory.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $bad = @(
        @{ Marker='X509RevocationMode.NoCheck';     Sev='HIGH';   Title='X509 revocation check disabled (NoCheck)' }
        @{ Marker='RevocationMode = X509RevocationMode.NoCheck'; Sev='HIGH'; Title='Chain policy disables revocation checks' }
        @{ Marker='RevocationMode.NoCheck';          Sev='HIGH';   Title='Revocation check disabled' }
    )
    foreach ($pe in Get-TcpkPeFiles -Path $Path) {
        if (Test-TcpkIsFrameworkFile $pe.Name) { continue }
        $text = Read-TcpkAllText -Path $pe.FullName
        if (-not $text) { continue }
        foreach ($b in $bad) {
            if ($text.Contains($b.Marker)) {
                New-TcpkFinding -Module 'network' -RuleId 'tls.revocation-disabled' `
                    -Severity $b.Sev -Confidence 'Confirmed' `
                    -Title "$($b.Title) in $($pe.Name)" `
                    -File $pe.FullName -Evidence $b.Marker `
                    -Cwe @('CWE-299') `
                    -Description 'Disabling revocation means the app accepts certificates that have been explicitly revoked by their CA.' `
                    -Fix 'Use X509RevocationMode.Online (preferred) or .Offline; never NoCheck for production TLS.'
                break
            }
        }
    }
}
