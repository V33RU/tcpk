function Test-TcpkTlsBypass {
<#
.SYNOPSIS
    A12. TLS validation bypass patterns.

.DESCRIPTION
    Looks for lambda / code patterns that disable certificate chain
    validation in HttpClient / WinHttp / WebRequest / WCF:

      - ServerCertificateCustomValidationCallback = (...) => true
      - ServerCertificateValidationCallback (legacy)
      - SslPolicyErrors lambda returning true unconditionally

    The byte-text scan finds candidates. Confidence is Unverified for
    bypass-style hits because the lambda body itself cannot be read from
    bytes alone -- requires decompilation to confirm whether validation is
    actually disabled or just customized.

.PARAMETER Path
    File or directory.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $patterns = @(
        @{ Rx='ServerCertificateCustomValidationCallback\s*=\s*\(?[^)]*\)?\s*=>\s*true'
           Sev='CRITICAL'; Conf='Inferred'
           Title='ServerCertificateCustomValidationCallback returns true unconditionally' },
        @{ Rx='ServerCertificateValidationCallback\s*=\s*[^;]*=>\s*true'
           Sev='CRITICAL'; Conf='Inferred'
           Title='ServerCertificateValidationCallback returns true unconditionally' },
        @{ Rx='SslPolicyErrors\s*\)\s*=>\s*true'
           Sev='CRITICAL'; Conf='Inferred'
           Title='SslPolicyErrors lambda returns true (cert validation bypass)' },
        @{ Rx='ServerCertificateCustomValidationCallback'
           Sev='HIGH'; Conf='Unverified'
           Title='Custom TLS validation callback present (verify body)' },
        @{ Rx='WINHTTP_OPTION_DISABLE_FEATURE.*WINHTTP_DISABLE_PASSPORT_AUTH'
           Sev='LOW'; Conf='Confirmed'
           Title='WinHttp feature disable (audit context)' }
    )

    foreach ($pe in Get-TcpkPeFiles -Path $Path) {
        if (Test-TcpkIsFrameworkFile $pe.Name) { continue }
        $text = Read-TcpkAllText -Path $pe.FullName
        if (-not $text) { continue }

        $seenIds = @{}
        foreach ($p in $patterns) {
            $m = [regex]::Match($text, $p.Rx)
            if (-not $m.Success) { continue }

            $id = ($p.Rx -replace '\W','_')
            if ($seenIds.ContainsKey($id)) { continue }
            $seenIds[$id] = $true

            New-TcpkFinding -Module 'static' -RuleId "tls-bypass.$id" `
                -Severity $p.Sev -Confidence $p.Conf `
                -Title "$($p.Title) in $($pe.Name)" `
                -File $pe.FullName -Evidence $m.Value `
                -Cwe @('CWE-295') `
                -Fix 'Remove the override or replace with proper chain + hostname validation (and pin cert thumbprint if appropriate).'
        }
    }
}
