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
           Title='WinHttp feature disable (audit context)' },
        @{ Rx='(AllowAllHostnameVerifier|ALLOW_ALL_HOSTNAME_VERIFIER|NullHostnameVerifier|setHostnameVerifier)'
           Sev='CRITICAL'; Conf='Inferred'; Cwe=@('CWE-297')
           Title='All-hosts HostnameVerifier (TLS hostname check disabled)' },
        @{ Rx='HostnameVerifier[^;{]{0,60}(=>|->)\s*true'
           Sev='CRITICAL'; Conf='Inferred'; Cwe=@('CWE-297')
           Title='HostnameVerifier returns true unconditionally (hostname check bypassed)' },
        @{ Rx='(X509CertificateValidationMode\s*\.?\s*None|CertificateValidationMode\s*=\s*"?None|CheckCertificateName\s*=\s*false)'
           Sev='HIGH'; Conf='Inferred'; Cwe=@('CWE-297','CWE-295')
           Title='Certificate name / validation mode disabled (WCF / WinRT)' }
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

            $cwe = if ($p.Cwe) { $p.Cwe } else { @('CWE-295') }
            New-TcpkFinding -Module 'static' -RuleId "tls-bypass.$id" `
                -Severity $p.Sev -Confidence $p.Conf `
                -Title "$($p.Title) in $($pe.Name)" `
                -File $pe.FullName -Evidence $m.Value `
                -Cwe $cwe `
                -Fix 'Remove the override or replace with proper chain + hostname validation (and pin cert thumbprint if appropriate).'
        }

        # Deterministic IL confirmation (Cecil): prove a cert-validation callback that
        # returns true unconditionally, or use of the BCL accept-all validator. This
        # promotes the finding from Inferred to CONFIRMED. Degrades silently if Cecil
        # is unavailable. The callback can live in any (sibling) assembly, so this runs
        # per-PE across the whole target.
        foreach ($cb in (Get-TcpkTlsCallbackVerdicts -DllPath $pe.FullName)) {
            $ev = New-Object 'System.Collections.Generic.List[string]'
            $ev.Add("$($cb.Kind): $($cb.Reason)")
            $ev.Add('')
            $ev.Add('LOCATION (open THIS assembly in ILSpy/dnSpy - the callback is here, not necessarily in the main exe):')
            $ev.Add("  Assembly : $($cb.File)")
            $ev.Add("  Namespace: $($cb.Namespace)")
            $ev.Add("  Type     : $($cb.Type)")
            $ev.Add("  Method   : $($cb.Signature)")
            $ev.Add("  MD token : $($cb.Token)")
            if ($cb.Enclosing -and $cb.Method -ne $cb.Enclosing) {
                $ev.Add("  Note     : this is a compiler-generated lambda. ILSpy lists it under a nested display-class node (e.g. '<>c'); its name '$($cb.Method)' is not typeable in the search box - search for the enclosing method '$($cb.Enclosing)' instead, or use the MD token in dnSpy.")
            }
            if ($cb.AssignedAt -and $cb.AssignedAt.Count -gt 0) {
                $ev.Add('WIRED UP AT (where the callback is assigned / passed as a delegate):')
                foreach ($site in $cb.AssignedAt) { $ev.Add("  $site") }
            }
            if ($cb.Il) {
                $ev.Add('IL PROOF (disassembled method body):')
                $shown = 0
                foreach ($ln in @($cb.Il -split "`n")) {
                    $ev.Add("  $ln"); $shown++
                    if ($shown -ge 40) { $ev.Add('  ... (truncated)'); break }
                }
            }
            $ev.Add('')
            $ev.Add('HOW TO OPEN IT: in ILSpy use File > Open on the assembly named above, expand the Namespace then the Type, and open the Method. In dnSpy press Ctrl+D and paste the MD token. If a search returns nothing, you almost certainly had the wrong DLL loaded.')

            New-TcpkFinding -Module 'static' -RuleId 'tls-bypass.cert-callback-accepts-all' `
                -Severity 'CRITICAL' -Confidence 'Confirmed' `
                -Title "TLS cert validation accepts ALL certificates: $($cb.Type)::$($cb.Method) in $($pe.Name)" `
                -File $pe.FullName -Evidence ($ev -join "`n") `
                -Cwe @('CWE-295') `
                -Description 'Proven from IL: the certificate-validation callback returns true unconditionally (or assigns the BCL accept-all validator), so the client accepts ANY server certificate - trivial man-in-the-middle of all TLS traffic. The Evidence block gives the exact assembly, namespace, type, method signature and metadata token so the callback can be opened directly in ILSpy/dnSpy.' `
                -Fix 'Implement real chain + hostname validation (or pin the certificate thumbprint). Never return true unconditionally and never use DangerousAcceptAnyServerCertificateValidator in production.'
        }
    }
}
