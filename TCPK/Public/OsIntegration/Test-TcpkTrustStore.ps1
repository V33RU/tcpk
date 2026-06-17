function Test-TcpkTrustStore {
<#
.SYNOPSIS
    C15. Certificate trust-store pollution by the app/installer.

.DESCRIPTION
    An installer that drops a custom root CA into the Trusted Root store, or a
    publisher cert into TrustedPublisher, weakens trust for the WHOLE machine:
    it can defeat cert pinning, enable silent code-trust, and let the vendor (or
    anyone who steals their key) MITM TLS.

    This check enumerates the Root and TrustedPublisher stores (LocalMachine +
    CurrentUser) and flags entries whose Subject/Issuer matches -NameLike (the
    vendor/package). It also cross-references certificates shipped under -Path:
    a shipped .cer whose thumbprint is installed in a trust store is a confirmed
    pollution by this app.

.PARAMETER NameLike
    Vendor/package substring to attribute trust-store entries to this app.

.PARAMETER Path
    Optional install dir, to cross-reference shipped .cer/.crt thumbprints.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param(
        [string[]]$NameLike = @(),
        [string]$Path
    )

    if (-not (Assert-TcpkWindows 'Test-TcpkTrustStore')) { return }
    $terms = Get-TcpkNameTerms -NameLike $NameLike

    # thumbprints of certs shipped inside the package (strongest attribution)
    $shipped = @{}
    if ($Path -and (Test-Path -LiteralPath $Path)) {
        $certFiles = Get-ChildItem -LiteralPath $Path -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension.ToLowerInvariant() -in '.cer','.crt','.der' }
        foreach ($cf in $certFiles) {
            try {
                $c = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $cf.FullName
                $shipped[$c.Thumbprint] = $cf.Name
                $c.Dispose()
            } catch { }
        }
    }

    $stores = @(
        @{ Path='Cert:\LocalMachine\Root';             Kind='Trusted Root CA (machine)'; Sev='HIGH' },
        @{ Path='Cert:\CurrentUser\Root';              Kind='Trusted Root CA (user)';    Sev='HIGH' },
        @{ Path='Cert:\LocalMachine\TrustedPublisher'; Kind='Trusted Publisher (machine)'; Sev='MEDIUM' },
        @{ Path='Cert:\CurrentUser\TrustedPublisher';  Kind='Trusted Publisher (user)';  Sev='MEDIUM' }
    )

    foreach ($st in $stores) {
        $certs = @()
        try { $certs = Get-ChildItem -Path $st.Path -ErrorAction SilentlyContinue } catch { continue }
        foreach ($c in $certs) {
            $subj = "$($c.Subject)"
            $iss  = "$($c.Issuer)"
            $byThumbprint = $shipped.ContainsKey($c.Thumbprint)
            $byName = ($terms.Count -gt 0) -and ((Test-TcpkTermMatch -Text $subj -Terms $terms) -or (Test-TcpkTermMatch -Text $iss -Terms $terms))
            if (-not ($byThumbprint -or $byName)) { continue }

            $why = if ($byThumbprint) { "thumbprint matches shipped file '$($shipped[$c.Thumbprint])'" } else { "subject/issuer matches an identity term ($($terms -join ', '))" }
            $conf = if ($byThumbprint) { 'Confirmed' } else { 'Inferred' }
            $sev = if ($byThumbprint -and $st.Kind -like 'Trusted Root*') { 'HIGH' } else { $st.Sev }

            # Decode the certificate IN FULL and carry it on the finding, so the analyst gets the
            # whole cert (self-signed? CA? EKU/usage, key, validity, private-key presence + PEM)
            # without having to pull it from the store by hand.
            $selfSigned = ($subj -eq $iss)
            $expired    = ((Get-Date) -gt $c.NotAfter)
            $keySz      = try { "$($c.PublicKey.Key.KeySize)" } catch { '?' }
            $bcx        = $c.Extensions | Where-Object { $_ -is [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension] } | Select-Object -First 1
            $isCa       = [bool]($bcx -and $bcx.CertificateAuthority)
            $ekux       = $c.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' } | Select-Object -First 1
            $ekuTxt     = if ($ekux) { (@($ekux.EnhancedKeyUsages | ForEach-Object { $_.FriendlyName }) -join ', ') } else { 'ANY (no EKU)' }
            $kux        = $c.Extensions | Where-Object { $_ -is [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension] } | Select-Object -First 1
            $kuTxt      = if ($kux) { "$($kux.KeyUsages)" } else { '(none)' }
            $decoded    = ("{0} | self-signed={1} | CA={2} | EKU={3} | KeyUsage={4} | key={5}-{6}bit | sig={7} | serial={8} | thumbprint={9} | hasPrivateKey={10} | valid={11}..{12}{13} | subject={14} | issuer={15}" -f `
                $why, $selfSigned, $isCa, $ekuTxt, $kuTxt, $c.PublicKey.Oid.FriendlyName, $keySz, $c.SignatureAlgorithm.FriendlyName, $c.SerialNumber, $c.Thumbprint, $c.HasPrivateKey, $c.NotBefore.ToUniversalTime().ToString('u'), $c.NotAfter.ToUniversalTime().ToString('u'), $(if ($expired) { ' [EXPIRED]' } else { '' }), $subj, $iss)
            $pem        = "-----BEGIN CERTIFICATE-----`n" + [Convert]::ToBase64String($c.RawData, [Base64FormattingOptions]::InsertLineBreaks) + "`n-----END CERTIFICATE-----"

            New-TcpkFinding -Module 'os' -RuleId 'truststore.app-installed-cert' `
                -Severity $sev -Confidence $conf `
                -Title "App-attributed cert in $($st.Kind): $($c.Subject.Substring(0,[Math]::Min(60,$c.Subject.Length)))" `
                -File $st.Path `
                -Evidence $decoded `
                -Cwe @('CWE-296','CWE-295') `
                -Description ("A certificate attributable to this application is installed in a system trust store. Trusted-root pollution lets the holder of the matching private key MITM TLS or sign trusted code on this machine.`n`nFull certificate (PEM):`n{0}" -f $pem) `
                -Fix 'Do not add custom root CAs to the machine trust store. Use per-connection pinning to your own CA instead, and remove the installed root.'
        }
    }
}
