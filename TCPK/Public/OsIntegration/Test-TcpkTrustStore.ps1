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

    # Collect explicitly-distrusted thumbprints BEFORE scanning trust stores.
    # A cert present in both Root and Disallowed is explicitly revoked by the OS/admin;
    # it cannot validate any chain and the stated "MITM / code-sign" impact is impossible.
    $disallowedThumbs = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($dp in @('Cert:\LocalMachine\Disallowed','Cert:\CurrentUser\Disallowed')) {
        try {
            Get-ChildItem -Path $dp -ErrorAction SilentlyContinue |
                ForEach-Object { [void]$disallowedThumbs.Add($_.Thumbprint) }
        } catch { }
    }

    $stores = @(
        @{ Path='Cert:\LocalMachine\Root';             Kind='Trusted Root CA (machine)' },
        @{ Path='Cert:\CurrentUser\Root';              Kind='Trusted Root CA (user)' },
        @{ Path='Cert:\LocalMachine\TrustedPublisher'; Kind='Trusted Publisher (machine)' },
        @{ Path='Cert:\CurrentUser\TrustedPublisher';  Kind='Trusted Publisher (user)' }
    )

    foreach ($st in $stores) {
        $certs = @()
        try { $certs = Get-ChildItem -Path $st.Path -ErrorAction SilentlyContinue } catch { continue }
        foreach ($c in $certs) {
            $subj = "$($c.Subject)"
            $iss  = "$($c.Issuer)"
            $byThumbprint = $shipped.ContainsKey($c.Thumbprint)
            $byName = ($terms.Count -gt 0) -and (
                (Test-TcpkTermMatch -Text $subj -Terms $terms) -or
                (Test-TcpkTermMatch -Text $iss  -Terms $terms))
            if (-not ($byThumbprint -or $byName)) { continue }

            # Decode the certificate in full so the analyst has everything without
            # pulling it from the store by hand.
            $selfSigned = ($subj -eq $iss)
            $expired    = ((Get-Date) -gt $c.NotAfter)
            $keySz      = try { "$($c.PublicKey.Key.KeySize)" } catch { '?' }
            $bcx   = $c.Extensions | Where-Object { $_ -is [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension] } | Select-Object -First 1
            $isCa  = [bool]($bcx -and $bcx.CertificateAuthority)
            $ekux  = $c.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' } | Select-Object -First 1
            $ekuTxt = if ($ekux) { (@($ekux.EnhancedKeyUsages | ForEach-Object { $_.FriendlyName }) -join ', ') } else { 'ANY (no EKU)' }
            $kux   = $c.Extensions | Where-Object { $_ -is [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension] } | Select-Object -First 1
            $kuTxt = if ($kux) { "$($kux.KeyUsages)" } else { '(none)' }

            # Gate 1: Disallowed store check.
            # The OS/admin has explicitly distrusted this thumbprint.  It cannot validate
            # any chain; the impact claimed by a ROOT finding is impossible.
            $isDisallowed = $disallowedThumbs.Contains($c.Thumbprint)

            # Gate 2: Actual chain validity.
            # A cert whose chain does not build cannot produce the claimed MITM / code-sign
            # impact regardless of which store it lives in.
            $chainValid     = $false
            $chainStatusTxt = 'not checked'
            if (-not $isDisallowed) {
                try {
                    $xchain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
                    $xchain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
                    $xchain.ChainPolicy.VerificationFlags = [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::IgnoreNotTimeValid
                    $chainValid = $xchain.Build($c)
                    $chainStatusTxt = if ($chainValid) { 'valid' } else {
                        ($xchain.ChainStatus | ForEach-Object { $_.Status.ToString() }) -join '; '
                    }
                    $xchain.Dispose()
                } catch { $chainStatusTxt = 'chain-build-exception' }
            }

            # Compute gated severity.
            # Impact is only real when: not distrusted, chain validates, and for the
            # highest impact claim (issue certs / MITM TLS), isCa must be true.
            $sev = if ($isDisallowed) {
                'INFO'    # explicitly distrusted: cannot be exploited
            } elseif (-not $chainValid) {
                'INFO'    # chain broken (expired, revoked, untrusted root): no usable trust
            } elseif ($isCa -and $st.Kind -like 'Trusted Root*') {
                'HIGH'    # valid CA in root store: genuine trust expansion
            } elseif ($st.Kind -like 'Trusted Root*') {
                'MEDIUM'  # valid non-CA in root store: name-match trust without cert issuance
            } else {
                'MEDIUM'  # TrustedPublisher with valid chain: code-signing trust
            }

            # Attribution: distinguish shipped-with-app (Confirmed) from name-match (Inferred).
            # A subject-name match proves identity overlap, NOT that this app installed the cert.
            $attrWhy = if ($byThumbprint) {
                "cert shipped with this application; thumbprint matches '$($shipped[$c.Thumbprint])'"
            } else {
                "cert subject/issuer matches an identity term ($($terms -join ', ')); " +
                "ATTRIBUTION UNCONFIRMED -- no evidence of installation by this app was found in its installer or code"
            }
            $conf = if ($byThumbprint) { 'Confirmed' } else { 'Inferred' }

            # Impact text conditioned on the actual chain state and CA flag.
            $impactTxt = if ($isDisallowed) {
                "The certificate is in the Disallowed store (explicitly revoked or distrusted by OS/admin). " +
                "X509Chain.Build fails for every verification policy. " +
                "It cannot be used to validate a connection, issue subordinate certificates, or sign code. " +
                "This is NOT trust-store pollution; it is evidence of distrust hygiene."
            } elseif (-not $chainValid) {
                "X509Chain.Build failed ($chainStatusTxt). " +
                "An expired, revoked, or chain-broken certificate cannot validate any new TLS connection " +
                "or be used to sign trusted code. Structural observation only; no current exploitable impact."
            } elseif ($isCa) {
                "A CA certificate with a valid chain is in a trusted root store. " +
                "The holder of the matching private key can issue arbitrary subordinate certificates " +
                "trusted by this machine, enabling MITM TLS interception or signing trusted code."
            } else {
                "A non-CA certificate (BasicConstraints.CA=False) with a valid chain is in a trust store. " +
                "It cannot issue subordinate certificates or act as a MITM CA. " +
                "Impact is limited to scenarios where this specific certificate's identity is checked."
            }

            # Title qualified by attribution method
            $titlePrefix = if ($byThumbprint) { 'Cert shipped with app' } else { 'Cert bearing app identity' }
            $titleSuffix = if ($isDisallowed) { ' [DISALLOWED]' } elseif ($expired) { ' [EXPIRED]' } else { '' }

            $decoded = ("{0} | self-signed={1} | CA={2} | EKU={3} | KeyUsage={4} | key={5}-{6}bit | " +
                "sig={7} | serial={8} | thumbprint={9} | hasPrivateKey={10} | valid={11}..{12}{13} | " +
                "chain={14} | disallowed={15} | subject={16} | issuer={17}") -f
                $attrWhy, $selfSigned, $isCa, $ekuTxt, $kuTxt,
                $c.PublicKey.Oid.FriendlyName, $keySz,
                $c.SignatureAlgorithm.FriendlyName, $c.SerialNumber, $c.Thumbprint,
                $c.HasPrivateKey,
                $c.NotBefore.ToUniversalTime().ToString('u'),
                $c.NotAfter.ToUniversalTime().ToString('u'),
                $(if ($expired) { ' [EXPIRED]' } else { '' }),
                $chainStatusTxt, $isDisallowed, $subj, $iss

            $pem = "-----BEGIN CERTIFICATE-----`n" +
                [Convert]::ToBase64String($c.RawData, [Base64FormattingOptions]::InsertLineBreaks) +
                "`n-----END CERTIFICATE-----"

            New-TcpkFinding -Module 'os' -RuleId 'truststore.app-installed-cert' `
                -Severity $sev -Confidence $conf `
                -Title "$titlePrefix in $($st.Kind)$titleSuffix`: $($c.Subject.Substring(0,[Math]::Min(60,$c.Subject.Length)))" `
                -File $st.Path `
                -Evidence $decoded `
                -Cwe @('CWE-296','CWE-295') `
                -Description ("$impactTxt`n`n$attrWhy`n`nFull certificate (PEM):`n$pem") `
                -Fix 'Remove custom root CAs from the machine trust store. Use per-connection certificate pinning instead. If this cert is legitimately installed, confirm its origin and document it.'
        }
    }
}
