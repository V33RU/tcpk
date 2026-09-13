function Test-TcpkCertBundle {
<#
.SYNOPSIS
    A65. Audit shipped certificate / key files (.crt / .pem / .cer / .p12 / .pfx /
    .key / .jks) for cryptographic weaknesses and accidentally-embedded private keys.

.DESCRIPTION
    Complements Test-TcpkTrustStore (which reads the RUNNING Windows trust store)
    and Test-TcpkKeyMaterial (which greps binaries for key literals). This cmdlet
    audits x.509 material shipped INSIDE the install tree - a very common surface
    for embedded companion / firmware bundles that carry vendor CAs, device certs
    and MQTT / mTLS material.

    Rules:
      cert.embedded-private-key       HIGH     Confirmed  A file (any extension)
                                                            starts with a PEM
                                                            'BEGIN PRIVATE KEY' /
                                                            'BEGIN RSA PRIVATE KEY'
                                                            / 'BEGIN EC PRIVATE KEY'
                                                            block. Shipping a
                                                            private key with an app
                                                            binary means every
                                                            installer holder has it.
      cert.sha1-signature             MEDIUM   Confirmed  Certificate uses
                                                            SHA-1 signature. Public
                                                            CAs stopped issuing
                                                            SHA-1 certs in 2016;
                                                            still-shipped SHA-1
                                                            certs are old or
                                                            self-signed.
      cert.weak-rsa-key               MEDIUM   Confirmed  RSA public key modulus
                                                            below 2048 bits.
      cert.expired                    HIGH     Confirmed  notAfter is in the past.
                                                            A shipped app pinning
                                                            this cert stops working;
                                                            an attacker can revive
                                                            the private key with no
                                                            fear of the vendor
                                                            re-issuing.
      cert.expiring-soon              LOW      Confirmed  notAfter within 90 days.
      cert.self-signed-root-shipped   MEDIUM   Confirmed  Subject == Issuer AND is
                                                            under a "trust anchor"
                                                            shipped-path shape
                                                            (roots / trusted / ca /
                                                            certs / ssl / anchors).
                                                            Custom self-signed root
                                                            added to the app's own
                                                            trust bundle.

    Skips OS-shipped CA bundles: /etc/ssl/certs/, /usr/share/ca-certificates/,
    /etc/pki/ca-trust/, /etc/pki/tls/certs/, /var/lib/ca-certificates/, and any
    subtree named ca-certificates. Those are Mozilla / CCADB roots the OS
    packages ship - real findings against them belong to the OS, not the audited
    app.

    Requires an openssl binary on PATH (Get-Command openssl) for x509 parsing.
    On a bare Windows host without openssl the cmdlet falls back to embedded-
    private-key detection only (which is a text scan) and emits Skipped for the
    other rules so the audit reader knows why they did not run.

.PARAMETER Path
    Install directory or a single cert / key file.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { return }

    $osBundleSkipRx = '(?i)[\\/](etc[\\/]ssl[\\/]certs|usr[\\/]share[\\/]ca-certificates|etc[\\/]pki[\\/]ca-trust|etc[\\/]pki[\\/]tls[\\/]certs|var[\\/]lib[\\/]ca-certificates|ca-certificates)[\\/]'
    $exts = @('.crt','.pem','.cer','.p12','.pfx','.key','.jks','.pkcs12','.der')

    $files = @()
    $item = Get-Item -LiteralPath $Path
    if ($item.PSIsContainer) {
        try {
            $files = @(Get-ChildItem -LiteralPath $Path -Recurse -File -ErrorAction SilentlyContinue |
                       Where-Object {
                           $exts -contains $_.Extension.ToLowerInvariant() -and
                           $_.Length -lt 262144 -and
                           -not ($_.FullName -match $osBundleSkipRx)
                       })
        } catch { return }
    } elseif ($exts -contains $item.Extension.ToLowerInvariant()) {
        $files = @($item)
    }
    if ($files.Count -eq 0) { return }

    $openssl = (Get-Command openssl -ErrorAction SilentlyContinue).Source
    $opensslMissingReported = $false

    foreach ($f in $files) {
        # ---- cert.embedded-private-key (text-only, no openssl needed) --------------
        $head = ''
        try { $head = [IO.File]::ReadAllText($f.FullName) } catch { }
        if ($head -and $head -match '-----BEGIN (RSA |EC |DSA |ENCRYPTED )?PRIVATE KEY-----') {
            $encrypted = $head -match '-----BEGIN ENCRYPTED PRIVATE KEY-----'
            $sev = if ($encrypted) { 'MEDIUM' } else { 'HIGH' }
            New-TcpkFinding -Module 'discovery' -RuleId 'cert.embedded-private-key' `
                -Severity $sev -Confidence 'Confirmed' `
                -Title "Private key embedded in shipped file: $($f.Name)" `
                -File $f.FullName -Evidence ("PEM header present$(if ($encrypted) { ' (password-encrypted, MEDIUM)' } else { ' (unencrypted, HIGH)' })") `
                -Cwe @('CWE-321','CWE-798','CWE-522') `
                -Description ('The file ships a PEM-encoded private key. Every installer holder has it. ' +
                    'If the paired public certificate is deployed in a trust anchor or as a device identity, ' +
                    'the vendor cannot rotate without breaking every install. Encrypted PEMs are MEDIUM (the ' +
                    'passphrase is often also shipped or trivially recovered).') `
                -Fix 'Do not ship private keys with the application. If the key is a device identity, provision per-install at first run. If it is a client cert for an internal API, replace it with an OAuth device flow or a per-user cert issued by an authenticated backend.'
        }

        # ---- x509 checks via openssl -------------------------------------------------
        if (-not $openssl) {
            if (-not $opensslMissingReported) {
                New-TcpkFinding -Module 'discovery' -RuleId 'cert.parse-skipped' `
                    -Severity 'INFO' -Confidence 'Skipped' `
                    -Title 'openssl not on PATH - x509 checks skipped' `
                    -File $Path -Evidence 'Get-Command openssl returned nothing' `
                    -Description 'The cert-bundle x509 checks (SHA-1 signature, weak-RSA, expiry, self-signed root) require an openssl binary on PATH. Install OpenSSL (or run this cmdlet from a host that has it) to see those findings.'
                $opensslMissingReported = $true
            }
            continue
        }

        # Only .crt / .pem / .cer files are worth handing to openssl x509. .p12 / .pfx
        # need a password and openssl pkcs12; skip for now.
        if ($f.Extension.ToLowerInvariant() -notin '.crt','.pem','.cer') { continue }

        # Parse with openssl x509. Multiple certs in one PEM (bundle) are handled by
        # asking openssl for each certificate individually via -inform PEM + a loop
        # driven by 'openssl storeutl' - simpler to just parse the FIRST cert here and
        # note that multi-cert bundles are treated as their first entry.
        $subject = ''; $issuer = ''; $sigAlg = ''; $keyBits = 0; $notAfter = ''
        try {
            $out = & $openssl x509 -in $f.FullName -noout -subject -issuer -enddate -text 2>$null
        } catch { $out = $null }
        if (-not $out) { continue }
        foreach ($line in $out) {
            if ($line -match '^subject=\s*(.+)$')  { $subject = $matches[1].Trim() }
            elseif ($line -match '^issuer=\s*(.+)$')   { $issuer  = $matches[1].Trim() }
            elseif ($line -match '^notAfter=\s*(.+)$') { $notAfter = $matches[1].Trim() }
            elseif ($line -match 'Signature Algorithm:\s*(\S+)') {
                if (-not $sigAlg) { $sigAlg = $matches[1].Trim() }
            }
            elseif ($line -match 'RSA Public-Key: \((\d+)\s*bit') { $keyBits = [int]$matches[1] }
            elseif ($line -match 'Public-Key: \((\d+)\s*bit')     { if (-not $keyBits) { $keyBits = [int]$matches[1] } }
        }
        if (-not $subject -and -not $issuer) { continue }   # openssl refused, skip

        # ---- cert.sha1-signature ---------------------------------------------------
        if ($sigAlg -match '^(?i)sha1WithRSAEncryption|ecdsa-with-SHA1|dsa-with-SHA1$') {
            New-TcpkFinding -Module 'discovery' -RuleId 'cert.sha1-signature' `
                -Severity 'MEDIUM' -Confidence 'Confirmed' `
                -Title "SHA-1 signature: $($f.Name)" `
                -File $f.FullName -Evidence "SigAlg=$sigAlg; Subject=$subject" `
                -Cwe @('CWE-327','CWE-328') `
                -Description ('The certificate is signed with SHA-1. Public CAs stopped issuing SHA-1 certs ' +
                    'in 2016; browsers reject them since Chrome 56 / Firefox 51. A still-shipped SHA-1 cert ' +
                    'is either self-signed (weak-hash forgery surface) or long-lived legacy that should have ' +
                    'been rotated.') `
                -Fix 'Re-issue the certificate with SHA-256 or better. If it is a self-signed root, replace with a modern one and rotate the trust bundle.'
        }

        # ---- cert.weak-rsa-key -----------------------------------------------------
        if ($keyBits -and $keyBits -lt 2048) {
            New-TcpkFinding -Module 'discovery' -RuleId 'cert.weak-rsa-key' `
                -Severity 'MEDIUM' -Confidence 'Confirmed' `
                -Title "RSA key below 2048 bits: $($f.Name) ($keyBits bit)" `
                -File $f.FullName -Evidence "PublicKey=$keyBits bit; Subject=$subject" `
                -Cwe @('CWE-326','CWE-327') `
                -Description ('The certificate public key is RSA-' + $keyBits + '. NIST retired RSA-1024 in ' +
                    '2013; every modern platform expects >= 2048 (or an EC key of comparable strength).') `
                -Fix 'Re-issue with RSA-3072 (or ECDSA P-256). Rotate the paired private key at the same time.'
        }

        # ---- cert.expired / cert.expiring-soon ------------------------------------
        if ($notAfter) {
            $expiry = $null
            try { $expiry = [DateTime]::Parse($notAfter) } catch { }
            if ($expiry) {
                $now = Get-Date
                if ($expiry -lt $now) {
                    New-TcpkFinding -Module 'discovery' -RuleId 'cert.expired' `
                        -Severity 'HIGH' -Confidence 'Confirmed' `
                        -Title "Expired certificate shipped: $($f.Name)" `
                        -File $f.FullName -Evidence "notAfter=$notAfter (now=$($now.ToString('u'))); Subject=$subject" `
                        -Cwe @('CWE-298','CWE-295') `
                        -Description ('The shipped certificate expired on ' + $notAfter + '. Any client-side ' +
                            'code that pins it fails validation until the app is updated. An attacker with the ' +
                            'private key can revive the cert (no CA re-issuance to worry about) and MITM any ' +
                            'traffic that ignores the expiry.') `
                        -Fix 'Re-issue the cert. If clients pin, ship a new build with the new cert; if they pin a public key, transition via a two-cert pin window.'
                } elseif ($expiry -lt $now.AddDays(90)) {
                    New-TcpkFinding -Module 'discovery' -RuleId 'cert.expiring-soon' `
                        -Severity 'LOW' -Confidence 'Confirmed' `
                        -Title "Certificate expires soon: $($f.Name)" `
                        -File $f.FullName -Evidence "notAfter=$notAfter (in <90 days); Subject=$subject" `
                        -Cwe @('CWE-298') `
                        -Description ('The shipped certificate expires within 90 days. Plan the rotation; if ' +
                            'clients pin, ship the new cert first with a two-cert pin window.') `
                        -Fix 'Rotate now; do not wait for the expiry outage.'
                }
            }
        }

        # ---- cert.self-signed-root-shipped ----------------------------------------
        # Subject == Issuer AND path is inside a trust-anchor-shaped directory. This
        # catches vendor custom roots that the app adds to its own trust bundle to
        # allow a private CA hierarchy. Not a defect by itself, but always worth
        # calling out to the report reader.
        if ($subject -and $issuer -and $subject -eq $issuer -and
            $f.FullName -match '(?i)[\\/](trusted|root|roots|anchors|ca[\\/]?bundle|certs|trust)[\\/]') {
            New-TcpkFinding -Module 'discovery' -RuleId 'cert.self-signed-root-shipped' `
                -Severity 'MEDIUM' -Confidence 'Confirmed' `
                -Title "Self-signed root shipped in trust-anchor path: $($f.Name)" `
                -File $f.FullName -Evidence "Subject == Issuer: $subject" `
                -Cwe @('CWE-296','CWE-345') `
                -Description ('A self-signed certificate sits under a trust-anchor-shaped path. This is how a ' +
                    'vendor adds a custom root to the app trust bundle. Not a defect by itself, but every ' +
                    'downstream endpoint chained to this root is trusted by the app on the strength of the ' +
                    'private key holder. If the key is co-shipped (see cert.embedded-private-key on the same ' +
                    'file) the primitive becomes MITM at any point along that chain.') `
                -Fix 'Confirm the private key for this root is stored offline (HSM), not shipped anywhere in the release. Rotate the root if the private key has ever left the HSM.'
        }
    }
}
