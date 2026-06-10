function Test-TcpkKeyMaterial {
<#
.SYNOPSIS
    D07. Private-key and certificate material inventory.

.DESCRIPTION
    Finds cryptographic key/cert files shipped inside the app and rates the
    exposure:
      * .pfx / .p12  -- attempts to load with an EMPTY password. If it loads
                        with a private key, the keystore is unprotected (HIGH).
      * .pem / .key  -- 'PRIVATE KEY' present and not 'ENCRYPTED' => cleartext
                        private key shipped (HIGH). 'ENCRYPTED PRIVATE KEY' => INFO.
      * .cer/.crt/.der -- public certificates, inventory only (INFO).
    Also scans first-party assemblies / configs for embedded PEM private-key
    blocks ('-----BEGIN ... PRIVATE KEY-----').

.PARAMETER Path
    File or directory.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $keyExt    = @('.pfx','.p12','.pem','.key','.der','.cer','.crt','.jks','.keystore','.ppk','.pkcs12')
    $pubExt    = @('.cer','.crt','.der')

    $files = if ((Get-Item -LiteralPath $Path).PSIsContainer) {
        Get-ChildItem -LiteralPath $Path -Recurse -File -ErrorAction SilentlyContinue
    } else { Get-Item -LiteralPath $Path }

    foreach ($f in $files) {
        $ext = $f.Extension.ToLowerInvariant()
        if ($ext -notin $keyExt) { continue }

        switch ($ext) {
            { $_ -in '.pfx','.p12','.pkcs12' } {
                $loaded = $false; $hasPriv = $false
                try {
                    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 `
                        -ArgumentList @($f.FullName, '', 'Exportable')
                    $loaded = $true
                    $hasPriv = $cert.HasPrivateKey
                    $cert.Dispose()
                } catch { $loaded = $false }

                if ($loaded -and $hasPriv) {
                    New-TcpkFinding -Module 'creds' -RuleId 'keymaterial.pfx-unprotected' `
                        -Severity 'HIGH' -Confidence 'Confirmed' `
                        -Title "Unprotected PKCS#12 keystore (private key, empty password): $($f.Name)" `
                        -File $f.FullName -Evidence 'X509Certificate2 loaded with empty password; HasPrivateKey=True' `
                        -Cwe @('CWE-256','CWE-522') `
                        -Description 'A .pfx/.p12 shipped with the app loads using an empty password and contains a private key. Anyone with the file owns the private key (TLS server impersonation / code signing).' `
                        -Fix 'Do not ship private keys. If unavoidable, protect with a strong password not embedded in the binary, and store outside the package.'
                } else {
                    New-TcpkFinding -Module 'creds' -RuleId 'keymaterial.pfx-present' `
                        -Severity 'LOW' -Confidence 'Confirmed' `
                        -Title "PKCS#12 keystore shipped: $($f.Name)" `
                        -File $f.FullName -Evidence 'password-protected or no exportable private key' `
                        -Cwe @('CWE-312') `
                        -Description 'A keystore is shipped with the app. Confirm whether the protecting password is also hardcoded nearby (which would negate the protection).' `
                        -Fix 'Keep keystores out of the shipped package; load from a protected location at runtime.'
                }
            }
            { $_ -in '.pem','.key' } {
                $txt = ''
                try { $txt = Get-Content -LiteralPath $f.FullName -Raw -ErrorAction Stop } catch { $txt = '' }
                if ($txt -match '-----BEGIN[A-Z ]*ENCRYPTED PRIVATE KEY-----') {
                    New-TcpkFinding -Module 'creds' -RuleId 'keymaterial.pem-encrypted-key' `
                        -Severity 'INFO' -Confidence 'Confirmed' `
                        -Title "Encrypted private key shipped: $($f.Name)" `
                        -File $f.FullName -Cwe @('CWE-312') `
                        -Description 'An encrypted private key is shipped. Verify the passphrase is not hardcoded in the app.'
                } elseif ($txt -match '-----BEGIN ([A-Z]+ )?PRIVATE KEY-----') {
                    New-TcpkFinding -Module 'creds' -RuleId 'keymaterial.pem-cleartext-key' `
                        -Severity 'HIGH' -Confidence 'Confirmed' `
                        -Title "Cleartext private key shipped: $($f.Name)" `
                        -File $f.FullName -Evidence 'PEM PRIVATE KEY block, not encrypted' `
                        -Cwe @('CWE-256','CWE-522') `
                        -Description 'A cleartext private key is shipped inside the app. The corresponding identity (TLS/SSH/signing) is fully compromised.' `
                        -Fix 'Remove the key from the package and rotate it. Provision per-host keys at runtime.'
                } elseif ($txt -match '-----BEGIN (CERTIFICATE|PUBLIC KEY)-----') {
                    New-TcpkFinding -Module 'creds' -RuleId 'keymaterial.public-cert' `
                        -Severity 'INFO' -Confidence 'Confirmed' `
                        -Title "Certificate/public key shipped: $($f.Name)" `
                        -File $f.FullName `
                        -Description 'Public certificate material (inventory). Relevant if used as a pinned trust anchor.'
                }
            }
            { $_ -in '.der','.cer','.crt' } {
                New-TcpkFinding -Module 'creds' -RuleId 'keymaterial.public-cert' `
                    -Severity 'INFO' -Confidence 'Confirmed' `
                    -Title "Certificate shipped: $($f.Name)" `
                    -File $f.FullName `
                    -Description 'Public certificate (inventory). Check whether it is added to a trust store at install (see Test-TcpkTrustStore).'
            }
            { $_ -in '.jks','.keystore','.ppk' } {
                New-TcpkFinding -Module 'creds' -RuleId 'keymaterial.keystore-present' `
                    -Severity 'LOW' -Confidence 'Confirmed' `
                    -Title "Key store shipped: $($f.Name)" `
                    -File $f.FullName -Cwe @('CWE-312') `
                    -Description 'A Java/PuTTY key store is shipped. Confirm it is not the production signing/identity key and that its password is not hardcoded.'
            }
        }
    }

    # ---- embedded PEM private keys inside first-party binaries / configs ----
    # Require a real base64 KEY BODY and a matching END marker -- not just the header.
    # A bare '-----BEGIN ... PRIVATE KEY-----' string is usually a UI placeholder, a
    # format label, or a detection regex (false positive), so the header alone must NOT
    # trigger a CRITICAL/HIGH leaked-key finding.
    # The body class allows ':' ',' '.' '-' as well as base64 so a legacy PKCS#1
    # ENCRYPTED key (RFC1421 "Proc-Type: 4,ENCRYPTED" / "DEK-Info: AES-128-CBC,<iv>"
    # header lines between BEGIN and the base64) still matches -- those punctuation
    # chars would otherwise break the body scan at the first ':' and miss the key.
    $rxPem = [regex]'-----BEGIN (RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----[A-Za-z0-9+/=\s\\:,.-]{100,6000}-----END (RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----'
    foreach ($pe in Get-TcpkPeFiles -Path $Path) {
        if (Test-TcpkIsFrameworkFile $pe.Name) { continue }
        if (Test-TcpkIsNativeNoise $pe.Name)   { continue }
        $text = Read-TcpkAllText -Path $pe.FullName
        if (-not $text) { continue }
        if ($rxPem.IsMatch($text)) {
            New-TcpkFinding -Module 'creds' -RuleId 'keymaterial.embedded-private-key' `
                -Severity 'HIGH' -Confidence 'Confirmed' `
                -Title "Embedded PEM private key in $($pe.Name)" `
                -File $pe.FullName -Evidence '-----BEGIN ... PRIVATE KEY----- block found in binary' `
                -Cwe @('CWE-321','CWE-798') `
                -Description 'A PEM private-key block is embedded directly in a compiled binary. Extracting it is trivial; the identity it represents is compromised.' `
                -Fix 'Remove the embedded key and rotate it. Provision keys at runtime from a protected store.'
        }
    }
}
