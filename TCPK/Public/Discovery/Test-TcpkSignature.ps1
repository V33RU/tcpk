function Test-TcpkSignature {
<#
.SYNOPSIS
    A01. Authenticode chain validation.

.DESCRIPTION
    For MSIX/AppX/MSIXBundle packages: validates the package-level signature.
    Individual PEs INSIDE an MSIX are NOT separately Authenticode-signed --
    they are covered by AppxMetadata\CodeIntegrity.cat. So per-PE checks are
    skipped for MSIX-context targets; the catalog status is reported by
    Test-TcpkCodeIntegrity instead.

    For non-MSIX targets (classic Win32 installs, single PEs, loose folders
    of PEs): validates Authenticode signature on every PE.

.PARAMETER Path
    File or directory.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Assert-TcpkWindows 'Test-TcpkSignature')) { return }

    # A10. Weakness checks on an otherwise-Valid signature. Emitted findings
    # bubble up to this cmdlet's output stream when invoked with '&'.
    $emitWeak = {
        param([object]$sig, [string]$file, [string]$label)
        if (-not $sig -or $sig.Status -ne 'Valid' -or -not $sig.SignerCertificate) { return }
        $cert = $sig.SignerCertificate
        if (-not $sig.TimeStamperCertificate) {
            New-TcpkFinding -Module 'static' -RuleId 'authenticode.no-timestamp' `
                -Severity 'MEDIUM' -Confidence 'Confirmed' `
                -Title "$label signature is not timestamped" `
                -File $file -Evidence "signer=$($cert.Subject); NotAfter=$($cert.NotAfter.ToString('u'))" `
                -Cwe @('CWE-347') `
                -Description 'The Authenticode signature has no RFC3161 trusted timestamp. Once the signing certificate expires the signature stops validating, weakening long-term integrity and making re-signing/tampering easier to disguise.' `
                -Fix 'Counter-sign with a trusted timestamp authority (signtool /tr <ts-url> /td sha256).'
        }
        if ($cert.NotAfter -lt (Get-Date)) {
            if ($sig.TimeStamperCertificate) {
                # Timestamped: a trusted RFC3161 countersignature dated within the cert's
                # validity keeps the signature valid AFTER the cert expires (that is the
                # whole point of timestamping). So this is informational, NOT a real flaw
                # -- flagging it MEDIUM would be a false positive on properly-signed code.
                New-TcpkFinding -Module 'static' -RuleId 'authenticode.signer-expired' `
                    -Severity 'INFO' -Confidence 'Confirmed' `
                    -Title "$label signing certificate expired, but signature is timestamped (still valid)" `
                    -File $file -Evidence "signer=$($cert.Subject); certExpired=$($cert.NotAfter.ToString('u')); timestamped=yes" `
                    -Cwe @('CWE-347') `
                    -Description 'The signing certificate is past its validity period, but the signature carries a trusted RFC3161 timestamp dated within that period, so it still establishes valid provenance. Informational only.' `
                    -Fix 'No immediate action. Re-sign at the next release to keep the chain current.'
            } else {
                New-TcpkFinding -Module 'static' -RuleId 'authenticode.signer-expired' `
                    -Severity 'MEDIUM' -Confidence 'Confirmed' `
                    -Title "$label signing certificate is expired (no timestamp)" `
                    -File $file -Evidence "signer=$($cert.Subject); expired=$($cert.NotAfter.ToString('u')); timestamped=no" `
                    -Cwe @('CWE-347','CWE-324') `
                    -Description 'The signing certificate has expired and the signature is NOT timestamped, so it no longer establishes valid provenance.' `
                    -Fix 'Re-sign with a current certificate and a trusted RFC3161 timestamp.'
            }
        }
        $algo = ''
        try { $algo = "$($cert.SignatureAlgorithm.FriendlyName)" } catch { }
        if ($algo -match '(?i)sha1|md5') {
            New-TcpkFinding -Module 'static' -RuleId 'authenticode.weak-cert-hash' `
                -Severity 'MEDIUM' -Confidence 'Confirmed' `
                -Title "$label signing certificate uses a weak hash ($algo)" `
                -File $file -Evidence "SignatureAlgorithm=$algo; signer=$($cert.Subject)" `
                -Cwe @('CWE-327','CWE-347') `
                -Description 'The signing certificate chain uses SHA-1/MD5, which are collision-prone and deprecated for code signing.' `
                -Fix 'Obtain a SHA-256 (or stronger) code-signing certificate and re-sign.'
        }
    }

    $item = Get-Item -LiteralPath $Path -ErrorAction Stop

    # --- Case 1: MSIX/AppX file --- validate package signature, defer PE check to CodeIntegrity ---
    if (-not $item.PSIsContainer -and
        $item.Extension.ToLowerInvariant() -in '.msix','.appx','.msixbundle','.appxbundle') {
        $sig = Get-AuthenticodeSignature -FilePath $Path
        if ($sig.Status -ne 'Valid') {
            New-TcpkFinding -Module 'static' -RuleId 'authenticode.msix-not-valid' `
                -Severity 'CRITICAL' -Confidence 'Confirmed' `
                -Title "MSIX signature status = $($sig.Status)" `
                -File $Path -Evidence $sig.StatusMessage -Cwe @('CWE-347') `
                -Fix 'Sign with a trusted, non-revoked certificate; include a timestamp.'
        } else {
            & $emitWeak $sig $Path 'MSIX package'
        }
        return    # Catalog covers internal PEs; Test-TcpkCodeIntegrity reports on the catalog.
    }

    # --- Case 2: directory --- distinguish MSIX-extracted vs classic Win32 ---
    if ($item.PSIsContainer) {
        $isMsixDir = Test-Path -LiteralPath (Join-Path $item.FullName 'AppxManifest.xml')
        if ($isMsixDir) {
            # Already-extracted MSIX. Catalog covers PEs; only emit a status finding.
            $cat = Join-Path $item.FullName 'AppxMetadata\CodeIntegrity.cat'
            if (-not (Test-Path $cat)) {
                New-TcpkFinding -Module 'static' -RuleId 'authenticode.msix-no-catalog' `
                    -Severity 'MEDIUM' -Confidence 'Confirmed' `
                    -Title 'MSIX package has no CodeIntegrity.cat catalog' `
                    -File $item.FullName -Cwe @('CWE-347') `
                    -Description 'Without a CodeIntegrity catalog, package-level integrity enforcement is weakened.' `
                    -Fix 'Ensure AppxMetadata\CodeIntegrity.cat is present and Valid before release.'
            } else {
                $catSig = try { Get-AuthenticodeSignature -FilePath $cat } catch { $null }
                & $emitWeak $catSig $cat 'CodeIntegrity catalog'
            }
            return
        }
    }

    # --- Case 3: non-MSIX --- per-PE Authenticode validation ---
    foreach ($pe in Get-TcpkPeFiles -Path $Path) {
        $sig = Get-AuthenticodeSignature -FilePath $pe.FullName
        switch ($sig.Status) {
            'Valid'       { & $emitWeak $sig $pe.FullName $pe.Name; continue }
            'NotSigned' {
                New-TcpkFinding -Module 'static' -RuleId 'authenticode.pe-not-signed' `
                    -Severity 'MEDIUM' -Confidence 'Confirmed' `
                    -Title "$($pe.Name) is not Authenticode-signed" `
                    -File $pe.FullName -Cwe @('CWE-347','CWE-494') `
                    -Fix 'Sign every shipped EXE/DLL with the company code-signing certificate.'
            }
            'HashMismatch' {
                New-TcpkFinding -Module 'static' -RuleId 'authenticode.tampered' `
                    -Severity 'HIGH' -Confidence 'Confirmed' `
                    -Title "$($pe.Name) HashMismatch -- file modified after signing" `
                    -File $pe.FullName -Evidence $sig.StatusMessage -Cwe @('CWE-347')
            }
            'UnknownError' {
                # UnknownError = catalog-only or non-PE. Skipped, not a finding.
                continue
            }
            default {
                New-TcpkFinding -Module 'static' `
                    -RuleId ('authenticode.' + $sig.Status.ToString().ToLower()) `
                    -Severity 'MEDIUM' -Confidence 'Confirmed' `
                    -Title "$($pe.Name) signature status = $($sig.Status)" `
                    -File $pe.FullName -Evidence $sig.StatusMessage -Cwe @('CWE-347')
            }
        }
    }
}
