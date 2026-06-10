function Get-TcpkSigningMatrix {
<#
.SYNOPSIS
    Per-DLL code-signing matrix (signed / not signed -- information only).

.DESCRIPTION
    Returns a per-PE row showing whether each shipped EXE/DLL is Authenticode
    signed, who signed it, and the certificate's hash + expiry. This is the
    signing counterpart to Get-TcpkPeHardening: a complete at-a-glance inventory,
    NOT a findings list. (Test-TcpkSignature is the one that emits findings for
    unsigned / tampered / expired binaries.)

    MSIX-extracted packages: the individual PEs inside an MSIX are not separately
    Authenticode-signed -- they are covered by the package CodeIntegrity catalog,
    so for an extracted MSIX dir each PE is reported as CATALOG (not UNSIGNED).

    Status values:
      SIGNED     valid embedded Authenticode signature
      CATALOG    covered by an MSIX CodeIntegrity catalog (package-signed)
      EXPIRED-TS signed but cert is past NotAfter -- still valid because the signature is timestamped (informational)
      EXPIRED    signed but cert is past NotAfter AND not timestamped (no longer establishes provenance)
      UNSIGNED   no signature
      TAMPERED   signature present but file hash does not match (modified after signing)
      UNTRUSTED  signed but chain does not validate (untrusted root / revoked)
      UNKNOWN    indeterminate (e.g. catalog-only outside MSIX, or non-PE)

.PARAMETER Path
    File or directory.

.OUTPUTS
    [pscustomobject] per PE (NOT a [TcpkFinding]).
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Assert-TcpkWindows 'Get-TcpkSigningMatrix')) { return }

    $item = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
    if (-not $item) { return }
    $isMsixDir = $item.PSIsContainer -and (Test-Path -LiteralPath (Join-Path $item.FullName 'AppxManifest.xml'))

    foreach ($pe in Get-TcpkPeFiles -Path $Path) {
        $signed = 'NO'; $status = 'UNKNOWN'; $signer = ''; $algo = ''; $validFrom = ''; $expires = ''; $type = 'None'; $ts = $false
        $subject = ''; $issuer = ''; $serial = ''; $thumb = ''; $keySize = ''; $eku = ''
        $sig = $null
        try { $sig = Get-AuthenticodeSignature -FilePath $pe.FullName } catch { }

        if ($sig) {
            try { $type = "$($sig.SignatureType)" } catch { }
            try { $ts = [bool]$sig.TimeStamperCertificate } catch { }
            $cert = $sig.SignerCertificate
            if ($cert) {
                $subject = "$($cert.Subject)"
                if ($subject -match 'CN=([^,]+)') { $signer = $matches[1].Trim('"').Trim() } else { $signer = $subject }
                $issuer = "$($cert.Issuer)"
                try { $algo = "$($cert.SignatureAlgorithm.FriendlyName)" } catch { }
                try { $validFrom = $cert.NotBefore.ToString('yyyy-MM-dd') } catch { }
                try { $expires = $cert.NotAfter.ToString('yyyy-MM-dd') } catch { }
                try { $serial = "$($cert.SerialNumber)" } catch { }
                try { $thumb = "$($cert.Thumbprint)" } catch { }
                try { $keySize = "$($cert.PublicKey.Key.KeySize)" } catch { }
                try { $eku = (@($cert.EnhancedKeyUsageList | ForEach-Object { $_.FriendlyName } | Where-Object { $_ }) -join ', ') } catch { }
            }
            switch ("$($sig.Status)") {
                'Valid'        { $signed = 'YES'; $status = if ($type -match '(?i)catalog') { 'CATALOG' } else { 'SIGNED' } }
                'NotSigned'    { $signed = if ($isMsixDir) { 'CATALOG' } else { 'NO' }; $status = if ($isMsixDir) { 'CATALOG' } else { 'UNSIGNED' } }
                'HashMismatch' { $signed = 'NO'; $status = 'TAMPERED' }
                'NotTrusted'   { $signed = 'NO'; $status = 'UNTRUSTED' }
                'UnknownError' { $signed = if ($isMsixDir) { 'CATALOG' } else { 'NO' }; $status = if ($isMsixDir) { 'CATALOG' } else { 'UNKNOWN' } }
                default        { $signed = 'NO'; $status = "$($sig.Status)".ToUpper() }
            }
            # Flag an EXPIRED signing certificate. The signature can still be valid if
            # it was timestamped, but the cert itself is past NotAfter -- surface it so
            # it is not buried as just a date in the Expires column.
            if ($cert -and $status -in 'SIGNED','CATALOG') {
                try {
                    if ($cert.NotAfter -lt (Get-Date)) {
                        # EXPIRED-TS = cert expired BUT timestamped, so the signature is
                        # still valid (informational); EXPIRED = expired with no timestamp
                        # (a real provenance problem).
                        $status = if ($ts) { 'EXPIRED-TS' } else { 'EXPIRED' }
                    }
                } catch { }
            }
        } elseif ($isMsixDir) {
            $signed = 'CATALOG'; $status = 'CATALOG'
        }

        [pscustomobject]@{
            DLL        = $pe.Name
            Signed     = $signed
            Status     = $status
            Signer     = $signer
            Issuer     = $issuer
            Algorithm  = $algo
            KeySize    = $keySize
            ValidFrom  = $validFrom
            Expires    = $expires
            Serial     = $serial
            Thumbprint = $thumb
            Eku        = $eku
            Type       = $type
            Subject    = $subject
            Path       = $pe.FullName
        }
    }
}
