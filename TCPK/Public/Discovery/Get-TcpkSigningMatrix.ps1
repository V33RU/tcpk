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
        $signed = 'NO'; $status = 'UNKNOWN'; $signer = ''; $algo = ''; $expires = ''; $type = 'None'
        $sig = $null
        try { $sig = Get-AuthenticodeSignature -FilePath $pe.FullName } catch { }

        if ($sig) {
            try { $type = "$($sig.SignatureType)" } catch { }
            $cert = $sig.SignerCertificate
            if ($cert) {
                if ("$($cert.Subject)" -match 'CN=([^,]+)') { $signer = $matches[1].Trim('"').Trim() }
                else { $signer = "$($cert.Subject)" }
                try { $algo = "$($cert.SignatureAlgorithm.FriendlyName)" } catch { }
                try { $expires = $cert.NotAfter.ToString('yyyy-MM-dd') } catch { }
            }
            switch ("$($sig.Status)") {
                'Valid'        { $signed = 'YES'; $status = if ($type -match '(?i)catalog') { 'CATALOG' } else { 'SIGNED' } }
                'NotSigned'    { $signed = if ($isMsixDir) { 'CATALOG' } else { 'NO' }; $status = if ($isMsixDir) { 'CATALOG' } else { 'UNSIGNED' } }
                'HashMismatch' { $signed = 'NO'; $status = 'TAMPERED' }
                'NotTrusted'   { $signed = 'NO'; $status = 'UNTRUSTED' }
                'UnknownError' { $signed = if ($isMsixDir) { 'CATALOG' } else { 'NO' }; $status = if ($isMsixDir) { 'CATALOG' } else { 'UNKNOWN' } }
                default        { $signed = 'NO'; $status = "$($sig.Status)".ToUpper() }
            }
        } elseif ($isMsixDir) {
            $signed = 'CATALOG'; $status = 'CATALOG'
        }

        [pscustomobject]@{
            DLL       = $pe.Name
            Signed    = $signed
            Status    = $status
            Signer    = $signer
            Algorithm = $algo
            Expires   = $expires
            Type      = $type
            Path      = $pe.FullName
        }
    }
}
