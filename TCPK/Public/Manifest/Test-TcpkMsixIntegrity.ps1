function Test-TcpkMsixIntegrity {
<#
.SYNOPSIS
    B11. MSIX package-integrity checks the other MSIX cmdlets do not cover:
    Sparse / Modification packages, publisher-vs-signer mismatch, and a SHA-1
    block map.

.DESCRIPTION
    Three distinct integrity questions about a shipped MSIX package:

      msix.sparse-or-modification-package   HIGH   Confirmed
        A Sparse package (uap10:AllowExecution) registers an AppxManifest identity
        against an EXTERNAL folder tree with no sealed payload container - so code
        that runs under the package identity lives outside the signed .msix, on a
        path the vendor's signature does not cover. A Modification package
        (uap4:MainPackageDependency) grafts onto a main package and can add
        extensions / file associations / startup entries to it. Both widen the
        trust boundary the base MSIX signature is supposed to seal.

      msix.publisher-signer-mismatch        HIGH   Confirmed
        The Package/Identity/@Publisher distinguished name in AppxManifest.xml
        does not match the subject of the certificate that actually signed
        AppxSignature.p7x. Windows derives the package family name (and therefore
        the package identity, its storage, its capabilities) from the manifest
        Publisher, but only the signer cert is cryptographically bound. A mismatch
        means the package identity is asserting a publisher it was not signed by -
        a spoofing / confused-deputy surface.

      msix.blockmap-sha1                     MEDIUM Confirmed
        AppxBlockMap.xml declares HashMethod = SHA1. The block map is what Windows
        streams and integrity-checks the package payload against; SHA-1 is
        collision-attackable, so a crafted payload block can in principle be
        substituted while keeping the block-map hash intact. MSIX tooling has
        emitted SHA-256 block maps for years; a SHA-1 block map is an old package.

.PARAMETER Path
    MSIX / AppX file or an extracted package directory.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { return }

    $expanded = Expand-TcpkMsix -Path $Path
    if (-not $expanded) { return }

    $m = Read-TcpkAppxManifest -ExpandedPath $expanded
    if (-not $m) { return }
    $nsm = Get-TcpkAppxNsMgr -Manifest $m
    if (-not $nsm) { return }

    # ---- msix.sparse-or-modification-package -----------------------------------
    $sparse = $m.DocumentElement.SelectNodes('//*[local-name()="AllowExecution"]')
    $modDep = $m.DocumentElement.SelectNodes('//*[local-name()="MainPackageDependency"]')
    if (($sparse -and $sparse.Count -gt 0) -or ($modDep -and $modDep.Count -gt 0)) {
        $kind = if ($modDep -and $modDep.Count -gt 0) { 'Modification package (MainPackageDependency)' } else { 'Sparse package (AllowExecution)' }
        New-TcpkFinding -Module 'manifest' -RuleId 'msix.sparse-or-modification-package' `
            -Severity 'HIGH' -Confidence 'Confirmed' `
            -Title "MSIX is a $kind" `
            -File $Path -Evidence $kind `
            -Cwe @('CWE-345','CWE-668') `
            -Description ('The package registers a Windows package identity that is not fully sealed inside a ' +
                'signed .msix payload. A Sparse package grants identity to code living in an external folder ' +
                'tree the signature does not cover; a Modification package grafts onto a base package and can ' +
                'add extensions, file associations, protocol handlers or startup entries to it. Either way the ' +
                'code that runs under the package identity can sit outside the sealed, signed payload the base ' +
                'MSIX signature is supposed to bound.') `
            -Fix 'For a Sparse package, host the executable content inside the sealed MSIX payload and remove uap10:AllowExecution unless the external-location trust is deliberate and the external tree is admin-only. For a Modification package, confirm the base package it modifies actually expects and audits every extension the modification adds.'
    }

    # ---- msix.publisher-signer-mismatch ----------------------------------------
    # Read the manifest Publisher DN.
    $manifestPublisher = ''
    try {
        $idNode = $m.DocumentElement.SelectSingleNode('//*[local-name()="Identity"]')
        if ($idNode) { $manifestPublisher = "$($idNode.GetAttribute('Publisher'))" }
    } catch { }

    $sigPath = Join-Path $expanded 'AppxSignature.p7x'
    if ($manifestPublisher -and (Test-Path -LiteralPath $sigPath)) {
        $signerSubject = ''
        try {
            # AppxSignature.p7x begins with a 4-byte 'PKCX' magic before the raw PKCS#7.
            $bytes = [IO.File]::ReadAllBytes($sigPath)
            $offset = 0
            if ($bytes.Length -gt 4 -and $bytes[0] -eq 0x50 -and $bytes[1] -eq 0x4B -and $bytes[2] -eq 0x43 -and $bytes[3] -eq 0x58) {
                $offset = 4
            }
            $der = New-Object byte[] ($bytes.Length - $offset)
            [Array]::Copy($bytes, $offset, $der, 0, $der.Length)
            $cms = New-Object System.Security.Cryptography.Pkcs.SignedCms
            $cms.Decode($der)
            if ($cms.SignerInfos.Count -gt 0 -and $cms.SignerInfos[0].Certificate) {
                $signerSubject = "$($cms.SignerInfos[0].Certificate.Subject)"
            }
        } catch { $signerSubject = '' }

        if ($signerSubject) {
            # Normalise both DNs (order-insensitive, whitespace-insensitive) before comparing.
            $normP = (($manifestPublisher -split ',' | ForEach-Object { $_.Trim() }) | Sort-Object) -join ','
            $normS = (($signerSubject -split ',' | ForEach-Object { $_.Trim() }) | Sort-Object) -join ','
            if ($normP -ne $normS) {
                New-TcpkFinding -Module 'manifest' -RuleId 'msix.publisher-signer-mismatch' `
                    -Severity 'HIGH' -Confidence 'Confirmed' `
                    -Title 'MSIX manifest Publisher does not match the signing certificate subject' `
                    -File $Path -Evidence "manifest Publisher=$manifestPublisher | signer subject=$signerSubject" `
                    -Cwe @('CWE-345','CWE-347') `
                    -Description ('Windows derives the package family name and package identity from the ' +
                        'AppxManifest Publisher DN, but only the certificate that signed AppxSignature.p7x is ' +
                        'cryptographically bound to the package. When the manifest asserts a Publisher the ' +
                        'signer certificate does not carry, the package claims an identity it was not signed ' +
                        'by. On a normally-installed package Windows enforces the match; a mismatch here means ' +
                        'the package was re-manifested after signing, or is a test/dev artefact that would fail ' +
                        'a clean install - either way it is not the identity it claims.') `
                    -Fix 'Re-sign the package with a certificate whose Subject exactly equals the manifest Publisher DN. If the Publisher was changed intentionally, re-sign after the change; the two must be byte-identical (order-insensitive) for Windows to install the package.'
            }
        }
    }

    # ---- msix.blockmap-sha1 ----------------------------------------------------
    $bmPath = Join-Path $expanded 'AppxBlockMap.xml'
    if (Test-Path -LiteralPath $bmPath) {
        $bmText = ''
        try { $bmText = [IO.File]::ReadAllText($bmPath) } catch { }
        if ($bmText -match '(?i)HashMethod\s*=\s*"[^"]*sha1[^"]*"') {
            $hm = ([regex]::Match($bmText, '(?i)HashMethod\s*=\s*"([^"]+)"')).Groups[1].Value
            New-TcpkFinding -Module 'manifest' -RuleId 'msix.blockmap-sha1' `
                -Severity 'MEDIUM' -Confidence 'Confirmed' `
                -Title 'MSIX AppxBlockMap uses a SHA-1 hash method' `
                -File $bmPath -Evidence "HashMethod=$hm" `
                -Cwe @('CWE-328','CWE-327') `
                -Description ('AppxBlockMap.xml declares a SHA-1 HashMethod. The block map is what Windows ' +
                    'integrity-checks the streamed package payload against. SHA-1 is collision-attackable, so ' +
                    'a payload block could in principle be substituted while keeping the block-map hash intact. ' +
                    'Modern MSIX tooling emits SHA-256 block maps; a SHA-1 block map indicates an old package ' +
                    'or a non-standard packer.') `
                -Fix 'Re-package with current MSIX tooling (makeappx / MSIX Packaging Tool), which emits a SHA-256 block map. Do not hand-author a SHA-1 block map.'
        }
    }
}
