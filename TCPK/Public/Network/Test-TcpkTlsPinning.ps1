function Test-TcpkTlsPinning {
<#
.SYNOPSIS
    F01. TLS certificate pinning detection.

.DESCRIPTION
    Scans first-party PEs for pinning markers (thumbprint comparison,
    pinned-cert references) and contrasts with HTTP-client usage. Emits:
      - INFO if pinning markers present (Inferred: confirm in ILSpy)
      - LOW  if HTTP client used but no pinning markers anywhere

    Pinning is a hardening signal, not a vulnerability when absent.

.PARAMETER Path
    File or directory.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $pinningMarkers = @(
        'GetCertHashString','Thumbprint',
        'PublicKey.EncodedKeyValue','SubjectPublicKeyInfo',
        'PinnedCertificate','PinnedThumbprint','CertificatePinning','CertPin'
    )
    $httpMarkers = @('HttpClient','WebClient','HttpWebRequest','SocketsHttpHandler')

    $foundPinning = $false; $pinningSample = $null
    $foundHttp = $false;    $httpSample = $null

    foreach ($pe in Get-TcpkPeFiles -Path $Path) {
        if (Test-TcpkIsFrameworkFile $pe.Name) { continue }
        $text = Read-TcpkAllText -Path $pe.FullName
        if (-not $text) { continue }
        # Skip the bundled Chromium/Electron runtime -- its string table is framework code,
        # not first-party (a stray 'Thumbprint' there is not evidence the APP pins).
        if (Test-TcpkIsChromiumRuntime -Name $pe.Name -Text $text) { continue }
        foreach ($m in $pinningMarkers) {
            if ($text.Contains($m)) {
                $foundPinning = $true
                if (-not $pinningSample) { $pinningSample = @{File=$pe.FullName; Marker=$m} }
                break
            }
        }
        foreach ($m in $httpMarkers) {
            if ($text.Contains($m)) {
                $foundHttp = $true
                if (-not $httpSample) { $httpSample = @{File=$pe.FullName; Marker=$m} }
                break
            }
        }
    }

    if ($foundPinning) {
        New-TcpkFinding -Module 'network' -RuleId 'tls.pinning-present' `
            -Severity 'INFO' -Confidence 'Inferred' `
            -Title 'TLS cert-pinning markers present' `
            -File $pinningSample.File -Evidence $pinningSample.Marker `
            -Description 'At least one first-party binary references pinning primitives. Confirm in ILSpy that the pin is actually checked at TLS handshake time.'
    }
    elseif ($foundHttp) {
        New-TcpkFinding -Module 'network' -RuleId 'tls.pinning-absent' `
            -Severity 'LOW' -Confidence 'Inferred' `
            -Title 'HTTP client used; no cert-pinning markers found' `
            -File $httpSample.File -Evidence "uses $($httpSample.Marker); no pinning keywords" `
            -Cwe @('CWE-295') `
            -Description 'App trusts the system root store. Acceptable for most consumer apps; raise to HIGH for high-value targets where corporate-CA MITM is in-threat-model.' `
            -Fix 'For sensitive backends, pin the leaf or root cert thumbprint via ServerCertificateCustomValidationCallback (and confirm the callback actually pins, not just returns true).'
    }
}
