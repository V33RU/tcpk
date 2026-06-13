function Test-TcpkUpdateFlow {
<#
.SYNOPSIS
    F02. Update mechanism: signed manifest? signed payload? downgrade defense?

.DESCRIPTION
    Static analysis of the update flow. Extracts update / firmware / manifest
    URLs and contrasts with signature-verification keywords across first-party
    PEs. If update-flow keywords are present but signature-verification
    keywords are absent, emits a CRITICAL finding (supply-chain primitive --
    same pattern as a typical thick-client updater).

.PARAMETER Path
    File or directory.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $updateKw = @(
        'CheckForUpdate','UpdateAvailable','UpdateUrl','UpdateManifest',
        'DownloadUpdate','LatestVersion','update-manifest','/firmware'
    )
    # Signature-verification primitives. Deliberately narrow:
    # X509Chain was removed -- it's used in TLS handshake callbacks too, so
    # its presence does NOT mean update content is being verified.
    # WinVerifyTrust covers OS-level signature checks; the .NET ones below
    # are the only modern signature-verification call shapes.
    $sigKw = @(
        'RSA.VerifyData','RSA.VerifyHash','DSA.VerifyData','ECDsa.VerifyData',
        'SignedXml','SignedCms','Pkcs7','CmsSigned','WinVerifyTrust',
        'Authenticode','VerifySignature'
    )
    $urlRx = [regex]'https?://[A-Za-z0-9./?_=&%:#@~+\-]+'

    # Per-DLL tracking so we can require update + sig-verify in the SAME binary.
    # An SSH library or unrelated crypto DLL having Pkcs7 elsewhere does NOT
    # mean the update flow is signed.
    $updateDlls = @{}    # full-path -> true (DLL contains update-flow keywords)
    $sigDlls    = @{}    # full-path -> true (DLL contains sig-verify keywords)
    $updateUrls = @{}
    $updatePeSample = $null

    foreach ($pe in Get-TcpkPeFiles -Path $Path) {
        if (Test-TcpkIsFrameworkFile $pe.Name) { continue }
        $text = Read-TcpkAllText -Path $pe.FullName
        if (-not $text) { continue }

        foreach ($k in $updateKw) {
            if ($text.Contains($k)) {
                $updateDlls[$pe.FullName] = $true
                if (-not $updatePeSample) { $updatePeSample = $pe.FullName }
                break
            }
        }
        foreach ($k in $sigKw) {
            if ($text.Contains($k)) {
                $sigDlls[$pe.FullName] = $true
                break
            }
        }
        # Update-shaped URLs in any first-party PE
        foreach ($m in $urlRx.Matches($text)) {
            $u = $m.Value
            if ($u -match '(?i)update-manifest|/firmware|/updates?/') {
                $updateUrls[$u] = $pe.FullName
            }
        }
    }

    $hasUpdateFlow = $updateDlls.Count -gt 0
    # Require sig-verify in at least one DLL that ALSO has update-flow keywords.
    $hasSigVerification = $false
    foreach ($d in $updateDlls.Keys) {
        if ($sigDlls.ContainsKey($d)) { $hasSigVerification = $true; break }
    }

    foreach ($u in $updateUrls.Keys) {
        New-TcpkFinding -Module 'network' -RuleId 'update.url-found' `
            -Severity 'INFO' -Confidence 'Confirmed' `
            -Title "Update / firmware URL: $u" `
            -File $updateUrls[$u] -Evidence $u
    }

    if ($hasUpdateFlow -and -not $hasSigVerification) {
        New-TcpkFinding -Module 'network' -RuleId 'update.no-signature-verification' `
            -Severity 'CRITICAL' -Confidence 'Inferred' `
            -Title 'Update flow present; NO signature-verification primitives in first-party code' `
            -File $updatePeSample `
            -Evidence ("update keywords: " + ($updateKw -join ',') + " | sig keywords absent") `
            -Cwe @('CWE-494','CWE-345','CWE-347') `
            -Description 'If downloaded update content is not signature-verified before execution, anyone who can write to the update origin (or MITM the channel) achieves persistent RCE on every client. Confirm in ILSpy that DownloadUpdate / CheckForUpdate methods do not call any cryptographic verification path.' `
            -Fix 'Sign update manifests with an offline-keyed RSA signature; sign each downloaded payload (Authenticode or detached PKCS#7); verify before any extract/exec.'
    }
    # The positive "sig-verification referenced" case is NOT emitted as a finding: a single
    # string match falsely reassures (the verify call may be stale / off the download path).
}
