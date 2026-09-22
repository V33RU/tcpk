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
    $updateDlls = @{}    # full-path -> string[] of the update keywords ACTUALLY found in it
    $sigDlls    = @{}    # full-path -> true (DLL contains sig-verify keywords)
    $updateUrls = @{}
    $updatePeSample = $null

    foreach ($pe in Get-TcpkPeFiles -Path $Path) {
        # Skip non-first-party binaries: the Electron main exe embeds Chromium console-warning
        # text with doc links (e.g. the document.write /updates/ page) that the URL heuristic
        # misreads as an update endpoint -- a false positive attributed to the app.
        if (-not (Test-TcpkIsFirstParty -Name $pe.Name -SizeBytes $pe.Length -Path $pe.FullName)) { continue }
        $text = Read-TcpkAllText -Path $pe.FullName
        if (-not $text) { continue }

        # Collect EVERY keyword that matched, and do not break on the first one.
        #
        # This loop used to set a boolean and break, so the identity of the match was thrown
        # away before anything could report it. The finding below then built its Evidence by
        # joining $updateKw, the hardcoded CANDIDATE list, which made the Evidence a
        # compile-time constant: identical for every target ever scanned, and asserting that
        # all eight keywords were observed when one may have matched. A finding must never
        # state an observation that was not made.
        $peHits = New-Object 'System.Collections.Generic.List[string]'
        foreach ($k in $updateKw) {
            if ($text.Contains($k)) { $peHits.Add($k) }
        }
        if ($peHits.Count -gt 0) {
            $updateDlls[$pe.FullName] = @($peHits.ToArray())
            if (-not $updatePeSample) { $updatePeSample = $pe.FullName }
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
        # Evidence is built from what was OBSERVED, per binary, never from the candidate list.
        $obsKw = New-Object 'System.Collections.Generic.List[string]'
        $parts = New-Object 'System.Collections.Generic.List[string]'
        foreach ($d in ($updateDlls.Keys | Sort-Object)) {
            $kws = @($updateDlls[$d])
            foreach ($k in $kws) { if (-not $obsKw.Contains($k)) { $obsKw.Add($k) } }
            if ($parts.Count -lt 10) { $parts.Add(("{0}: {1}" -f (Split-Path $d -Leaf), ($kws -join ','))) }
        }
        $evi = "update keywords observed: " + (($obsKw | Sort-Object) -join ',') +
               " | in " + $updateDlls.Count + " first-party binary(ies): " + ($parts -join '; ') +
               " | no signature-verification keyword in any of them"
        if ($updateDlls.Count -gt 10) { $evi = $evi + " ...(+" + ($updateDlls.Count - 10) + " more)" }

        # -File is the first binary that matched, which is enumeration-order dependent and so
        # is not on its own an honest answer to "where". Affected carries the real set.
        $agg = New-TcpkFinding -Module 'network' -RuleId 'update.no-signature-verification' `
            -Severity 'CRITICAL' -Confidence 'Inferred' `
            -Title 'Update flow present; NO signature-verification primitives in first-party code' `
            -File $updatePeSample `
            -Evidence $evi `
            -Cwe @('CWE-494','CWE-345','CWE-347') `
            -Description 'If downloaded update content is not signature-verified before execution, anyone who can write to the update origin (or MITM the channel) achieves persistent RCE on every client. Confirm in ILSpy that DownloadUpdate / CheckForUpdate methods do not call any cryptographic verification path.' `
            -Fix 'Sign update manifests with an offline-keyed RSA signature; sign each downloaded payload (Authenticode or detached PKCS#7); verify before any extract/exec.'
        $agg.Affected = [string[]]@($updateDlls.Keys | Sort-Object)
        $agg
    }
    # The positive "sig-verification referenced" case is NOT emitted as a finding: a single
    # string match falsely reassures (the verify call may be stale / off the download path).
}
