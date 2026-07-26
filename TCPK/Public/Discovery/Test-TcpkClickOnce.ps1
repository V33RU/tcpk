function Test-TcpkClickOnce {
<#
.SYNOPSIS
    Detect ClickOnce deployment hijack surfaces.

.DESCRIPTION
    ClickOnce (.appref-ms / .application / .manifest) deployments download and
    execute code from a remote server. If the deployment URL uses HTTP (not HTTPS),
    or the manifest requests FullTrust without code signing, the update channel is
    MITM-able for arbitrary code execution.

    Checks:
      1. .appref-ms shortcut files -- parse the deployment URL
      2. .application / .manifest XML -- deployment codeBase URL scheme
      3. FullTrust with missing or weak publisher identity
      4. HTTP deployment URLs (MITM-able update)

.PARAMETER Path
    File or directory to scan.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $dir = $Path
    try { if (-not (Get-Item -LiteralPath $Path).PSIsContainer) { $dir = Split-Path -Parent $Path } } catch { return }

    # --- Scan .appref-ms shortcuts ---
    $apprefFiles = @(Get-ChildItem -LiteralPath $dir -Recurse -File -Filter '*.appref-ms' -ErrorAction SilentlyContinue)
    foreach ($f in $apprefFiles) {
        try { $content = Get-Content -LiteralPath $f.FullName -Raw -ErrorAction Stop } catch { continue }
        if (-not $content) { continue }

        $parts = $content.Trim() -split '#'
        $deployUrl = $parts[0].Trim()

        if ($deployUrl -match '^http://') {
            New-TcpkFinding -Module 'static' -RuleId 'clickonce.http-deployment' `
                -Severity 'HIGH' -Confidence 'Confirmed' `
                -Title "ClickOnce deployment over plaintext HTTP: $($f.Name)" `
                -File $f.FullName `
                -Evidence "deployment URL: $deployUrl" `
                -Cwe @('CWE-494','CWE-319') `
                -Description ('This ClickOnce shortcut points to a deployment URL over plaintext HTTP. ' +
                    'An on-path attacker can serve a modified manifest and application binaries -- full ' +
                    'code execution with the user''s identity. ClickOnce apps can request FullTrust, ' +
                    'giving them unrestricted access to the machine.') `
                -Fix 'Move the ClickOnce deployment to an HTTPS endpoint and re-publish.'
        } elseif ($deployUrl -match '^https?://') {
            New-TcpkFinding -Module 'static' -RuleId 'clickonce.deployment-present' `
                -Severity 'INFO' -Confidence 'Confirmed' `
                -Title "ClickOnce deployment shortcut: $($f.Name)" `
                -File $f.FullName `
                -Evidence "deployment URL: $deployUrl" `
                -Cwe @('CWE-494') `
                -Description ('A ClickOnce deployment shortcut is present. Verify the deployment ' +
                    'server''s certificate and that the application manifest is signed with a ' +
                    'trusted publisher certificate.') `
                -Fix 'Ensure the deployment uses HTTPS with a valid certificate and the application manifest is code-signed.'
        }
    }

    # --- Scan .application and .manifest files ---
    $manifestFiles = @(Get-ChildItem -LiteralPath $dir -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Extension -in '.application','.manifest' -and $_.Length -lt 2MB })
    foreach ($f in $manifestFiles) {
        try { $raw = Get-Content -LiteralPath $f.FullName -Raw -ErrorAction Stop } catch { continue }
        if (-not $raw) { continue }

        if ($raw -notmatch 'urn:schemas-microsoft-com:asm') { continue }

        # Check deployment codeBase URL
        $codeBaseMatch = [regex]::Match($raw, 'codebase\s*=\s*"([^"]+)"', 'IgnoreCase')
        if ($codeBaseMatch.Success) {
            $cbUrl = $codeBaseMatch.Groups[1].Value
            if ($cbUrl -match '^http://') {
                New-TcpkFinding -Module 'static' -RuleId 'clickonce.manifest-http' `
                    -Severity 'HIGH' -Confidence 'Confirmed' `
                    -Title "ClickOnce manifest references HTTP codeBase: $($f.Name)" `
                    -File $f.FullName `
                    -Evidence "codebase=$cbUrl" `
                    -Cwe @('CWE-494','CWE-319') `
                    -Description ('The ClickOnce deployment manifest specifies a codeBase URL over plaintext ' +
                        'HTTP. The application download and all updates transit in the clear -- an on-path ' +
                        'attacker can replace the manifest or binaries with malicious ones.') `
                    -Fix 'Change the deployment codeBase to HTTPS.'
            }
        }

        # Check trust level -- FullTrust is the dangerous one
        if ($raw -match 'permissionSet\s*=\s*"FullTrust"' -or $raw -match 'Unrestricted\s*=\s*"true"') {
            $hasSig = ($raw -match 'publisherIdentity') -or ($raw -match '<Signature' -and $raw -match 'dsig:')
            $sev = if ($hasSig) { 'MEDIUM' } else { 'HIGH' }
            $sigNote = if ($hasSig) {
                'A publisher identity / signature block IS present -- verify it uses a trusted CA.'
            } else {
                'No publisher identity or XML signature block was found -- the manifest may not be code-signed.'
            }
            New-TcpkFinding -Module 'static' -RuleId 'clickonce.full-trust' `
                -Severity $sev -Confidence 'Confirmed' `
                -Title "ClickOnce requests FullTrust permissions: $($f.Name)" `
                -File $f.FullName `
                -Evidence "permissionSet=FullTrust or Unrestricted=true; signed=$hasSig" `
                -Cwe @('CWE-250','CWE-494') `
                -Description ('This ClickOnce application requests FullTrust (unrestricted CAS permissions), ' +
                    'meaning it runs with the same privileges as a locally installed application. If the ' +
                    'deployment channel is compromised, the attacker gets full code execution. ' + $sigNote) `
                -Fix 'Request only the minimum CAS permission set the application needs. Ensure the manifest is signed with a trusted Authenticode certificate.'
        }
    }
}
