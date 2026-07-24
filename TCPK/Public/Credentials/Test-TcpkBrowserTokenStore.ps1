function Test-TcpkBrowserTokenStore {
<#
.SYNOPSIS
    D08. Chromium / Electron token + cookie store, and its encryption strength
    (App-Bound Encryption vs plain DPAPI).

.DESCRIPTION
    Electron / CEF / NW.js apps embed a full Chromium profile, usually under
    %APPDATA%\<AppName>\ or %LOCALAPPDATA%\<AppName>\User Data\. That profile holds
    the same high-value stores a browser does: Cookies (session tokens), Login Data
    (saved passwords), Web Data (autofill). These are the #1 infostealer target.

    The store is encrypted with a key kept in the profile's "Local State" under
    os_crypt:
      * encrypted_key            -> DPAPI-only (pre-Chrome 127). Any code running as
                                    the current user can decrypt every cookie/password.
      * app_bound_encrypted_key  -> App-Bound Encryption (Chrome 127+, Jul 2024).
                                    Bound to the app via a SYSTEM service; raises the
                                    bar, but multiple public bypasses exist (2024-25).

    This reports which protection the app's profile uses, so the engagement can call
    the at-rest token risk accurately. (Complements Test-TcpkWebViewCreds, which
    covers the packaged-WebView2 Edge profile.)

.PARAMETER NameLike
    Identity terms (app / vendor names) used to locate the profile folder. Required
    -- without terms this returns nothing (it will not survey every user profile).

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([string[]]$NameLike)

    if (-not (Assert-TcpkWindows 'Test-TcpkBrowserTokenStore')) { return }
    $terms = Get-TcpkNameTerms -NameLike $NameLike
    if (-not $terms.Count) { return }

    $bases = @($env:APPDATA, $env:LOCALAPPDATA) | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -Unique
    $markerLeaves = @('Cookies', 'Login Data', 'Web Data')
    $seenProfiles = New-Object System.Collections.Generic.HashSet[string]

    foreach ($base in $bases) {
        # only descend into top-level app dirs whose name matches a term
        $appDirs = Get-ChildItem -LiteralPath $base -Directory -ErrorAction SilentlyContinue |
            Where-Object { Test-TcpkTermMatch -Text $_.Name -Terms $terms }

        foreach ($app in $appDirs) {
            # bounded recursive hunt for Chromium store markers
            $markers = Get-ChildItem -LiteralPath $app.FullName -Recurse -Depth 3 -File -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -in $markerLeaves -and $_.Length -gt 0 }

            foreach ($m in $markers) {
                $profileDir = Split-Path -Parent $m.FullName
                $title = switch ($m.Name) {
                    'Cookies'    { 'Cookies (session tokens)' }
                    'Login Data' { 'Login Data (saved passwords)' }
                    'Web Data'   { 'Web Data (autofill / cards)' }
                    default      { $m.Name }
                }
                $sev = if ($m.Name -eq 'Web Data') { 'MEDIUM' } else { 'HIGH' }
                New-TcpkFinding -Module 'creds' -RuleId 'browser.cred-store' `
                    -Severity $sev -Confidence 'Confirmed' `
                    -Title "Chromium profile: $title" `
                    -File $m.FullName -Evidence "size=$($m.Length) modified=$($m.LastWriteTime)" `
                    -Cwe @('CWE-522') `
                    -Description 'A Chromium-managed credential / token store belonging to the app. Encrypted against other users, but readable by any code running as the current user (the classic infostealer primitive).' `
                    -Fix 'Clear session tokens on logout; do not persist long-lived auth cookies; prefer OS credential vaults for refresh tokens.'

                # classify the os_crypt key strength once per Local State.
                # Local State sits at the "User Data" root; the cookie store can be
                # several levels below (Default\Network\Cookies), so walk upward.
                $localState = $null
                $d = $profileDir
                for ($up = 0; $up -lt 5 -and $d; $up++) {
                    $cand = Join-Path $d 'Local State'
                    if (Test-Path -LiteralPath $cand) { $localState = $cand; break }
                    $d = Split-Path -Parent $d
                }
                if ($localState -and $seenProfiles.Add($localState)) {
                    $osc = $null
                    try { $osc = (Get-Content -LiteralPath $localState -Raw | ConvertFrom-Json).os_crypt } catch { }
                    if ($osc) {
                        $hasAbe   = [bool]$osc.PSObject.Properties['app_bound_encrypted_key']
                        $hasDpapi = [bool]$osc.PSObject.Properties['encrypted_key']
                        if ($hasAbe) {
                            New-TcpkFinding -Module 'creds' -RuleId 'browser.cookie-key-app-bound' `
                                -Severity 'LOW' -Confidence 'Confirmed' `
                                -Title 'Chromium store uses App-Bound Encryption' `
                                -File $localState -Evidence 'os_crypt.app_bound_encrypted_key present' `
                                -Cwe @('CWE-311') `
                                -Description 'The profile key is App-Bound Encrypted (Chrome 127+). This raises the bar over plain DPAPI by binding decryption to a SYSTEM service, but multiple public bypasses exist (2024-25) for code running as the user.' `
                                -Fix 'Keep the embedded Chromium current; do not store long-lived tokens in the cookie jar.'
                        } elseif ($hasDpapi) {
                            New-TcpkFinding -Module 'creds' -RuleId 'browser.cookie-key-dpapi' `
                                -Severity 'MEDIUM' -Confidence 'Confirmed' `
                                -Title 'Chromium store key is DPAPI-only (no App-Bound Encryption)' `
                                -File $localState -Evidence 'os_crypt.encrypted_key present; no app_bound_encrypted_key' `
                                -Cwe @('CWE-311', 'CWE-312') `
                                -Description 'The cookie/password key is protected only by user DPAPI, so any code running as the current user can decrypt every cookie and saved password offline. This is the exact primitive used by infostealer malware.' `
                                -Fix 'Update the embedded Chromium to a build with App-Bound Encryption; minimise and expire stored tokens; clear the cookie jar on logout.'

                            # Prove decryptability: DPAPI-unprotect the AES-256 master key as the
                            # current user. Success means every v10/v11 cookie + saved password in
                            # this profile is decryptable offline -- the infostealer primitive PROVEN
                            # for this install, not just inferred from the key type. Read-only.
                            $mk = $null
                            try { $mk = Get-TcpkChromiumMasterKey -LocalStatePath $localState } catch { }
                            if ($mk -and $mk.Length -eq 32) {
                                $kh = (($mk[0..3] | ForEach-Object { $_.ToString('x2') }) -join ' ')
                                New-TcpkFinding -Module 'creds' -RuleId 'browser.master-key-recovered' `
                                    -Severity 'HIGH' -Confidence 'Confirmed (dynamic)' `
                                    -Title 'Chromium/WebView2 master key recovered via user DPAPI' `
                                    -File $localState -Evidence "recovered a 32-byte AES-256 os_crypt key (first 4 bytes: $kh ...)" `
                                    -Cwe @('CWE-312', 'CWE-522') `
                                    -Description 'TCPK DPAPI-unprotected the profile master key while running as the current user. That key AES-256-GCM-decrypts every v10/v11 cookie and saved password in this profile, so any code running as the user can dump the entire credential store OFFLINE -- the exact infostealer primitive, now PROVEN for this install rather than inferred from the key type.' `
                                    -Fix 'Move to App-Bound Encryption (a current Chromium build), do not persist long-lived tokens in the cookie jar, clear it on logout, and rotate anything already exposed.'
                            }
                        }
                    }
                }
            }
        }
    }
}
