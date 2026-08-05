function Test-TcpkBrowserTokenStore {
<#
.SYNOPSIS
    D08. Chromium / Electron token + cookie store, encryption strength,
    and actual credential exposure measured from live store content.

.DESCRIPTION
    Electron / CEF / NW.js apps embed a full Chromium profile, usually under
    %APPDATA%\<AppName>\ or %LOCALAPPDATA%\<AppName>\User Data\. That profile
    holds the same high-value stores a browser does: Cookies (session tokens),
    Login Data (saved passwords), Web Data (autofill / cards).

    This cmdlet MEASURES what is present; it does not assert:

      1. Tests readability via FileShare.ReadWrite and records three real states:
         readable / exclusively locked (target app may be running) / absent.
      2. Queries row counts from the cookies, logins, and autofill/credit_cards
         tables. Degrades to Confidence=Inferred when a SQLite driver is not
         available or the schema has drifted from the expected Chromium shape.
      3. Derives severity from measured content: 0 rows = INFO, cookies only
         with rows = MEDIUM, logins or autofill rows = HIGH.
      4. Detects the runtime via Test-TcpkIsChromiumRuntime and emits Fix text
         actionable for that runtime only. Electron / CEF apps cannot move to
         App-Bound Encryption (Chrome 127+); the Fix reflects that.
      5. Recovers the DPAPI-protected AES-256 master key then attempts a GCM
         round-trip on a live encrypted_value blob. Only emits
         Confidence=Confirmed (dynamic) when decryption tag verifies. A 32-byte
         key with no verifiable blob emits Confidence=Inferred.
      6. By default, collapses duplicate store paths so each physical file is
         reported once. Pass -NoCollapse to emit all findings independently
         (for historical report reproducibility across scans).

    Profile layout discovery covers both:
      <App>\Network\Cookies               (single-profile / newer layout)
      <App>\User Data\<Profile>\Network\Cookies  (multi-profile layout)

.PARAMETER NameLike
    Identity terms (app / vendor names) used to locate the profile folder.
    Required -- without terms the cmdlet returns nothing.

.PARAMETER NoCollapse
    Emit findings for every store path independently rather than collapsing
    to one finding per unique physical path.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param(
        [string[]]$NameLike,
        [switch]$NoCollapse
    )

    if (-not (Assert-TcpkWindows 'Test-TcpkBrowserTokenStore')) { return }
    $terms = Get-TcpkNameTerms -NameLike $NameLike
    if (-not $terms.Count) { return }

    #region --- inner helpers (local to this invocation) ---

    function Get-StoreReadState ([string]$FilePath) {
        if (-not (Test-Path -LiteralPath $FilePath)) { return 'absent' }
        try {
            $fs = [System.IO.FileStream]::new(
                $FilePath,
                [System.IO.FileMode]::Open,
                [System.IO.FileAccess]::Read,
                [System.IO.FileShare]::ReadWrite)
            $fs.Dispose()
            return 'readable'
        } catch [System.IO.IOException] {
            return 'locked'
        } catch {
            return 'absent'
        }
    }

    function Open-SqliteConnection ([string]$FilePath) {
        $uri = "Data Source=$FilePath;Version=3;Read Only=True;"
        # Try System.Data.SQLite (community .NET wrapper)
        $t = [Type]::GetType('System.Data.SQLite.SQLiteConnection, System.Data.SQLite')
        if (-not $t) {
            foreach ($dll in @(
                (Join-Path $PSScriptRoot '..\..\Lib\System.Data.SQLite.dll'),
                "$env:LOCALAPPDATA\Programs\DB Browser for SQLite\System.Data.SQLite.dll"
            )) {
                if (Test-Path -LiteralPath $dll -ErrorAction SilentlyContinue) {
                    try { Add-Type -Path $dll -ErrorAction SilentlyContinue } catch { }
                    $t = [Type]::GetType('System.Data.SQLite.SQLiteConnection, System.Data.SQLite')
                    if ($t) { break }
                }
            }
        }
        if ($t) {
            try { $c = $t::new($uri); $c.Open(); return $c } catch { }
        }
        # Try Microsoft.Data.Sqlite (ships with some .NET apps)
        $t2 = [Type]::GetType('Microsoft.Data.Sqlite.SqliteConnection, Microsoft.Data.Sqlite')
        if ($t2) {
            try { $c2 = $t2::new($uri); $c2.Open(); return $c2 } catch { }
        }
        return $null
    }

    function Get-TableRowCount ([object]$Conn, [string[]]$TableNames) {
        foreach ($tbl in $TableNames) {
            try {
                $cmd = $Conn.CreateCommand()
                $cmd.CommandText = "SELECT COUNT(*) FROM [$tbl]"
                $v = $cmd.ExecuteScalar()
                if ($null -ne $v) { return [int]$v }
            } catch { }
        }
        return -1
    }

    function Measure-ChromiumStore ([string]$FilePath) {
        $r = [PSCustomObject]@{
            IsValidSqlite = $false
            CookieRows    = -1
            LoginRows     = -1
            AutofillRows  = -1
            Confidence    = 'Inferred'
        }
        # Binary magic check -- never crashes, no lock needed
        try {
            $hdr = [byte[]]::new(16)
            $fs = [System.IO.FileStream]::new(
                $FilePath,
                [System.IO.FileMode]::Open,
                [System.IO.FileAccess]::Read,
                [System.IO.FileShare]::ReadWrite)
            $n = $fs.Read($hdr, 0, 16)
            $fs.Dispose()
            if ($n -eq 16) {
                $magic = [System.Text.Encoding]::ASCII.GetString($hdr, 0, 15)
                $r.IsValidSqlite = ($magic -eq 'SQLite format 3')
            }
        } catch { return $r }

        if (-not $r.IsValidSqlite) { return $r }

        $conn = Open-SqliteConnection -FilePath $FilePath
        if (-not $conn) { return $r }
        try {
            $r.CookieRows  = Get-TableRowCount -Conn $conn -TableNames @('cookies')
            $r.LoginRows   = Get-TableRowCount -Conn $conn -TableNames @('logins')
            $cc = Get-TableRowCount -Conn $conn -TableNames @('credit_cards')
            $af = Get-TableRowCount -Conn $conn -TableNames @('autofill')
            if ($cc -ge 0 -or $af -ge 0) {
                $r.AutofillRows = [Math]::Max(0, $cc) + [Math]::Max(0, $af)
            }
            $r.Confidence = 'Confirmed'
        } catch { }
        finally { $conn.Dispose() }
        return $r
    }

    function Get-LiveEncryptedBlob ([string]$CookiePath) {
        if ((Get-StoreReadState -FilePath $CookiePath) -ne 'readable') { return $null }
        $conn = Open-SqliteConnection -FilePath $CookiePath
        if (-not $conn) { return $null }
        try {
            $cmd = $conn.CreateCommand()
            $cmd.CommandText = 'SELECT encrypted_value FROM cookies WHERE length(encrypted_value) > 31 LIMIT 1'
            $v = $cmd.ExecuteScalar()
            if ($v -is [byte[]]) { return $v }
        } catch { }
        finally { $conn.Dispose() }
        return $null
    }

    #endregion

    $bases = @($env:APPDATA, $env:LOCALAPPDATA) |
        Where-Object { $_ -and (Test-Path -LiteralPath $_) } |
        Select-Object -Unique

    $markerLeaves   = @('Cookies', 'Login Data', 'Web Data')
    $seenProfiles   = New-Object System.Collections.Generic.HashSet[string]
    $seenStorePaths = New-Object System.Collections.Generic.HashSet[string]

    foreach ($base in $bases) {
        $appDirs = Get-ChildItem -LiteralPath $base -Directory -ErrorAction SilentlyContinue |
            Where-Object { Test-TcpkTermMatch -Text $_.Name -Terms $terms }

        foreach ($app in $appDirs) {
            # Invariant 4: detect runtime from the app directory
            $rtText = ''
            Get-ChildItem -LiteralPath $app.FullName -Filter '*.exe' -File -ErrorAction SilentlyContinue |
                Select-Object -First 5 |
                ForEach-Object { try { $rtText += Read-TcpkAllText -Path $_.FullName } catch { } }
            $isChromiumRuntime = Test-TcpkIsChromiumRuntime -Name $app.Name -Text $rtText
            # ABE is only available in Chrome/Edge-branded builds (Chromium 127+).
            # Electron, CEF, and NW.js embed older or unbranded Chromium and cannot
            # support ABE; Fix text must reflect this.
            $canSupportAbe = $isChromiumRuntime -and ($rtText -match '(?i)(Google Chrome|Microsoft Edge|msedge\.exe)')

            $markers = Get-ChildItem -LiteralPath $app.FullName `
                -Recurse -Depth 5 -File -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -in $markerLeaves }

            foreach ($m in $markers) {
                $storePath = $m.FullName

                # Invariant 6: de-duplicate by store path
                if (-not $NoCollapse -and -not $seenStorePaths.Add($storePath)) { continue }

                # Invariant 3: three-state readability check
                $readState = Get-StoreReadState -FilePath $storePath
                if ($readState -eq 'absent') { continue }

                $precondNote = if ($readState -eq 'readable') {
                    'Store was readable at scan time.'
                } else {
                    'Store was exclusively locked at scan time (target app may be running); ' +
                    'readability confirmed by lock detection but content could not be queried.'
                }

                # Invariant 2: content-gated severity from row counts
                $metrics = $null
                if ($readState -eq 'readable') {
                    try { $metrics = Measure-ChromiumStore -FilePath $storePath } catch { }
                }

                $storeTitle = switch ($m.Name) {
                    'Cookies'    { 'Cookies (session tokens)' }
                    'Login Data' { 'Login Data (saved passwords)' }
                    'Web Data'   { 'Web Data (autofill / cards)' }
                    default      { $m.Name }
                }

                $cookieRows = if ($metrics) { $metrics.CookieRows   } else { -1 }
                $loginRows  = if ($metrics) { $metrics.LoginRows    } else { -1 }
                $afRows     = if ($metrics) { $metrics.AutofillRows } else { -1 }
                $isMeasured = $metrics -and ($metrics.Confidence -eq 'Confirmed')

                $hasLogins     = ($loginRows  -gt 0) -or ($afRows -gt 0)
                $hasCookies    = $cookieRows  -gt 0
                $isEmpty       = $isMeasured -and -not $hasLogins -and -not $hasCookies

                $sev = if ($isEmpty) { 'INFO' }
                    elseif ($hasLogins) { 'HIGH' }
                    elseif ($hasCookies) { 'MEDIUM' }
                    elseif ($readState -eq 'locked') {
                        # Cannot query locked store; use structural estimate
                        if ($m.Name -eq 'Login Data') { 'HIGH' } else { 'MEDIUM' }
                    }
                    elseif ($metrics -and -not $metrics.IsValidSqlite) { 'INFO' }
                    else { 'INFO' }

                $confidenceStore = if ($isMeasured) { 'Confirmed' } else { 'Inferred' }
                $titleSuffix     = if ($isEmpty) { ' (empty)' } else { '' }

                # Invariant 1: build description from what was measured
                $rowParts = @()
                if ($cookieRows -ge 0) { $rowParts += "cookies=$cookieRows" }
                if ($loginRows  -ge 0) { $rowParts += "logins=$loginRows" }
                if ($afRows     -ge 0) { $rowParts += "autofill/cards=$afRows" }
                $rowSummary = if ($rowParts) { $rowParts -join '; ' }
                    elseif ($readState -eq 'locked') { 'row counts unavailable (store locked)' }
                    elseif ($metrics -and $metrics.IsValidSqlite) { 'row counts unavailable (SQLite driver not loaded)' }
                    else { 'store is not a valid SQLite or is unreadable' }

                $descContent = if ($isMeasured) {
                    "Measured content: $rowSummary."
                } elseif ($metrics -and $metrics.IsValidSqlite) {
                    "Valid SQLite confirmed; $rowSummary."
                } else {
                    "Content not queried ($readState)."
                }

                New-TcpkFinding -Module 'creds' -RuleId 'browser.cred-store' `
                    -Severity $sev -Confidence $confidenceStore `
                    -Title "Chromium profile: $storeTitle$titleSuffix" `
                    -File $storePath `
                    -Evidence "readability=$readState; size=$($m.Length); $rowSummary" `
                    -Cwe @('CWE-522') `
                    -Description ("Chromium $($m.Name) store in $($app.Name). " +
                        "$precondNote $descContent " +
                        'Protected by DPAPI against other OS users; readable by any process ' +
                        'running as the current user.') `
                    -Fix ('Clear session tokens on logout; do not persist long-lived auth cookies; ' +
                        'prefer OS credential vaults (Windows Credential Manager) for refresh tokens.')

                # os_crypt key strength -- once per Local State file (Invariant 4 + 5)
                $profileDir = Split-Path -Parent $storePath
                $localState = $null
                $d = $profileDir
                for ($up = 0; $up -lt 5 -and $d; $up++) {
                    $cand = Join-Path $d 'Local State'
                    if (Test-Path -LiteralPath $cand) { $localState = $cand; break }
                    $d = Split-Path -Parent $d
                }

                if (-not ($localState -and $seenProfiles.Add($localState))) { continue }

                $osc = $null
                try { $osc = (Get-Content -LiteralPath $localState -Raw | ConvertFrom-Json).os_crypt } catch { }
                if (-not $osc) { continue }

                $hasAbe   = [bool]$osc.PSObject.Properties['app_bound_encrypted_key']
                $hasDpapi = [bool]$osc.PSObject.Properties['encrypted_key']

                if ($hasAbe) {
                    # Invariant 4: ABE severity by runtime capability
                    $abeSev  = if ($canSupportAbe) { 'LOW' } else { 'INFO' }
                    $abeDesc = if ($canSupportAbe) {
                        "The profile key in $($app.Name) is App-Bound Encrypted (Chrome 127+). " +
                        'Binding is to a SYSTEM service, raising the bar over plain DPAPI. ' +
                        'Multiple public bypasses have been published (2024-25) for processes ' +
                        'running as the current user.'
                    } else {
                        "app_bound_encrypted_key is present in the $($app.Name) Local State, " +
                        'but the detected runtime does not appear to be a Chrome/Edge-branded ' +
                        'build that fully implements App-Bound Encryption (Chromium 127+). ' +
                        'Structural observation only; not a defect in the runtime.'
                    }
                    New-TcpkFinding -Module 'creds' -RuleId 'browser.cookie-key-app-bound' `
                        -Severity $abeSev -Confidence 'Confirmed' `
                        -Title 'Chromium store uses App-Bound Encryption' `
                        -File $localState `
                        -Evidence 'os_crypt.app_bound_encrypted_key present' `
                        -Cwe @('CWE-311') `
                        -Description $abeDesc `
                        -Fix 'Keep the embedded Chromium current; do not store long-lived tokens in the cookie jar.'

                } elseif ($hasDpapi) {
                    # Invariant 4: Fix text must be actionable for the DETECTED runtime
                    $dpapiFix = if ($canSupportAbe) {
                        "Update the embedded Chromium build in $($app.Name) to a version with " +
                        'App-Bound Encryption (Chromium 127+); minimise stored tokens; ' +
                        'clear the cookie jar on logout; rotate any credentials already in the store.'
                    } else {
                        "The detected runtime ($($app.Name)) does not support App-Bound Encryption. " +
                        'Recommended mitigations: do not persist long-lived auth tokens in the ' +
                        'Chromium cookie jar; clear the profile on logout; use Windows Credential ' +
                        'Manager for refresh tokens; reduce the scope of tokens stored in-app.'
                    }

                    New-TcpkFinding -Module 'creds' -RuleId 'browser.cookie-key-dpapi' `
                        -Severity 'MEDIUM' -Confidence 'Confirmed' `
                        -Title 'Chromium store key is DPAPI-only (no App-Bound Encryption)' `
                        -File $localState `
                        -Evidence 'os_crypt.encrypted_key present; no app_bound_encrypted_key' `
                        -Cwe @('CWE-311', 'CWE-312') `
                        -Description ("The cookie/password key in $($app.Name) is protected only by " +
                            'user DPAPI. Any code running as the current user can decrypt every cookie ' +
                            'and saved password offline. This is the exact primitive used by ' +
                            'infostealer malware.') `
                        -Fix $dpapiFix

                    # Invariant 5: prove the key with an AES-256-GCM round-trip
                    $mk = $null
                    try { $mk = Get-TcpkChromiumMasterKey -LocalStatePath $localState } catch { }

                    if ($mk -and $mk.Length -eq 32) {
                        $kh = (($mk[0..3] | ForEach-Object { $_.ToString('x2') }) -join ' ')

                        # Find a Cookies file in this profile to source a live blob
                        $profileRoot = Split-Path -Parent $localState
                        $testBlob = $null
                        $cookieFiles = @(Get-ChildItem -LiteralPath $profileRoot `
                            -Recurse -Depth 4 -Filter 'Cookies' -File `
                            -ErrorAction SilentlyContinue)
                        foreach ($cf in $cookieFiles) {
                            $testBlob = Get-LiveEncryptedBlob -CookiePath $cf.FullName
                            if ($testBlob) { break }
                        }

                        if ($testBlob -and $testBlob.Length -gt 31) {
                            # Attempt GCM decrypt (Invariant 5: tag must verify)
                            $plaintext = $null
                            try { $plaintext = Unprotect-TcpkChromiumBlob -Key $mk -Blob $testBlob } catch { }

                            if ($null -ne $plaintext) {
                                New-TcpkFinding -Module 'creds' -RuleId 'browser.master-key-recovered' `
                                    -Severity 'HIGH' -Confidence 'Confirmed (dynamic)' `
                                    -Title 'Chromium master key recovered and AES-256-GCM round-trip verified' `
                                    -File $localState `
                                    -Evidence ("DPAPI-unprotected 32-byte AES-256 key (first 4 bytes: $kh ...); " +
                                        'AES-256-GCM decryption of a live v10/v11 encrypted_value blob succeeded. ' +
                                        "Store content: $rowSummary.") `
                                    -Cwe @('CWE-312', 'CWE-522') `
                                    -Description ("TCPK recovered the AES-256 master key via user DPAPI and " +
                                        "confirmed it decrypts live v10/v11 blobs from the $($app.Name) " +
                                        'cookie store. Any code running as the current user can dump the ' +
                                        'entire credential store offline. The infostealer primitive is ' +
                                        'demonstrated, not inferred.') `
                                    -Fix $dpapiFix
                            } else {
                                New-TcpkFinding -Module 'creds' -RuleId 'browser.master-key-recovered' `
                                    -Severity 'MEDIUM' -Confidence 'Inferred' `
                                    -Title 'Chromium master key DPAPI-recovered (GCM round-trip inconclusive)' `
                                    -File $localState `
                                    -Evidence ("DPAPI-unprotected 32-byte key (first 4 bytes: $kh ...); " +
                                        'GCM decrypt returned null (tag mismatch or blob not v10/v11 format).') `
                                    -Cwe @('CWE-312', 'CWE-522') `
                                    -Description ("The $($app.Name) master key was DPAPI-unprotected (32 bytes) " +
                                        'but a GCM round-trip against a live encrypted_value blob did not ' +
                                        'verify. Key length is consistent with AES-256; dynamic ' +
                                        'decryptability not confirmed.') `
                                    -Fix $dpapiFix
                            }
                        } else {
                            # Key recovered but no live blob to verify against
                            New-TcpkFinding -Module 'creds' -RuleId 'browser.master-key-recovered' `
                                -Severity 'MEDIUM' -Confidence 'Inferred' `
                                -Title 'Chromium master key DPAPI-recovered (no live blob for GCM verification)' `
                                -File $localState `
                                -Evidence ("DPAPI-unprotected 32-byte key (first 4 bytes: $kh ...); " +
                                    'no encrypted_value blobs available to complete GCM round-trip ' +
                                    "(store empty, locked, or SQLite driver not available).") `
                                -Cwe @('CWE-312', 'CWE-522') `
                                -Description ("The $($app.Name) master key was DPAPI-unprotected (32 bytes, " +
                                    'consistent with AES-256). No live blob was available for GCM ' +
                                    'verification. Confidence is Inferred: key type implies decryptability ' +
                                    'but it has not been confirmed dynamically.') `
                                -Fix $dpapiFix
                        }
                    }
                } else {
                    New-TcpkFinding -Module 'creds' -RuleId 'browser.cookie-key-unknown' `
                        -Severity 'INFO' -Confidence 'Inferred' `
                        -Title 'Chromium Local State: os_crypt key type not recognized' `
                        -File $localState `
                        -Evidence 'os_crypt present; neither encrypted_key nor app_bound_encrypted_key found' `
                        -Cwe @('CWE-311') `
                        -Description ("os_crypt found in $($app.Name) Local State but contains neither " +
                            'the standard DPAPI key (encrypted_key) nor an App-Bound key ' +
                            '(app_bound_encrypted_key). This may be a custom Chromium fork or ' +
                            'an unrecognized key protection scheme.') `
                        -Fix 'Inspect Local State manually to identify the actual key protection mechanism.'
                }
            }
        }
    }
}
