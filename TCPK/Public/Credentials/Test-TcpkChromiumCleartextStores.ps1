function Test-TcpkChromiumCleartextStores {
<#
.SYNOPSIS
    D10. Chromium unencrypted data stores (Local Storage, HTTP cache, IndexedDB).

.DESCRIPTION
    Chromium applies os_crypt (AES-256-GCM) to the Cookies and Login Data SQLite
    stores, but leaves several other stores as cleartext on disk:

      Local Storage   (%AppDir%\Local Storage\leveldb\)
        Persists across restarts; survives profile wipe of Cookies. Chromium stores
        key-value pairs as raw LevelDB records without encrypting values.

      Session Storage (%AppDir%\Session Storage\)
        In-memory per tab, but recent Chromium versions persist it to disk on suspend
        or crash. Same LevelDB format, same lack of encryption.

      IndexedDB       (%AppDir%\IndexedDB\)
        Structured web-app data (Electron apps frequently use this as a local DB).
        LevelDB-backed, cleartext.

      HTTP Cache      (%AppDir%\Cache\Cache_Data\ or %AppDir%\Network\Cache_Data\)
        Raw HTTP response bodies and headers. Can contain Authorization: Bearer tokens,
        Set-Cookie headers with sensitive values, and API response payloads.

    Infostealers that bypass the encrypted cookie store target these locations first.

    The cmdlet scans each store for recognizable credential patterns:
      - JWT tokens   (three-part base64url, header must parse as {"alg":...})
      - Bearer / Token headers in HTTP cache
      - Named token fields in JSON (access_token, refresh_token, id_token, etc.)
      - API key / secret patterns in JSON or URL-encoded form data

    Each finding includes the file path, the matched pattern name, and a trimmed
    extract of the matched text (first 120 chars).

.PARAMETER NameLike
    Identity terms used to locate the app's profile directory. Required.

.PARAMETER MaxFileKB
    Maximum size in KB to scan per file. Default 2048 (2 MB). Larger files
    are scanned from the beginning only up to this limit to bound scan time.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param(
        [string[]]$NameLike,
        [int]$MaxFileKB = 2048
    )

    if (-not (Assert-TcpkWindows 'Test-TcpkChromiumCleartextStores')) { return }
    $terms = Get-TcpkNameTerms -NameLike $NameLike
    if (-not $terms.Count) { return }

    $maxBytes = $MaxFileKB * 1024

    # ---- credential patterns ----
    # Each entry: Name, Regex, MinLength (to suppress short false positives), Severity
    $patterns = @(
        @{
            Name      = 'JWT token'
            Rx        = '(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}(?![A-Za-z0-9_-])'
            MinLen    = 50
            Severity  = 'HIGH'
        },
        @{
            Name      = 'Bearer/Token auth header'
            Rx        = '(?i)(?:Authorization|X-Auth-Token)\s*:\s*(?:Bearer|Token)\s+([A-Za-z0-9_.\-+/]{20,})'
            MinLen    = 40
            Severity  = 'HIGH'
        },
        @{
            Name      = 'Named token in JSON'
            Rx        = '(?i)"(?:access_token|refresh_token|id_token|auth_token|session_token|bearer_token|oauth_token)"\s*:\s*"([A-Za-z0-9_.\-+/]{16,})"'
            MinLen    = 40
            Severity  = 'HIGH'
        },
        @{
            Name      = 'API key/secret in JSON'
            Rx        = '(?i)"(?:api[_-]?key|api[_-]?secret|client[_-]?secret|app[_-]?secret|private[_-]?key)"\s*:\s*"([A-Za-z0-9_.\-+/]{20,})"'
            MinLen    = 40
            Severity  = 'MEDIUM'
        },
        @{
            Name      = 'Session/auth value in URL-encoded storage'
            Rx        = '(?i)(?:session[_-]?(?:id|token)|auth[_-]?token|access[_-]?token)=([A-Za-z0-9_.\-+%]{20,})'
            MinLen    = 30
            Severity  = 'MEDIUM'
        }
    )

    # ---- store directory patterns relative to an app directory ----
    # Depth allows both single-profile and User Data\<Profile>\ layouts.
    $storeDirPatterns = @(
        @{ Glob = 'Local Storage\leveldb';   Exts = @('.log','.ldb');  Title = 'Local Storage (LevelDB)' },
        @{ Glob = 'Session Storage';         Exts = @('.log','.ldb');  Title = 'Session Storage (LevelDB)' },
        @{ Glob = 'IndexedDB';               Exts = @('.log','.ldb');  Title = 'IndexedDB (LevelDB)' },
        @{ Glob = 'Cache\Cache_Data';        Exts = @('');             Title = 'HTTP Cache (Cache_Data)' },
        @{ Glob = 'Network\Cache_Data';      Exts = @('');             Title = 'HTTP Cache (Network\Cache_Data)' }
    )

    $bases = @($env:APPDATA, $env:LOCALAPPDATA) |
        Where-Object { $_ -and (Test-Path -LiteralPath $_) } |
        Select-Object -Unique

    $seen = New-Object System.Collections.Generic.HashSet[string]

    foreach ($base in $bases) {
        $appDirs = Get-ChildItem -LiteralPath $base -Directory -ErrorAction SilentlyContinue |
            Where-Object { Test-TcpkTermMatch -Text $_.Name -Terms $terms }

        foreach ($app in $appDirs) {
            foreach ($sp in $storeDirPatterns) {
                # Find all directories matching this store pattern (handles both profile layouts)
                $storeDirs = Get-ChildItem -LiteralPath $app.FullName `
                    -Recurse -Depth 6 -Directory -ErrorAction SilentlyContinue |
                    Where-Object { $_.FullName -like "*\$($sp.Glob)" }

                foreach ($storeDir in $storeDirs) {
                    # Enumerate files in this store directory (no recursion; the dirs are already specific)
                    $files = Get-ChildItem -LiteralPath $storeDir.FullName -File -ErrorAction SilentlyContinue |
                        Where-Object {
                            $sp.Exts[0] -eq '' -or   # empty string = all files
                            $_.Extension -in $sp.Exts
                        } |
                        Select-Object -First 50  # cap per-store file count

                    foreach ($file in $files) {
                        if (-not $seen.Add($file.FullName)) { continue }

                        # Read up to $maxBytes as ASCII/Latin-1 (binary but text-scannable)
                        $text = $null
                        try {
                            $buf = [byte[]]::new([Math]::Min($maxBytes, $file.Length))
                            $fs = [System.IO.FileStream]::new(
                                $file.FullName,
                                [System.IO.FileMode]::Open,
                                [System.IO.FileAccess]::Read,
                                [System.IO.FileShare]::ReadWrite)
                            $n = $fs.Read($buf, 0, $buf.Length)
                            $fs.Dispose()
                            if ($n -gt 0) {
                                $text = [System.Text.Encoding]::Latin1.GetString($buf, 0, $n)
                            }
                        } catch { continue }
                        if (-not $text) { continue }

                        foreach ($pat in $patterns) {
                            $matches = [regex]::Matches($text, $pat.Rx)
                            if (-not $matches.Count) { continue }

                            $matchCount = 0
                            $firstExtract = $null
                            foreach ($m in $matches) {
                                if ($m.Value.Length -lt $pat.MinLen) { continue }
                                $matchCount++
                                if (-not $firstExtract) {
                                    $extract = $m.Value
                                    if ($extract.Length -gt 120) { $extract = $extract.Substring(0, 120) + '...' }
                                    $firstExtract = $extract
                                }
                            }
                            if ($matchCount -eq 0) { continue }

                            $sev = Resolve-TcpkImpact -RuleId 'chromium.cleartext-cred' `
                                -Facts @{ credential_match_count = $matchCount } `
                                -Candidate $pat.Severity

                            New-TcpkFinding -Module 'creds' -RuleId 'chromium.cleartext-cred' `
                                -Severity $sev -Confidence 'Confirmed' `
                                -Title "Cleartext credential in $($sp.Title): $($pat.Name)" `
                                -File $file.FullName `
                                -Evidence "matches=$matchCount; first_match=$firstExtract" `
                                -Cwe @('CWE-312', 'CWE-922') `
                                -Description ("Chromium leaves $($sp.Title) unencrypted on disk. " +
                                    "$matchCount match(es) of pattern '$($pat.Name)' found in " +
                                    "$($app.Name) ($($file.Name)). " +
                                    'os_crypt (AES-256-GCM) protects Cookies and Login Data, but ' +
                                    'Local Storage, Session Storage, IndexedDB, and HTTP cache ' +
                                    'receive no at-rest encryption. An attacker with read access to ' +
                                    "the user's profile directory can extract these values without " +
                                    'DPAPI or App-Bound Encryption.') `
                                -Fix ('Do not store long-lived credentials in Chromium unencrypted stores. ' +
                                    'For sensitive values: store in OS credential manager ' +
                                    '(Windows Credential Manager / keytar) and load at runtime; ' +
                                    'clear Local Storage / Session Storage on logout; ' +
                                    'set appropriate cache-control headers (no-store) on ' +
                                    'auth responses so credentials are not cached.')
                        }
                    }
                }
            }
        }
    }
}
