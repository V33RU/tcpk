function Test-TcpkLocalDb {
<#
.SYNOPSIS
    D07. Local databases at rest (SQLite / .db) -- unencrypted + world-readable.

.DESCRIPTION
    Thick clients frequently cache data in a local SQLite DB. If it is
    unencrypted and readable by other users, any local attacker reads its
    contents (tokens, PII, cached creds). This finds *.db/*.sqlite/*.db3 files
    shipped in the install AND under the user's data dirs, checks the SQLite
    magic header (encrypted DBs do NOT start with 'SQLite format 3'), and checks
    the file ACL.

.PARAMETER Path
    Install directory.

.PARAMETER NameLike
    Optional vendor/product substring to also scan %LOCALAPPDATA%/%APPDATA%.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [string[]]$NameLike
    )

    $terms = Get-TcpkNameTerms -NameLike $NameLike
    $dirs = New-Object 'System.Collections.Generic.List[string]'
    $dirs.Add($Path)
    if ($terms.Count) {
        foreach ($base in @($env:LOCALAPPDATA, $env:APPDATA, $env:ProgramData, $env:TEMP)) {
            if ($base -and (Test-Path $base)) {
                foreach ($d in (Get-ChildItem -LiteralPath $base -Directory -ErrorAction SilentlyContinue | Where-Object { Test-TcpkTermMatch -Text $_.Name -Terms $terms })) {
                    $dirs.Add($d.FullName)
                }
            }
        }
    }

    $magic = [Text.Encoding]::ASCII.GetBytes('SQLite format 3')
    $seen = @{}
    # Browser/WebView2/Chromium internal caches are full of .db files that are NOT
    # the app's data store -- skip them (WebView2 creds are covered separately).
    $skipPath = '(?i)(WebView2|EBWebView|GPUCache|Code Cache|CacheStorage|Service Worker|IndexedDB|blob_storage|GrShaderCache|DawnCache|component_crx_cache|\\Cache\\|\\Network\\)'
    $emitted = 0; $cap = 40

    foreach ($d in $dirs) {
        if (-not (Test-Path -LiteralPath $d)) { continue }
        # NOTE: -Include is ignored with -LiteralPath; filter by extension via Where-Object.
        $dbs = Get-ChildItem -LiteralPath $d -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension -in '.db','.sqlite','.sqlite3','.db3','.s3db' -and $_.FullName -notmatch $skipPath }
        foreach ($db in $dbs) {
            if ($emitted -ge $cap) { break }
            if ($seen.ContainsKey($db.FullName)) { continue }
            $seen[$db.FullName] = $true

            # read header
            $hdr = $null
            try {
                $fs = [IO.File]::OpenRead($db.FullName)
                $buf = New-Object byte[] 16
                [void]$fs.Read($buf, 0, 16); $fs.Dispose()
                $hdr = $buf
            } catch { continue }

            $isSqlite = $true
            for ($i = 0; $i -lt $magic.Length; $i++) { if ($hdr[$i] -ne $magic[$i]) { $isSqlite = $false; break } }

            # world-readable?
            $worldReadable = $false; $grant = ''
            try {
                $acl = Get-Acl -LiteralPath $db.FullName -ErrorAction Stop
                $w = $acl.Access | Where-Object {
                    "$($_.IdentityReference)" -match '(?i)\b(Everyone|Authenticated Users|BUILTIN\\Users|\\Users$|^Users$)\b' -and
                    "$($_.FileSystemRights)" -match 'Read|Modify|FullControl' -and $_.AccessControlType -eq 'Allow'
                }
                if ($w) { $worldReadable = $true; $grant = ($w | ForEach-Object { "$($_.IdentityReference)=$($_.FileSystemRights)" } | Select-Object -Unique) -join '; ' }
            } catch { }

            if ($isSqlite) {
                $sev = if ($worldReadable) { 'HIGH' } else { 'MEDIUM' }
                New-TcpkFinding -Module 'creds' -RuleId 'localdb.sqlite-unencrypted' `
                    -Severity $sev -Confidence 'Confirmed' `
                    -Title "Unencrypted SQLite DB: $($db.Name)$(if ($worldReadable) { ' (user-readable)' })" `
                    -File $db.FullName -Evidence "header='SQLite format 3'$(if ($grant) { "; ACL: $grant" })" -Cwe @('CWE-311','CWE-312') `
                    -Description 'A plaintext SQLite database. Open it (DB Browser for SQLite) and confirm it holds no tokens/PII/cached credentials. If other users can read it, that data is exposed locally.' `
                    -Fix 'Encrypt at rest (SQLCipher / DPAPI-wrapped key) and restrict the file ACL to the owning user.'
                $emitted++
            }
            elseif ($worldReadable) {
                New-TcpkFinding -Module 'creds' -RuleId 'localdb.user-readable' `
                    -Severity 'MEDIUM' -Confidence 'Confirmed' `
                    -Title "User-readable local DB: $($db.Name)" `
                    -File $db.FullName -Evidence $grant -Cwe @('CWE-732') `
                    -Description 'A local database file readable by other users (header is not plain SQLite -- possibly encrypted or another format). Confirm whether it holds sensitive data and whether the encryption key is recoverable locally.'
                $emitted++
            }
        }
    }
}
