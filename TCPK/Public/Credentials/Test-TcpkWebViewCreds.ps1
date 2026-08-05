function Test-TcpkWebViewCreds {
<#
.SYNOPSIS
    D06. WebView2 Edge user profile -- saved login state.

.DESCRIPTION
    WebView2 hosts a full Chromium profile per app, stored under
    %LOCALAPPDATA%\Packages\<pkgFamilyName>\AC\Microsoft\Edge\User Data\
    (for packaged apps) or under app-controlled paths for non-packaged.

    The profile carries Cookies, Login Data, and Web Data SQLite stores.
    Each is encrypted with a DPAPI-protected AES-256 master key (EdgeMaster
    Key). If the target has WebView2 navigations to auth-bearing origins,
    those credentials persist here.

    This cmdlet measures what is actually present:
      - Attempts FileShare.ReadWrite open and records three real states:
        readable / exclusively locked (app may be running) / absent.
      - Queries row counts from the relevant tables. Degrades to
        Confidence=Inferred on schema mismatch or missing SQLite driver.
      - Derives severity from measured content: 0 rows = INFO, cookies only
        with rows = MEDIUM, logins or autofill rows = HIGH.

.PARAMETER PackageFamilyName
    Package family name, e.g. YourApp_xxxxxxxxxxxxx. Required for packaged apps.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$PackageFamilyName)

    if (-not (Assert-TcpkWindows 'Test-TcpkWebViewCreds')) { return }

    $base = "$env:LOCALAPPDATA\Packages\$PackageFamilyName\AC\Microsoft\Edge\User Data"
    if (-not (Test-Path -LiteralPath $base)) { return }

    #region --- inner helpers ---

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

    function Measure-WebViewStore ([string]$FilePath) {
        $r = [PSCustomObject]@{
            IsValidSqlite = $false
            CookieRows    = -1
            LoginRows     = -1
            AutofillRows  = -1
            Confidence    = 'Inferred'
        }
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
                $r.IsValidSqlite = (
                    [System.Text.Encoding]::ASCII.GetString($hdr, 0, 15) -eq 'SQLite format 3'
                )
            }
        } catch { return $r }
        if (-not $r.IsValidSqlite) { return $r }

        $conn = Open-SqliteConnection -FilePath $FilePath
        if (-not $conn) { return $r }
        try {
            $r.CookieRows = Get-TableRowCount -Conn $conn -TableNames @('cookies')
            $r.LoginRows  = Get-TableRowCount -Conn $conn -TableNames @('logins')
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

    #endregion

    $targets = @(
        @{ Rel = 'Default\Login Data';        Title = 'Login Data (saved passwords)' },
        @{ Rel = 'Default\Web Data';          Title = 'Web Data (autofill / cards)' },
        @{ Rel = 'Default\Cookies';           Title = 'Cookies (session tokens)' },
        @{ Rel = 'Default\Network\Cookies';   Title = 'Cookies (session tokens, Network layout)' }
    )

    foreach ($t in $targets) {
        $full = Join-Path $base $t.Rel
        if (-not (Test-Path -LiteralPath $full)) { continue }

        # Invariant 3: three-state readability
        $readState = Get-StoreReadState -FilePath $full
        if ($readState -eq 'absent') { continue }

        $precondNote = if ($readState -eq 'readable') {
            'Store was readable at scan time.'
        } else {
            'Store was exclusively locked at scan time (app may be running); ' +
            'readability confirmed by lock detection but content could not be queried.'
        }

        # Invariant 2: content-gated severity
        $info = Get-Item -LiteralPath $full -ErrorAction SilentlyContinue
        $metrics = $null
        if ($readState -eq 'readable') {
            try { $metrics = Measure-WebViewStore -FilePath $full } catch { }
        }

        $cookieRows = if ($metrics) { $metrics.CookieRows   } else { -1 }
        $loginRows  = if ($metrics) { $metrics.LoginRows    } else { -1 }
        $afRows     = if ($metrics) { $metrics.AutofillRows } else { -1 }
        $isMeasured = $metrics -and ($metrics.Confidence -eq 'Confirmed')

        $hasLogins  = ($loginRows -gt 0) -or ($afRows -gt 0)
        $hasCookies = $cookieRows -gt 0
        $isEmpty    = $isMeasured -and -not $hasLogins -and -not $hasCookies

        $sev = if ($isEmpty) { 'INFO' }
            elseif ($hasLogins) { 'HIGH' }
            elseif ($hasCookies) { 'MEDIUM' }
            elseif ($readState -eq 'locked') {
                if ($t.Rel -like '*Login*') { 'HIGH' } else { 'MEDIUM' }
            }
            elseif ($metrics -and -not $metrics.IsValidSqlite) { 'INFO' }
            else { 'INFO' }

        $confidenceStore = if ($isMeasured) { 'Confirmed' } else { 'Inferred' }
        $titleSuffix     = if ($isEmpty) { ' (empty)' } else { '' }

        $rowParts = @()
        if ($cookieRows -ge 0) { $rowParts += "cookies=$cookieRows" }
        if ($loginRows  -ge 0) { $rowParts += "logins=$loginRows" }
        if ($afRows     -ge 0) { $rowParts += "autofill/cards=$afRows" }
        $rowSummary = if ($rowParts) { $rowParts -join '; ' }
            elseif ($readState -eq 'locked') { 'row counts unavailable (store locked)' }
            else { 'row counts unavailable (SQLite driver not loaded)' }

        $descContent = if ($isMeasured) {
            "Measured content: $rowSummary."
        } elseif ($metrics -and $metrics.IsValidSqlite) {
            "Valid SQLite confirmed; $rowSummary."
        } else {
            "Content not queried ($readState)."
        }

        $fileSize = if ($info) { $info.Length } else { 0 }
        $fileMtime = if ($info) { $info.LastWriteTime } else { 'unknown' }

        New-TcpkFinding -Module 'creds' -RuleId 'webview2.profile-cred-store' `
            -Severity $sev -Confidence $confidenceStore `
            -Title "WebView2 Edge profile: $($t.Title)$titleSuffix" `
            -File $full `
            -Evidence "readability=$readState; size=$fileSize; modified=$fileMtime; $rowSummary" `
            -Cwe @('CWE-522') `
            -Description ("WebView2 Chromium $($t.Rel -replace '.*\\','') store for " +
                "$PackageFamilyName. $precondNote $descContent " +
                'Protected by user DPAPI (EdgeMaster Key) against other OS users; ' +
                'readable by any process running as the current user.') `
            -Fix 'For sensitive auth flows, clear the WebView2 profile on logout ' +
                '(CoreWebView2.CookieManager.DeleteAllCookies, or wipe the User Data directory). ' +
                'Do not persist long-lived session cookies in the WebView2 profile.'
    }
}
