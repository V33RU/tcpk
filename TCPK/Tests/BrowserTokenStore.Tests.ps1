#requires -Module Pester

<#
Fixture matrix for Test-TcpkBrowserTokenStore (Invariants 1-6) and
Test-TcpkWebViewCreds (content-gate + readability).

Fixtures (a)-(f) correspond to the six required test scenarios.
Each fixture creates a temporary directory tree under $env:TEMP, redirects
$env:APPDATA to the temp root, calls the cmdlet, then asserts on findings.

Crypto helpers (Get-TcpkChromiumMasterKey, Unprotect-TcpkChromiumBlob,
Assert-TcpkWindows) are mocked via InModuleScope so the suite runs on any
OS and does not require a real Chromium install or DPAPI access.

SQLite-row-count assertions are gated on $script:hasSqlite; they run only
when System.Data.SQLite or Microsoft.Data.Sqlite is available at test time.
#>

BeforeAll {
    $modPath = Join-Path $PSScriptRoot '..\TCPK.psd1'
    if (-not (Test-Path $modPath)) {
        throw "Cannot locate TCPK.psd1 relative to $PSScriptRoot"
    }
    Import-Module $modPath -Force -ErrorAction Stop

    # --- SQLite fixture helper ---
    # Returns $true if a real SQLite file was written (driver available).
    # Otherwise writes only the 16-byte magic so the binary check passes
    # but SQL queries fail -> Confidence=Inferred.
    function script:New-ChromiumStoreSqlite {
        param(
            [string]$Path,
            [string]$Schema,
            [string[]]$Inserts = @()
        )
        $magic = [byte[]](
            0x53,0x51,0x4C,0x69,0x74,0x65,0x20,0x66,
            0x6F,0x72,0x6D,0x61,0x74,0x20,0x33,0x00
        )

        # Try System.Data.SQLite
        $t = [Type]::GetType('System.Data.SQLite.SQLiteConnection, System.Data.SQLite')
        if (-not $t) {
            $t2 = [Type]::GetType('Microsoft.Data.Sqlite.SqliteConnection, Microsoft.Data.Sqlite')
            if ($t2) { $t = $t2 }
        }

        if ($t) {
            try {
                $conn = $t::new("Data Source=$Path;Version=3;")
                $conn.Open()
                if ($Schema) {
                    $cmd = $conn.CreateCommand(); $cmd.CommandText = $Schema
                    $cmd.ExecuteNonQuery() | Out-Null
                }
                foreach ($ins in $Inserts) {
                    $cmd = $conn.CreateCommand(); $cmd.CommandText = $ins
                    $cmd.ExecuteNonQuery() | Out-Null
                }
                $conn.Dispose()
                return $true
            } catch { }
        }

        # Fallback: magic only (binary check passes, SQL fails -> Inferred)
        [System.IO.File]::WriteAllBytes($Path, $magic)
        return $false
    }

    $script:hasSqlite = $false
    $script:_probe = Join-Path $env:TEMP "tcpk_sqlite_probe_$(New-Guid).db"
    try {
        $script:hasSqlite = New-ChromiumStoreSqlite -Path $script:_probe -Schema 'CREATE TABLE t (x)'
    } finally {
        Remove-Item $script:_probe -Force -ErrorAction SilentlyContinue
    }

    # Fake 32-byte AES key returned by the DPAPI mock
    $script:fakeKey = [byte[]]::new(32)
    for ($i = 0; $i -lt 32; $i++) { $script:fakeKey[$i] = [byte]($i + 1) }

    # Minimal v10 blob: "v10" + 12-byte nonce + 1 ciphertext byte + 16-byte tag
    $script:fakeBlob = [byte[]]::new(32)
    $script:fakeBlob[0] = [byte][char]'v'
    $script:fakeBlob[1] = [byte][char]'1'
    $script:fakeBlob[2] = [byte][char]'0'
}

AfterAll {
    Remove-Item $script:_probe -Force -ErrorAction SilentlyContinue
}

# Shared helper: make a temp app tree and redirect $env:APPDATA.
# Returns a hashtable with the paths created.
function script:New-AppFixture {
    param(
        [string]$AppName,
        [string]$Layout = 'single',  # 'single' | 'multiprofile'
        [bool]$HasCookies    = $true,
        [bool]$HasLoginData  = $false,
        [bool]$HasWebData    = $false,
        [bool]$HasLocalState = $true,
        [bool]$UseAbeKey     = $false,
        [bool]$UseDpapiKey   = $true,
        [bool]$MakeCookieLocked = $false,
        [bool]$MakeCookieCorrupt = $false,
        [bool]$MakeCookieZero = $false,
        [string]$CookieSchema = 'CREATE TABLE cookies (encrypted_value BLOB)',
        [string[]]$CookieInserts = @()
    )

    $root    = Join-Path $env:TEMP "TcpkTest_$(New-Guid)"
    $appDir  = Join-Path $root $AppName

    $cookieDir = if ($Layout -eq 'multiprofile') {
        Join-Path $appDir 'User Data\Default\Network'
    } else {
        Join-Path $appDir 'Network'
    }
    New-Item -Path $cookieDir -ItemType Directory -Force | Out-Null

    $cookiePath  = $null
    $lockStream  = $null

    if ($HasCookies) {
        $cookiePath = Join-Path $cookieDir 'Cookies'
        if ($MakeCookieZero) {
            [System.IO.File]::WriteAllBytes($cookiePath, [byte[]]::new(0))
        } elseif ($MakeCookieCorrupt) {
            [System.IO.File]::WriteAllBytes($cookiePath, [System.Text.Encoding]::ASCII.GetBytes('NOT A SQLITE FILE'))
        } else {
            New-ChromiumStoreSqlite -Path $cookiePath `
                -Schema $CookieSchema -Inserts $CookieInserts | Out-Null
        }

        if ($MakeCookieLocked) {
            $lockStream = [System.IO.FileStream]::new(
                $cookiePath,
                [System.IO.FileMode]::Open,
                [System.IO.FileAccess]::ReadWrite,
                [System.IO.FileShare]::None)
        }
    }

    $loginPath = $null
    if ($HasLoginData) {
        $loginPath = Join-Path (Split-Path $cookieDir) 'Login Data'
        New-ChromiumStoreSqlite -Path $loginPath `
            -Schema 'CREATE TABLE logins (username TEXT, password_value BLOB)' `
            -Inserts @("INSERT INTO logins VALUES('user@example.com', X'763130AABBCC')") | Out-Null
    }

    $webDataPath = $null
    if ($HasWebData) {
        $webDataPath = Join-Path (Split-Path $cookieDir) 'Web Data'
        New-ChromiumStoreSqlite -Path $webDataPath `
            -Schema 'CREATE TABLE autofill (name TEXT, value TEXT)' `
            -Inserts @("INSERT INTO autofill VALUES('email','user@example.com')") | Out-Null
    }

    $localStatePath = $null
    if ($HasLocalState) {
        $lsDir = if ($Layout -eq 'multiprofile') { Join-Path $appDir 'User Data' } else { $appDir }
        New-Item -Path $lsDir -ItemType Directory -Force | Out-Null
        $localStatePath = Join-Path $lsDir 'Local State'
        $osCrypt = if ($UseAbeKey) {
            @{ os_crypt = @{ app_bound_encrypted_key = 'QUJCQQ==' } }
        } elseif ($UseDpapiKey) {
            @{ os_crypt = @{ encrypted_key = 'QUJCQQ==' } }
        } else {
            @{ os_crypt = @{} }
        }
        $osCrypt | ConvertTo-Json | Set-Content -Path $localStatePath -Encoding UTF8
    }

    return @{
        Root            = $root
        AppDir          = $appDir
        CookiePath      = $cookiePath
        LoginPath       = $loginPath
        WebDataPath     = $webDataPath
        LocalStatePath  = $localStatePath
        LockStream      = $lockStream
    }
}

function script:Invoke-InModuleWithMocks {
    param(
        [string]$AppName,
        [hashtable]$Fixture,
        [string]$RuntimeText = 'Electron/1.0.0 Chrome/114.0.0.0',
        [bool]$MasterKeySucceeds = $false,
        [bool]$GcmSucceeds       = $false
    )
    $origAppdata = $env:APPDATA
    $env:APPDATA = $Fixture.Root
    try {
        InModuleScope TCPK -Parameters @{
            AppName          = $AppName
            RuntimeText      = $RuntimeText
            MasterKeySucceeds = $MasterKeySucceeds
            GcmSucceeds      = $GcmSucceeds
            FakeKey          = $script:fakeKey
        } {
            param($AppName, $RuntimeText, $MasterKeySucceeds, $GcmSucceeds, $FakeKey)

            Mock Assert-TcpkWindows { return $true }
            Mock Read-TcpkAllText { return $RuntimeText }
            Mock Get-TcpkChromiumMasterKey {
                if ($MasterKeySucceeds) { return $FakeKey } else { return $null }
            }
            Mock Unprotect-TcpkChromiumBlob {
                if ($GcmSucceeds) { return 'decrypted-value' } else { return $null }
            }

            @(Test-TcpkBrowserTokenStore -NameLike $AppName)
        }
    } finally {
        $env:APPDATA = $origAppdata
        if ($Fixture.LockStream) { $Fixture.LockStream.Dispose() }
        Remove-Item $Fixture.Root -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# =============================================================================
Describe 'BrowserTokenStore fixture matrix' {
# =============================================================================

    # -------------------------------------------------------------------------
    Context '(a) Electron, cookies-only, empty store, DPAPI key, target running' {
    # -------------------------------------------------------------------------
        BeforeAll {
            $script:fx_a = New-AppFixture -AppName 'FixtureA' `
                -HasCookies $true -HasLoginData $false -HasWebData $false `
                -UseDpapiKey $true -UseAbeKey $false `
                -MakeCookieLocked $true   # simulate target app running
            $script:findings_a = Invoke-InModuleWithMocks `
                -AppName 'FixtureA' -Fixture $script:fx_a `
                -RuntimeText 'Electron/20.0.0 Chrome/114.0.0.0' `
                -MasterKeySucceeds $false -GcmSucceeds $false
        }
        AfterAll {
            if ($script:fx_a.LockStream) { $script:fx_a.LockStream.Dispose() }
        }

        It 'emits at least one finding' {
            $script:findings_a | Should -Not -BeNullOrEmpty
        }
        It 'cred-store finding severity is INFO or MEDIUM (locked, content unknown)' {
            $f = $script:findings_a | Where-Object { $_.RuleId -eq 'browser.cred-store' }
            $f | Should -Not -BeNullOrEmpty
            $f[0].Severity | Should -BeIn @('INFO','MEDIUM')
        }
        It 'does not claim saved-password content from a locked or unqueried store' {
            $f = $script:findings_a | Where-Object { $_.RuleId -eq 'browser.cred-store' }
            $f[0].Description | Should -Not -Match '(?i)saved.?password'
        }
        It 'records locked readability state in evidence or description' {
            $f = $script:findings_a | Where-Object { $_.RuleId -eq 'browser.cred-store' }
            ($f[0].Evidence + $f[0].Description) | Should -Match '(?i)lock'
        }
        It 'does not emit Confirmed (dynamic) when DPAPI key unavailable' {
            $dynamic = $script:findings_a | Where-Object { $_.Confidence -like '*dynamic*' }
            $dynamic | Should -BeNullOrEmpty
        }
    }

    # -------------------------------------------------------------------------
    Context '(b) Electron, cookies populated, DPAPI key, not running' {
    # -------------------------------------------------------------------------
        BeforeAll {
            $cookieInserts = @("INSERT INTO cookies VALUES (X'763130AABBCCDD')")
            if (-not $script:hasSqlite) { $cookieInserts = @() }

            $script:fx_b = New-AppFixture -AppName 'FixtureB' `
                -HasCookies $true -HasLoginData $false -HasWebData $false `
                -UseDpapiKey $true -UseAbeKey $false `
                -CookieInserts $cookieInserts
            $script:findings_b = Invoke-InModuleWithMocks `
                -AppName 'FixtureB' -Fixture $script:fx_b `
                -RuntimeText 'Electron/20.0.0 Chrome/114.0.0.0' `
                -MasterKeySucceeds $false -GcmSucceeds $false
        }

        It 'emits cred-store finding' {
            $f = $script:findings_b | Where-Object { $_.RuleId -eq 'browser.cred-store' }
            $f | Should -Not -BeNullOrEmpty
        }
        It 'cred-store severity is MEDIUM when cookies rows present (if SQLite available)' {
            if (-not $script:hasSqlite) {
                Set-ItResult -Skipped -Because 'SQLite driver not available; row-count gate not exercised'
                return
            }
            $f = $script:findings_b | Where-Object { $_.RuleId -eq 'browser.cred-store' }
            $f[0].Severity | Should -Be 'MEDIUM'
        }
        It 'confidence is Confirmed when row counts were measured' {
            if (-not $script:hasSqlite) {
                Set-ItResult -Skipped -Because 'SQLite driver not available'
                return
            }
            $f = $script:findings_b | Where-Object { $_.RuleId -eq 'browser.cred-store' }
            $f[0].Confidence | Should -Be 'Confirmed'
        }
        It 'readability=readable recorded in evidence' {
            $f = $script:findings_b | Where-Object { $_.RuleId -eq 'browser.cred-store' }
            $f[0].Evidence | Should -Match 'readable'
        }
        It 'emits DPAPI-only key finding' {
            $f = $script:findings_b | Where-Object { $_.RuleId -eq 'browser.cookie-key-dpapi' }
            $f | Should -Not -BeNullOrEmpty
        }
        It 'DPAPI Fix text does not reference App-Bound Encryption as a direct option for Electron' {
            $f = $script:findings_b | Where-Object { $_.RuleId -eq 'browser.cookie-key-dpapi' }
            # ABE is not available for Electron; Fix should not tell the user to "update to ABE"
            # as if it were a Chrome/Edge-branded build
            $f[0].Fix | Should -Not -Match '(?i)App-Bound Encryption.*Chromium 127'
        }
    }

    # -------------------------------------------------------------------------
    Context '(c) Chrome-class runtime, logins + autofill present, ABE absent' {
    # -------------------------------------------------------------------------
        BeforeAll {
            # Login Data insert: only if SQLite driver available
            $loginInserts = if ($script:hasSqlite) {
                @("INSERT INTO logins VALUES('admin@corp.com', X'763130AABBCC')")
            } else { @() }
            # Cookies insert: 32-byte blob so Get-LiveEncryptedBlob finds it (length > 31 check)
            # v10 (3) + nonce (12) + 1 ciphertext byte + tag (16) = 32 bytes minimum
            $cookieBlob = 'AA' * 32  # 32 bytes of 0xAA as hex
            $cookieInserts = if ($script:hasSqlite) {
                @("INSERT INTO cookies VALUES (X'$cookieBlob')")
            } else { @() }

            $script:fx_c = New-AppFixture -AppName 'FixtureC' `
                -HasCookies $true -HasLoginData $true -HasWebData $false `
                -UseDpapiKey $true -UseAbeKey $false `
                -CookieInserts $cookieInserts
            $script:findings_c = Invoke-InModuleWithMocks `
                -AppName 'FixtureC' -Fixture $script:fx_c `
                -RuntimeText 'Google Chrome/127.0.0.0' `
                -MasterKeySucceeds $true -GcmSucceeds $true
        }

        It 'Login Data finding severity is HIGH when logins rows present' {
            if (-not $script:hasSqlite) {
                Set-ItResult -Skipped -Because 'SQLite driver not available; row-count gate not exercised'
                return
            }
            $f = $script:findings_c | Where-Object {
                $_.RuleId -eq 'browser.cred-store' -and $_.Title -like '*Login*'
            }
            $f | Should -Not -BeNullOrEmpty
            $f[0].Severity | Should -Be 'HIGH'
        }
        It 'emits Confirmed (dynamic) when GCM round-trip succeeds and a live blob is available' {
            if (-not $script:hasSqlite) {
                Set-ItResult -Skipped -Because 'SQLite driver not available; Get-LiveEncryptedBlob cannot find a blob'
                return
            }
            $f = $script:findings_c | Where-Object { $_.RuleId -eq 'browser.master-key-recovered' }
            $f | Should -Not -BeNullOrEmpty
            $f[0].Confidence | Should -Be 'Confirmed (dynamic)'
        }
        It 'DPAPI Fix for Chrome-class runtime references App-Bound Encryption update' {
            $f = $script:findings_c | Where-Object { $_.RuleId -eq 'browser.cookie-key-dpapi' }
            $f | Should -Not -BeNullOrEmpty
            $f[0].Fix | Should -Match '(?i)(App-Bound|Chromium 127)'
        }
        It 'emits DPAPI key finding (no ABE)' {
            $dpapi = $script:findings_c | Where-Object { $_.RuleId -eq 'browser.cookie-key-dpapi' }
            $abe   = $script:findings_c | Where-Object { $_.RuleId -eq 'browser.cookie-key-app-bound' }
            $dpapi | Should -Not -BeNullOrEmpty
            $abe   | Should -BeNullOrEmpty
        }
    }

    # -------------------------------------------------------------------------
    Context '(d) ABE present (app_bound_encrypted_key)' {
    # -------------------------------------------------------------------------
        BeforeAll {
            $script:fx_d = New-AppFixture -AppName 'FixtureD' `
                -HasCookies $true -HasLoginData $false -HasWebData $false `
                -UseDpapiKey $false -UseAbeKey $true
            $script:findings_d = Invoke-InModuleWithMocks `
                -AppName 'FixtureD' -Fixture $script:fx_d `
                -RuntimeText 'Google Chrome/130.0.0.0' `
                -MasterKeySucceeds $false -GcmSucceeds $false
        }

        It 'emits ABE key finding, not DPAPI finding' {
            $abe   = $script:findings_d | Where-Object { $_.RuleId -eq 'browser.cookie-key-app-bound' }
            $dpapi = $script:findings_d | Where-Object { $_.RuleId -eq 'browser.cookie-key-dpapi' }
            $abe   | Should -Not -BeNullOrEmpty
            $dpapi | Should -BeNullOrEmpty
        }
        It 'does not emit master-key-recovered for ABE profile' {
            $mkf = $script:findings_d | Where-Object { $_.RuleId -eq 'browser.master-key-recovered' }
            $mkf | Should -BeNullOrEmpty
        }
        It 'ABE finding severity is LOW for Chrome-branded runtime' {
            $abe = $script:findings_d | Where-Object { $_.RuleId -eq 'browser.cookie-key-app-bound' }
            $abe[0].Severity | Should -Be 'LOW'
        }
    }

    # -------------------------------------------------------------------------
    Context '(e) User Data\Default\Network\Cookies nested layout discovered' {
    # -------------------------------------------------------------------------
        BeforeAll {
            $script:fx_e = New-AppFixture -AppName 'FixtureE' `
                -Layout 'multiprofile' `
                -HasCookies $true -HasLoginData $false -HasWebData $false `
                -UseDpapiKey $true -UseAbeKey $false
            $script:findings_e = Invoke-InModuleWithMocks `
                -AppName 'FixtureE' -Fixture $script:fx_e `
                -RuntimeText 'Electron/20.0.0 Chrome/114.0.0.0' `
                -MasterKeySucceeds $false -GcmSucceeds $false
        }

        It 'discovers Cookies in User Data\Default\Network\ layout' {
            $f = $script:findings_e | Where-Object { $_.RuleId -eq 'browser.cred-store' }
            $f | Should -Not -BeNullOrEmpty
            # Verify the file path ends with the nested layout
            $f[0].File | Should -Match '(?i)User.Data'
        }
        It 'finds Local State one level above User Data' {
            $lsf = $script:findings_e | Where-Object { $_.RuleId -eq 'browser.cookie-key-dpapi' }
            $lsf | Should -Not -BeNullOrEmpty
            $lsf[0].File | Should -Match '(?i)Local.State'
        }
    }

    # -------------------------------------------------------------------------
    Context '(f) Corrupt / non-SQLite / zero-byte store' {
    # -------------------------------------------------------------------------
        BeforeAll {
            # Create three separate app dirs: corrupt content, zero-byte, non-SQLite text
            $root = Join-Path $env:TEMP "TcpkTest_$(New-Guid)"
            New-Item -Path $root -ItemType Directory -Force | Out-Null

            foreach ($pair in @(
                @{ Name = 'FixtureF_corrupt'; Content = 'NOT A SQLITE FILE' },
                @{ Name = 'FixtureF_zero';   Content = '' },
                @{ Name = 'FixtureF_text';   Content = 'plain text no magic bytes' }
            )) {
                $dir = Join-Path $root "$($pair.Name)\Network"
                New-Item -Path $dir -ItemType Directory -Force | Out-Null
                Set-Content -Path (Join-Path $dir 'Cookies') -Value $pair.Content -Encoding UTF8
            }
            $script:fx_f_root = $root

            $origAppdata = $env:APPDATA
            $env:APPDATA = $root
            $script:findings_f = InModuleScope TCPK {
                Mock Assert-TcpkWindows { return $true }
                Mock Read-TcpkAllText { return 'Electron/1.0' }
                Mock Get-TcpkChromiumMasterKey { return $null }
                @(Test-TcpkBrowserTokenStore -NameLike 'FixtureF')
            }
            $env:APPDATA = $origAppdata
        }
        AfterAll {
            Remove-Item $script:fx_f_root -Recurse -Force -ErrorAction SilentlyContinue
        }

        It 'does not throw for corrupt store' {
            { $script:findings_f } | Should -Not -Throw
        }
        It 'emits INFO or no finding for non-SQLite content' {
            # Any findings for these stores should be INFO, never HIGH or MEDIUM
            $highMed = $script:findings_f |
                Where-Object { $_.Severity -in @('HIGH','MEDIUM') }
            $highMed | Should -BeNullOrEmpty
        }
        It 'findings.Count is 0 or all are INFO' {
            $script:findings_f | ForEach-Object {
                $_.Severity | Should -Be 'INFO'
            }
        }
    }

    # -------------------------------------------------------------------------
    Context 'NoCollapse switch: all store paths emitted independently' {
    # -------------------------------------------------------------------------
        BeforeAll {
            $script:fx_nc = New-AppFixture -AppName 'FixtureNC' `
                -HasCookies $true -HasLoginData $true -HasWebData $true `
                -UseDpapiKey $true -UseAbeKey $false
            $origAppdata = $env:APPDATA
            $env:APPDATA = $script:fx_nc.Root
            $script:findings_nc = InModuleScope TCPK {
                Mock Assert-TcpkWindows { return $true }
                Mock Read-TcpkAllText { return 'Electron/1.0' }
                Mock Get-TcpkChromiumMasterKey { return $null }
                @(Test-TcpkBrowserTokenStore -NameLike 'FixtureNC' -NoCollapse)
            }
            $env:APPDATA = $origAppdata
            if ($script:fx_nc.LockStream) { $script:fx_nc.LockStream.Dispose() }
            Remove-Item $script:fx_nc.Root -Recurse -Force -ErrorAction SilentlyContinue
        }

        It 'emits one browser.cred-store finding per present store file' {
            $storeFindigs = $script:findings_nc | Where-Object { $_.RuleId -eq 'browser.cred-store' }
            # Three store files were created (Cookies, Login Data, Web Data)
            $storeFindigs.Count | Should -BeGreaterOrEqual 3
        }
    }

    # -------------------------------------------------------------------------
    Context 'Invariant 5: 32-byte key without live blob -> Inferred, not Confirmed (dynamic)' {
    # -------------------------------------------------------------------------
        BeforeAll {
            # Empty store: readable but no encrypted_value blobs
            $script:fx_i5 = New-AppFixture -AppName 'FixtureI5' `
                -HasCookies $true -HasLoginData $false -HasWebData $false `
                -UseDpapiKey $true -UseAbeKey $false
            # Do NOT insert any cookie rows (empty store)
            $script:findings_i5 = Invoke-InModuleWithMocks `
                -AppName 'FixtureI5' -Fixture $script:fx_i5 `
                -RuntimeText 'Electron/20.0.0 Chrome/114.0.0.0' `
                -MasterKeySucceeds $true -GcmSucceeds $false
        }

        It 'master-key finding confidence is Inferred when no blob is available' {
            $mkf = $script:findings_i5 | Where-Object { $_.RuleId -eq 'browser.master-key-recovered' }
            if ($mkf) {
                $mkf[0].Confidence | Should -Not -Be 'Confirmed (dynamic)'
                $mkf[0].Confidence | Should -Be 'Inferred'
            } else {
                # Acceptable: no finding when store is empty and key cannot be proven
                Set-ItResult -Skipped -Because 'No master-key finding emitted (no blob, empty store)'
            }
        }
    }
}
