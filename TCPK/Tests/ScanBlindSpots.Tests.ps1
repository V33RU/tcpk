#requires -Version 5.1
# Files and cases the scans silently never reached. Each one looked like a clean result:
#   * a name filter meant for framework assemblies also hid NLog.config and log4net.config;
#   * a filter meant for licence text hid LicenseServer.exe.config and license.lic;
#   * the connection-string rules only matched "server first", not the password-first order
#     Windows writes into .udl / .odc files;
#   * a .NET 5-only encoding property made two checks skip every file on Windows PowerShell 5.1;
#   * a wrong parameter in an error handler made the MSI check throw and lose its findings;
#   * the certificate expiry rules could not parse the date openssl prints.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
    $script:ModuleRoot = Split-Path $psd1 -Parent
    $script:RepoRoot   = Split-Path $script:ModuleRoot -Parent

    $script:Dir = Join-Path ([IO.Path]::GetTempPath()) ('tcpk-blind-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:Dir -Force | Out-Null

    function New-Case([string]$Name, [string]$File, [string]$Text, [switch]$Utf16) {
        $d = Join-Path $script:Dir $Name
        New-Item -ItemType Directory -Path $d -Force | Out-Null
        $p = Join-Path $d $File
        if ($Utf16) { [IO.File]::WriteAllText($p, $Text, [Text.Encoding]::Unicode) }
        else        { [IO.File]::WriteAllText($p, $Text, (New-Object Text.UTF8Encoding $false)) }
        return $d
    }
    function Get-RuleIds([string]$Dir) { @(Test-TcpkSecrets -Path $Dir | ForEach-Object { "$($_.RuleId)" }) }

    $script:PwFirst  = 'Provider=SQLOLEDB.1;Password=Qz7mVx2kLp9;Persist Security Info=True;User ID=appsvc;Initial Catalog=Orders;Data Source=db01.corp.local'
    $script:SrvFirst = 'Server=db01.corp.local;Database=Orders;User Id=appsvc;Password=Qz7mVx2kLp9;'
}

AfterAll {
    if ($script:Dir -and (Test-Path -LiteralPath $script:Dir)) {
        Remove-Item -LiteralPath $script:Dir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Describe 'Framework-name filter leaves vendor config files alone' {
    It '<name> is framework: <expected>' -ForEach @(
        @{ name = 'NLog.dll';             expected = $true }
        @{ name = 'NLog.dll.config';      expected = $true }
        @{ name = 'NLog.xml';             expected = $true }
        @{ name = 'System.Text.Json.dll'; expected = $true }
        @{ name = 'NLog.config';          expected = $false }
        @{ name = 'log4net.config';       expected = $false }
        @{ name = 'Serilog.json';         expected = $false }
        @{ name = 'system.ini';           expected = $false }
        @{ name = 'MyApp.exe.config';     expected = $false }
    ) {
        $r = InModuleScope TCPK -Parameters @{ n = $name } { param($n) Test-TcpkIsFrameworkFile $n }
        $r | Should -Be $expected
    }
}

Describe 'Licence-text filter only skips documents' {
    It '<name> is first-party: <expected>' -ForEach @(
        @{ name = 'LICENSE';                  expected = $false }
        @{ name = 'LICENSE.txt';              expected = $false }
        @{ name = 'NOTICE.md';                expected = $false }
        @{ name = 'ThirdPartyNotices.txt';    expected = $false }
        @{ name = 'LICENSES.chromium.html';   expected = $false }
        @{ name = 'LicenseServer.exe.config'; expected = $true }
        @{ name = 'license.lic';              expected = $true }
        @{ name = 'LicenseManager.dll';       expected = $true }
        @{ name = 'Notice.config';            expected = $true }
    ) {
        $r = InModuleScope TCPK -Parameters @{ n = $name } { param($n) Test-TcpkIsFirstParty -Name $n }
        $r | Should -Be $expected
    }
}

Describe 'Secret scan reaches the files those filters used to hide' {
    It 'reads NLog.config' {
        $d = New-Case 'nlog' 'NLog.config' '<nlog><targets><target type="Mail" smtpPassword="Hx4nB8wQz1" smtpUserName="alerts" /></targets></nlog>'
        (Get-RuleIds $d).Count | Should -BeGreaterThan 0
    }
    It 'still skips the library documentation file NLog.xml' {
        $d = New-Case 'nlogdoc' 'NLog.xml' '<doc><example>smtpPassword="Hx4nB8wQz1"</example></doc>'
        (Get-RuleIds $d).Count | Should -Be 0
    }
    It 'reads LicenseServer.exe.config' {
        $d = New-Case 'licsrv' 'LicenseServer.exe.config' '<configuration><appSettings><add key="DbPassword" value="Hx4nB8wQz1"/></appSettings></configuration>'
        (Get-RuleIds $d).Count | Should -BeGreaterThan 0
    }
    It 'still skips licence text' {
        $d = New-Case 'lictext' 'LICENSE.txt' 'Permission is hereby granted, free of charge. password = "Hx4nB8wQz1"'
        (Get-RuleIds $d).Count | Should -Be 0
    }
}

Describe 'Connection string with the password before the server' {
    It 'is reported in a UTF-8 data link file' {
        $d = New-Case 'udl8' 'orders.udl' ("[oledb]`r`n; Everything after this line is an OLE DB initstring`r`n" + $script:PwFirst + "`r`n")
        Get-RuleIds $d | Should -Contain 'secrets.db-connection-string-password-first'
    }
    It 'is reported in a UTF-16 data link file, the encoding Windows writes' {
        $d = New-Case 'udl16' 'orders.udl' ("[oledb]`r`n; Everything after this line is an OLE DB initstring`r`n" + $script:PwFirst + "`r`n") -Utf16
        Get-RuleIds $d | Should -Contain 'secrets.db-connection-string-password-first'
    }
    It 'is not reported for a SavePassword flag with no password in it' {
        $d = New-Case 'udlflag' 'reports.udl' "[oledb]`r`n; Everything after this line is an OLE DB initstring`r`nProvider=MSDASQL.1;Persist Security Info=True;SavePassword=True;User ID=report_ro;Data Source=SQL01`r`n"
        @(Get-RuleIds $d | Where-Object { $_ -like 'secrets.*connection-string*' }).Count | Should -Be 0
    }
    It 'is not reported by the server-first rules for a flag such as RememberPwd=1' {
        $d = New-Case 'srvflag' 'conn.txt' 'Data Source=srv;User ID=sa;RememberPwd=1;Initial Catalog=x;'
        @(Get-RuleIds $d | Where-Object { $_ -like 'secrets.*connection-string*' }).Count | Should -Be 0
    }
    It 'still reports Jet OLEDB:Database Password' {
        $d = New-Case 'jet' 'conn.txt' 'Provider=Microsoft.ACE.OLEDB.12.0;Jet OLEDB:Database Password=Qz7mVx2kLp9;Data Source=C:\data\app.accdb'
        Get-RuleIds $d | Should -Contain 'secrets.db-connection-string-password-first'
    }
    It 'adds no second finding to a server-first string' {
        $d = New-Case 'srvfirst' 'conn.txt' $script:SrvFirst
        $ids = Get-RuleIds $d
        $ids | Should -Contain 'secrets.db-connection-string-with-password'
        $ids | Should -Not -Contain 'secrets.db-connection-string-password-first'
    }
}

Describe 'Source guards' {
    BeforeAll {
        $script:Sources = @(Get-ChildItem -LiteralPath (Join-Path $script:ModuleRoot 'Public')  -Recurse -File -Filter '*.ps1') +
                          @(Get-ChildItem -LiteralPath (Join-Path $script:ModuleRoot 'Private') -Recurse -File -Filter '*.ps1') +
                          @(Get-ChildItem -LiteralPath $script:RepoRoot -File -Filter '*.ps1')
    }
    It 'no code uses the Latin1 encoding property, which Windows PowerShell 5.1 does not have' {
        # [Text.Encoding]::Latin1 exists from .NET 5. On .NET Framework it is $null, the call on
        # it throws, and the surrounding catch turned that into "skip this file" for every file.
        $bad = @($script:Sources | Where-Object { (Get-Content -LiteralPath $_.FullName -Raw) -match 'Encoding\]::Latin1\b' })
        ($bad | ForEach-Object { $_.Name }) -join ', ' | Should -BeNullOrEmpty
    }
    It 'every Add-TcpkScanSkip call passes -Kind' {
        $bad = New-Object 'System.Collections.Generic.List[string]'
        foreach ($f in $script:Sources) {
            $n = 0
            foreach ($line in @(Get-Content -LiteralPath $f.FullName)) {
                $n++
                if ($line -match '^\s*#' -or $line -match 'function Add-TcpkScanSkip') { continue }
                if ($line -match '(^|[\s{;(])Add-TcpkScanSkip\s' -and $line -notmatch '-Kind\b') { $bad.Add("$($f.Name):$n") }
            }
        }
        ($bad -join ', ') | Should -BeNullOrEmpty
    }
}

Describe 'Test-TcpkMsiCustomActions' {
    It 'ignores a single file that is not an .msi instead of trying to open it' {
        $d = New-Case 'notmsi' 'setup.exe' 'MZ not an installer database'
        $f = InModuleScope TCPK -Parameters @{ p = (Join-Path $d 'setup.exe') } {
            param($p)
            Mock Assert-TcpkWindows { return $true }
            @(Test-TcpkMsiCustomActions -Path $p | Where-Object { "$($_.RuleId)" -ne 'msi.always-install-elevated' })
        }
        $f.Count | Should -Be 0
    }
}

Describe 'Test-TcpkCertBundle expiry' {
    It 'reports a certificate that expires within 90 days' -Skip:(-not (Get-Command openssl -ErrorAction SilentlyContinue)) {
        $d = Join-Path $script:Dir 'cert'
        New-Item -ItemType Directory -Path $d -Force | Out-Null
        $key = Join-Path $script:Dir 'fixture-key.pem'
        & openssl req -x509 -newkey rsa:2048 -nodes -keyout $key -out (Join-Path $d 'soon.crt') -subj '/CN=tcpk-fixture-soon' -days 30 2>$null | Out-Null
        Remove-Item -LiteralPath $key -Force -ErrorAction SilentlyContinue
        $ids = @(Test-TcpkCertBundle -Path $d | ForEach-Object { "$($_.RuleId)" })
        $ids | Should -Contain 'cert.expiring-soon'
    }
}
