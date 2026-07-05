#requires -Version 5.1
# Hardcoded secrets in .NET config appSettings / connection strings: a hardcoded AES key + IV +
# AES-encrypted password sitting together in one config is the canonical "decryptable credential"
# anti-pattern (the format/entropy rules only partially caught it). These are additive
# secrets.json rules (config-hardcoded-secret / -crypto-key / -iv / -connection-string-password);
# this test is the regression fixture AND the false-positive guard (benign keys + URL values stay
# silent). All fixture values below are SYNTHETIC -- no real application's secrets.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
}

Describe 'Hardcoded config secrets (appSettings)' {

    It 'flags the hardcoded password, AES key, and IV in appSettings' {
        $dir = Join-Path ([IO.Path]::GetTempPath()) ("tcpk-cfg-" + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        try {
            $cfg = @'
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <appSettings>
    <add key="DBPASSWORD" value="U2FtcGxlQmFzZTY0Q2lwaGVyPT0=" />
    <add key="AESKEY" value="0123456789ABCDEF0123456789ABCDEF" />
    <add key="IV" value="0123456789ABCDEF" />
    <add key="DBSERVER" value="10.0.0.5\SQLSAMPLE" />
  </appSettings>
</configuration>
'@
            Set-Content -LiteralPath (Join-Path $dir 'app.exe.config') -Value $cfg -Encoding UTF8
            $ids = @(Test-TcpkSecrets -Path $dir | ForEach-Object { "$($_.RuleId)" })
            $ids | Should -Contain 'secrets.config-hardcoded-secret'
            $ids | Should -Contain 'secrets.config-hardcoded-crypto-key'
            $ids | Should -Contain 'secrets.config-hardcoded-iv'
        } finally { [IO.Directory]::Delete($dir, $true) }
    }

    It 'does NOT flag benign appSettings keys or URL values (no false positives)' {
        $dir = Join-Path ([IO.Path]::GetTempPath()) ("tcpk-cfg-" + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        try {
            $cfg = @'
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <appSettings>
    <add key="Theme" value="Dark" />
    <add key="Timeout" value="30" />
    <add key="ForgotPasswordUrl" value="https://example.com/forgot" />
    <add key="ApiKeyName" value="" />
  </appSettings>
</configuration>
'@
            Set-Content -LiteralPath (Join-Path $dir 'app.exe.config') -Value $cfg -Encoding UTF8
            $cfgIds = @(Test-TcpkSecrets -Path $dir | ForEach-Object { "$($_.RuleId)" } | Where-Object { $_ -like 'secrets.config-*' })
            $cfgIds.Count | Should -Be 0
        } finally { [IO.Directory]::Delete($dir, $true) }
    }

    It 'flags a connection string with an embedded password' {
        $dir = Join-Path ([IO.Path]::GetTempPath()) ("tcpk-cfg-" + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        try {
            $cfg = @'
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <connectionStrings>
    <add name="db" connectionString="Data Source=srv;Initial Catalog=app;User Id=sa;Password=P@ssw0rd123;" />
  </connectionStrings>
</configuration>
'@
            Set-Content -LiteralPath (Join-Path $dir 'app.exe.config') -Value $cfg -Encoding UTF8
            $ids = @(Test-TcpkSecrets -Path $dir | ForEach-Object { "$($_.RuleId)" })
            $ids | Should -Contain 'secrets.config-connection-string-password'
        } finally { [IO.Directory]::Delete($dir, $true) }
    }
}
