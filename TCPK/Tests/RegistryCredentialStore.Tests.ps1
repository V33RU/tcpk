#requires -Version 5.1
# Static registry-credential-storage detection: an app that does
# Registry.CurrentUser.CreateSubKey("<app>") + SetValue("password", pass). A first-party PE that
# BOTH writes to the registry AND references a credential field -> LOW/Inferred review pointer.
# Fixtures are plain-text .dll files (Get-TcpkPeFiles filters on extension; Read-TcpkAllText reads
# text), inlined per-It (Pester 5 discovery/run scoping). FP guards: a registry write with no
# credential, and a credential with no registry write, both stay silent -- BOTH are required.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
}

Describe 'Static registry credential storage' {

    It 'flags a PE that writes to the registry and references a credential (LOW)' {
        $dir = Join-Path ([IO.Path]::GetTempPath()) ("tcpk-reg-" + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        try {
            Set-Content -LiteralPath (Join-Path $dir 'app.dll') -Value 'Microsoft.Win32.Registry CurrentUser CreateSubKey MyApp SetValue password isLoggedIn' -Encoding UTF8
            $f = @(Test-TcpkRegistryCredentialStore -Path $dir | Where-Object { $_.RuleId -eq 'storage.registry-credential' })
            $f.Count | Should -BeGreaterThan 0
            $f[0].Severity | Should -Be 'LOW'
        } finally { [IO.Directory]::Delete($dir, $true) }
    }

    It 'does NOT flag a registry write with no credential reference' {
        $dir = Join-Path ([IO.Path]::GetTempPath()) ("tcpk-reg-" + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        try {
            Set-Content -LiteralPath (Join-Path $dir 'app.dll') -Value 'RegistryKey CreateSubKey AppSettings SetValue Theme Dark WindowSize 1024' -Encoding UTF8
            $f = @(Test-TcpkRegistryCredentialStore -Path $dir | Where-Object { $_.RuleId -eq 'storage.registry-credential' })
            $f.Count | Should -Be 0
        } finally { [IO.Directory]::Delete($dir, $true) }
    }

    It 'does NOT flag a credential reference with no registry write' {
        $dir = Join-Path ([IO.Path]::GetTempPath()) ("tcpk-reg-" + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        try {
            Set-Content -LiteralPath (Join-Path $dir 'app.dll') -Value 'login form password textbox validates credentials over https api' -Encoding UTF8
            $f = @(Test-TcpkRegistryCredentialStore -Path $dir | Where-Object { $_.RuleId -eq 'storage.registry-credential' })
            $f.Count | Should -Be 0
        } finally { [IO.Directory]::Delete($dir, $true) }
    }
}
