#requires -Version 5.1
# ftp:// cleartext-transit detection: plain FTP sends commands, files, and credentials in clear.
# Get-TcpkPeFiles filters by extension only (no PE-header parse) and Read-TcpkAllText reads the
# text views, so a plain-text file with a .dll extension is a valid fixture. Guards: an IPv4 ftp
# host fires (MEDIUM); an embedded-credential ftp://user:pass@host fires HIGH (this path was a
# real bug -- the host-only regex stopped at the userinfo and dropped the finding); https-only
# content stays silent. Fixtures are inlined per-It (Pester 5 discovery/run scoping).

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
}

Describe 'Cleartext ftp:// detection' {

    It 'flags an ftp:// endpoint with an IPv4 host (MEDIUM)' {
        $dir = Join-Path ([IO.Path]::GetTempPath()) ("tcpk-ftp-" + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        try {
            Set-Content -LiteralPath (Join-Path $dir 'app.dll') -Value 'backup routine sends data to ftp://10.20.30.40 via STOR data.csv' -Encoding UTF8
            $ftp = @(Test-TcpkInsecureSchemes -Path $dir | Where-Object { $_.RuleId -eq 'scheme.cleartext-ftp' })
            $ftp.Count | Should -BeGreaterThan 0
            $ftp[0].Severity | Should -Be 'MEDIUM'
        } finally { [IO.Directory]::Delete($dir, $true) }
    }

    It 'rates ftp://user:pass@host as HIGH (embedded credentials)' {
        $dir = Join-Path ([IO.Path]::GetTempPath()) ("tcpk-ftp-" + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        try {
            Set-Content -LiteralPath (Join-Path $dir 'app.dll') -Value 'connect ftp://admin:s3cretPW@files.acmecorp.net/upload then quit' -Encoding UTF8
            $ftp = @(Test-TcpkInsecureSchemes -Path $dir | Where-Object { $_.RuleId -eq 'scheme.cleartext-ftp' })
            $ftp.Count | Should -BeGreaterThan 0
            (@($ftp | Where-Object { $_.Severity -eq 'HIGH' })).Count | Should -BeGreaterThan 0
        } finally { [IO.Directory]::Delete($dir, $true) }
    }

    It 'does not flag when there is no ftp:// scheme (https only)' {
        $dir = Join-Path ([IO.Path]::GetTempPath()) ("tcpk-ftp-" + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        try {
            Set-Content -LiteralPath (Join-Path $dir 'app.dll') -Value 'all traffic goes over https://api.acmecorp.net/v1 with TLS' -Encoding UTF8
            $ftp = @(Test-TcpkInsecureSchemes -Path $dir | Where-Object { $_.RuleId -eq 'scheme.cleartext-ftp' })
            $ftp.Count | Should -Be 0
        } finally { [IO.Directory]::Delete($dir, $true) }
    }
}
