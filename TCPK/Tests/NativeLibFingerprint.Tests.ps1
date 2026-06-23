#requires -Version 5.1
# Phase 4 (coverage breadth): Test-TcpkAppStack fingerprints bundled native C libraries by their
# embedded version string (OpenSSL / zlib / SQLite / libpng / libcurl / FreeType). Native deps are
# a common CVE source NOT reached by managed-IL analysis, so they are surfaced as recon (INFO) with
# the version, pointing to -OnlineCve / OSV for the actual advisories.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
    $script:work = Join-Path ([IO.Path]::GetTempPath()) ("tcpk-nativelib-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:work -Force | Out-Null
    $content = "MZ" + ([string]::new(' ', 64)) +
        "OpenSSL 1.1.1k  25 Mar 2021`n" +
        "inflate 1.2.11 Copyright 1995-2017 Mark Adler`n" +
        "libcurl/7.83.1`n" +
        "other strings here"
    [IO.File]::WriteAllText((Join-Path $script:work 'thirdparty.dll'), $content)
    # benign PE: a version-looking string but NO library name -> must NOT invent a lib
    [IO.File]::WriteAllText((Join-Path $script:work 'app.dll'), "MZ app version 2.3.4 build 100")
    $script:f = @(Test-TcpkAppStack -Path $script:work)
}
AfterAll { if ($script:work -and (Test-Path -LiteralPath $script:work)) { [IO.Directory]::Delete($script:work, $true) } }

Describe 'Native library fingerprint' {
    It 'detects bundled OpenSSL with its version (INFO recon)' {
        $o = @($script:f | Where-Object RuleId -eq 'appstack.native-openssl')
        @($o).Count   | Should -BeGreaterThan 0
        $o[0].Severity | Should -Be 'INFO'
        $o[0].Evidence | Should -Match '1\.1\.1k'
    }
    It 'detects bundled zlib and libcurl with versions' {
        @($script:f | Where-Object RuleId -eq 'appstack.native-zlib')[0].Evidence    | Should -Match '1\.2\.11'
        @($script:f | Where-Object RuleId -eq 'appstack.native-libcurl')[0].Evidence | Should -Match '7\.83\.1'
    }
    It 'does not invent a library from a bare version string' {
        @($script:f | Where-Object { $_.RuleId -like 'appstack.native-*' }).Count | Should -Be 3
    }
}
