#requires -Version 5.1
# Provenance gate (Test-TcpkIsFirstParty): the #1 false-positive source on Electron apps is a
# string/secret/import match inside a BUNDLED file (the Electron main exe, a Chromium DLL, the
# NSIS uninstaller, a LICENSES.* file) being attributed to first-party code. The gate classifies
# such files as NOT first-party so the noisy scanners skip them, while genuine app code
# (app.asar JS, the vendor's own DLLs) is still scanned. Fixtures mirror real-world Electron FPs.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
    function New-PvDir { $d = Join-Path ([IO.Path]::GetTempPath()) ("tcpk-pv-" + [guid]::NewGuid().ToString('N')); New-Item -ItemType Directory -Path $d -Force | Out-Null; $d }
}

Describe 'Test-TcpkIsFirstParty classifier' {
    It 'classifies <Name> (<Size> bytes) as first-party=<Expect>' -ForEach @(
        @{ Name = 'ffmpeg.dll';             Size = 3MB;   Expect = $false }   # bundled native lib
        @{ Name = 'elevate.exe';            Size = 0;     Expect = $false }   # runtime helper
        @{ Name = 'LICENSES.chromium.html'; Size = 19MB;  Expect = $false }   # third-party licence text
        @{ Name = 'Uninstall MyApp.exe';    Size = 1MB;   Expect = $false }   # NSIS uninstaller
        @{ Name = 'MyApp.exe';              Size = 200MB; Expect = $false }   # statically-linked runtime (size)
        @{ Name = 'myaddon.dll';            Size = 1MB;   Expect = $true }    # genuine small first-party dll
        @{ Name = 'main.js';                Size = 4096;  Expect = $true }    # first-party JS
    ) {
        InModuleScope TCPK -Parameters @{ Name = $Name; Size = $Size; Expect = $Expect } {
            param($Name, $Size, $Expect)
            (Test-TcpkIsFirstParty -Name $Name -SizeBytes $Size) | Should -Be $Expect
        }
    }

    It 'treats a loose PE next to resources\app.asar as bundled (structural, no content read)' {
        $d = New-PvDir
        New-Item -ItemType Directory -Path (Join-Path $d 'resources') -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $d 'resources\app.asar') -Value 'stub' -Encoding Ascii
        $vendor = Join-Path $d 'vendor.dll'; Set-Content -LiteralPath $vendor -Value 'x' -Encoding Ascii
        try {
            $r = InModuleScope TCPK -Parameters @{ n = 'vendor.dll'; p = $vendor } { param($n, $p) Test-TcpkIsFirstParty -Name $n -SizeBytes 1000 -Path $p }
            $r | Should -BeFalse
        } finally { Remove-Item -LiteralPath $d -Recurse -Force }
    }
}

Describe 'Provenance gate in the scanners (bundled skipped, first-party kept)' {
    It 'Test-TcpkSecrets skips a licence file but flags first-party code' {
        $d = New-PvDir
        Set-Content -LiteralPath (Join-Path $d 'LICENSES.chromium.html') -Value 'a bundled licence mentioning AKIA1234567890ABCDEF somewhere' -Encoding Ascii
        Set-Content -LiteralPath (Join-Path $d 'config.json') -Value '{"awsKey":"AKIA1234567890ABCDEF"}' -Encoding Ascii
        try {
            $f = @(Test-TcpkSecrets -Path $d | Where-Object { $_.RuleId -eq 'secrets.aws-access-key-id' })
            ($f | Where-Object { $_.File -match 'LICENSES' })   | Should -BeNullOrEmpty
            ($f | Where-Object { $_.File -match 'config\.json' }) | Should -Not -BeNullOrEmpty
        } finally { Remove-Item -LiteralPath $d -Recurse -Force }
    }

    It 'Test-TcpkSecrets skips a loose DLL at an Electron root (structural)' {
        $d = New-PvDir
        New-Item -ItemType Directory -Path (Join-Path $d 'resources') -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $d 'resources\app.asar') -Value 'stub' -Encoding Ascii
        Set-Content -LiteralPath (Join-Path $d 'vendor.dll') -Value 'AKIA1234567890ABCDEF' -Encoding Ascii
        try {
            @(Test-TcpkSecrets -Path $d | Where-Object { $_.RuleId -eq 'secrets.aws-access-key-id' -and $_.File -match 'vendor' }).Count | Should -Be 0
        } finally { Remove-Item -LiteralPath $d -Recurse -Force }
    }

    It 'the SAME loose DLL IS scanned when NOT at an Electron root (control -- no over-suppression)' {
        $d = New-PvDir
        Set-Content -LiteralPath (Join-Path $d 'vendor.dll') -Value 'AKIA1234567890ABCDEF' -Encoding Ascii
        try {
            @(Test-TcpkSecrets -Path $d | Where-Object { $_.RuleId -eq 'secrets.aws-access-key-id' -and $_.File -match 'vendor' }).Count | Should -BeGreaterThan 0
        } finally { Remove-Item -LiteralPath $d -Recurse -Force }
    }
}
