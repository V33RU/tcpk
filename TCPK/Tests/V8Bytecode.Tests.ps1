#requires -Version 5.1
# Pester 5: Test-TcpkV8Bytecode. The whole point of this check is that a bytecode-only app
# must NOT produce a clean report, so the tests focus on the false-positive and
# false-negative boundaries rather than on the happy path.

BeforeAll {
    Import-Module "$PSScriptRoot\..\TCPK.psd1" -Force

    function New-TestDir {
        $d = Join-Path ([System.IO.Path]::GetTempPath()) ('tcpk-v8-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
        New-Item -ItemType Directory -Path $d -Force | Out-Null
        return $d
    }
    # V8 bytecode is binary and starts with a header containing NULs; a plausible stand-in
    # is enough here because the detector tests "is this binary", not "is this valid V8".
    function New-JscFile([string]$Path) {
        $b = New-Object byte[] 512
        $b[0] = 0xC0; $b[1] = 0xDE; $b[2] = 0x00; $b[3] = 0x00
        [System.IO.File]::WriteAllBytes($Path, $b)
    }
}

Describe 'Test-TcpkV8Bytecode' {
    It 'stays silent on a target that is not Electron-shaped' {
        $d = New-TestDir
        try {
            Set-Content -LiteralPath (Join-Path $d 'readme.txt') -Value 'not electron'
            @(Test-TcpkV8Bytecode -Path $d).Count | Should -Be 0
        } finally { Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'stays silent on a normal Electron app with readable JS' {
        $d = New-TestDir
        try {
            Set-Content -LiteralPath (Join-Path $d 'main.js') -Value 'const { app } = require("electron"); app.whenReady()'
            Set-Content -LiteralPath (Join-Path $d 'preload.js') -Value 'window.x = 1'
            @(Test-TcpkV8Bytecode -Path $d).Count | Should -Be 0
        } finally { Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'flags a .jsc file whose contents are actually binary' {
        $d = New-TestDir
        try {
            New-JscFile (Join-Path $d 'main.jsc')
            $f = @(Test-TcpkV8Bytecode -Path $d | Where-Object RuleId -eq 'electron.v8-bytecode')
            $f | Should -Not -BeNullOrEmpty
            $f[0].Evidence | Should -Match 'jsc=1'
        } finally { Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'does NOT flag a text file that merely has a .jsc extension' {
        $d = New-TestDir
        try {
            Set-Content -LiteralPath (Join-Path $d 'notes.jsc') -Value 'this is plain text, not bytecode'
            Set-Content -LiteralPath (Join-Path $d 'main.js') -Value 'console.log(1)'
            @(Test-TcpkV8Bytecode -Path $d | Where-Object RuleId -eq 'electron.v8-bytecode') | Should -BeNullOrEmpty
        } finally { Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'flags bytenode declared as a dependency even with no .jsc present yet' {
        $d = New-TestDir
        try {
            Set-Content -LiteralPath (Join-Path $d 'main.js') -Value 'console.log(1)'
            Set-Content -LiteralPath (Join-Path $d 'package.json') -Encoding ASCII `
                -Value '{ "name":"x", "dependencies": { "bytenode": "^1.3.0" } }'
            $f = @(Test-TcpkV8Bytecode -Path $d | Where-Object RuleId -eq 'electron.v8-bytecode')
            $f | Should -Not -BeNullOrEmpty
            $f[0].Evidence | Should -Match 'bytenode'
        } finally { Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'rates it HIGH when bytecode outnumbers readable JS' {
        $d = New-TestDir
        try {
            1..3 | ForEach-Object { New-JscFile (Join-Path $d "m$_.jsc") }
            $f = @(Test-TcpkV8Bytecode -Path $d | Where-Object RuleId -eq 'electron.v8-bytecode')
            $f[0].Severity | Should -Be 'HIGH'
        } finally { Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'states that missing JS findings are unknown rather than clean' {
        $d = New-TestDir
        try {
            New-JscFile (Join-Path $d 'main.jsc')
            $f = @(Test-TcpkV8Bytecode -Path $d | Where-Object RuleId -eq 'electron.v8-bytecode')
            # This wording is the entire reason the check exists; assert it survives edits.
            $f[0].Description | Should -Match 'UNKNOWN, NOT AS CLEAN'
        } finally { Remove-Item -LiteralPath $d -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

Describe 'electron.v8-bytecode is registered in the mapping tables' {
    It 'maps to an ATT&CK technique and a TASVS control' {
        $t = & (Get-Module TCPK) { Get-TcpkAttackTechnique -RuleId 'electron.v8-bytecode' }
        @($t).Count | Should -BeGreaterThan 0
        ($t -join ' ') | Should -Match 'T1027'
        $c = & (Get-Module TCPK) { Get-TcpkTasvsControl -RuleId 'electron.v8-bytecode' }
        @($c).Count | Should -BeGreaterThan 0
    }
}
