#requires -Version 5.1
# v1.8.x: TCPK must read files a RUNNING target holds open (Chromium cache block files, logs,
# SQLite WAL/journal). Read-TcpkStringViews now opens with FileShare.ReadWrite|Delete; before,
# a file another process held open for WRITE was silently skipped and its secrets never scanned
# -- which is how a plaintext credential cached by a running app was missed end-to-end.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
    $script:f = Join-Path ([IO.Path]::GetTempPath()) ("tcpk-lock-" + [guid]::NewGuid().ToString('N') + ".txt")
    [IO.File]::WriteAllText($script:f, 'cached login: userid="svc_test" password="Synthetic-Lock-9"')
}
AfterAll { if ($script:f -and (Test-Path -LiteralPath $script:f)) { Remove-Item -LiteralPath $script:f -Force } }

Describe 'Reading a file held open (for write) by another process' {
    BeforeEach { & (Get-Module TCPK) { Clear-TcpkTextCache } }

    It 'reads a write-locked file instead of silently skipping it' {
        # simulate the running target: hold the file open for WRITE, sharing only Read
        $writer = [System.IO.FileStream]::new($script:f, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read)
        try {
            $v = & (Get-Module TCPK) { param($p) Read-TcpkStringViews -Path $p } $script:f
            $v | Should -Not -BeNullOrEmpty
            $v.Utf8 | Should -Match 'password'
        } finally { $writer.Dispose() }
    }

    It 'flags the cleartext credential in a locked file end-to-end' {
        $writer = [System.IO.FileStream]::new($script:f, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read)
        try {
            @(Test-TcpkSecrets -Path $script:f | Where-Object RuleId -eq 'secrets.cleartext-credential').Count |
                Should -BeGreaterThan 0
        } finally { $writer.Dispose() }
    }
}
