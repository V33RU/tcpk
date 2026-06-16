#requires -Version 5.1
# Pester 5: secret scanning must catch ODD-byte-aligned UTF-16 wide strings (regression for the
# bug where Read-TcpkStringViews decoded $views.Utf16LeOdd but Test-TcpkSecrets only scanned the
# even view -- silently missing ~half of wide-char secrets in binaries).

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
    $script:d = Join-Path ([IO.Path]::GetTempPath()) ("tcpk-align-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:d -Force | Out-Null
    # 1 pad byte, then the secret as UTF-16LE => the secret begins at an ODD offset, so the
    # offset-0 (even) decode is garbage and only the offset-1 (odd) view recovers it.
    $secret = 'AKIA1234567890ABCDEF'   # matches the AWS access-key-id rule; no placeholder words
    $bytes  = @([byte]0x20) + [Text.Encoding]::Unicode.GetBytes($secret)
    [IO.File]::WriteAllBytes((Join-Path $script:d 'wide.bin'), [byte[]]$bytes)
    # plain-text provider keys -- regression for the quick-literal prefilter that extracted regex
    # SYNTAX (':AKIA' from '(?:', 'bgithub_pat_' from '\b') and silently skipped these rules,
    # zeroing out AWS / GitHub-PAT detection in files.
    Set-Content -LiteralPath (Join-Path $script:d 'plain.txt') -Encoding ASCII -Value (
        'aws=AKIA1234567890ABCDEF' + "`n" + 'gh=github_pat_' + ('A' * 82))
}
AfterAll { if ($script:d -and (Test-Path $script:d)) { Remove-Item -LiteralPath $script:d -Recurse -Force } }

Describe 'Test-TcpkSecrets odd-aligned UTF-16 coverage' {
    It 'recovers a secret stored at an odd byte offset (via the utf16le-odd view)' {
        $f = @(Test-TcpkSecrets -Path $script:d | Where-Object { $_.RuleId -like 'secrets.*' })
        $f.Count | Should -BeGreaterThan 0
        ($f | Where-Object { "$($_.Evidence)" -match 'utf16le-odd' }).Count | Should -BeGreaterThan 0
    }
}

Describe 'Test-TcpkSecrets quick-literal prefilter (regression)' {
    It 'detects AWS access key + GitHub fine-grained PAT in plain text (prefilter no longer skips them)' {
        $f = @(Test-TcpkSecrets -Path $script:d)
        ($f | Where-Object RuleId -eq 'secrets.aws-access-key-id').Count       | Should -BeGreaterThan 0
        ($f | Where-Object RuleId -eq 'secrets.github-fine-grained-pat').Count | Should -BeGreaterThan 0
    }
}
