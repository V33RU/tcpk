#requires -Version 5.1
# Regression: a bare PEM header string (UI placeholder / format label / detection regex)
# must NOT be reported as a leaked private key. Only a full block -- header + base64 body
# + END marker -- counts. Guards the secrets.pem-private-key CRITICAL false positive that
# fired on Claude Desktop's minified JS (placeholder:"-----BEGIN RSA PRIVATE KEY-----").

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force

    $script:work = Join-Path ([IO.Path]::GetTempPath()) ("tcpk-pemfp-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:work -Force | Out-Null

    # (1) header-only placeholders, exactly like the real false positive -- must NOT flag
    'const form={placeholder:"-----BEGIN RSA PRIVATE KEY-----",hint:"-----BEGIN PRIVATE KEY-----"};' |
        Set-Content -LiteralPath (Join-Path $script:work 'placeholder.js') -Encoding UTF8

    # (2) a full (dummy) PEM block: header + base64 body + END -- must flag
    $body = ('A' * 1700)
    "-----BEGIN RSA PRIVATE KEY-----`n$body`n-----END RSA PRIVATE KEY-----" |
        Set-Content -LiteralPath (Join-Path $script:work 'realkey.txt') -Encoding UTF8
}

AfterAll {
    if ($script:work -and (Test-Path -LiteralPath $script:work)) {
        try { [System.IO.Directory]::Delete($script:work, $true) } catch {}
    }
}

Describe 'secrets.pem-private-key false-positive guard' {
    It 'does NOT flag a header-only placeholder string' {
        $r = @(Test-TcpkSecrets -Path (Join-Path $script:work 'placeholder.js') |
               Where-Object { $_.RuleId -eq 'secrets.pem-private-key' })
        $r.Count | Should -Be 0
    }

    It 'DOES flag a full PEM block (header + body + END) as HIGH' {
        # HIGH (not CRITICAL): a shipped cleartext private key is rated HIGH so the badge
        # matches its computed CVSS v4.0 (embedded-key archetype = 8.5 High).
        $r = @(Test-TcpkSecrets -Path (Join-Path $script:work 'realkey.txt') |
               Where-Object { $_.RuleId -eq 'secrets.pem-private-key' })
        $r.Count | Should -BeGreaterThan 0
        $r[0].Severity | Should -Be 'HIGH'
    }
}
