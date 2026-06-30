#requires -Version 5.1
# v1.8.2: the keyword "prefilter" gates on the heavy secret rules must be LOSS-FREE -- they
# only skip work, never drop a real positive. For each gated rule, a realistic secret that
# CONTAINS its trigger word must still be detected. Guards against a prefilter typo silently
# zeroing a rule (the v1.6.0 _QuickLit-regression class, now for the _Needles gate).
#
# Each test is self-contained (writes its own temp file + scans it) so the -ForEach data,
# discovered at parse time, and the module import (BeforeAll) compose without cross-phase
# $script: variable scoping problems.

$cases = @(
    @{ rule = 'cleartext-credential';               sample = 'password = "S3cr3t-Value-Z9"' }
    @{ rule = 'db-connection-string-with-password'; sample = 'Server=tcp:db.corp;Database=app;User Id=sa;Password=P@ssw0rd-Z9;' }
    @{ rule = 'azure-sas-token';                     sample = 'https://acct.blob.core.windows.net/c/b?sv=2022-11-02&ss=b&srt=co&sp=r&sig=abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQR12' }
    @{ rule = 'aws-access-key-id';                   sample = 'aws_key=AKIAIOSFODNN7EXAMPLE' }
    @{ rule = 'aws-secret-key-context';             sample = 'aws_secret_access_key = wJalrXUtnFEMIzK7MDENGzbPxRfiCYzZZ9LEKEY1234' }
    @{ rule = 'jwt-token';                           sample = 'token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVZadQssw5c' }
    @{ rule = 'github-classic-pat';                  sample = ('ghp_' + ('a' * 36)) }
    @{ rule = 'slack-token';                         sample = 'xoxb-1234567890-abcdefghijkl' }
    @{ rule = 'stripe-secret';                       sample = ('sk_live_' + ('A' * 24)) }
    @{ rule = 'gcp-service-account-key';            sample = '{"type": "service_account", "project_id": "x", "private_key": "-----BEGIN PRIVATE KEY-----' }
    @{ rule = 'private-key-xml';                     sample = '<RSAKeyValue><Modulus>x</Modulus><D>abcdefghijklmnopqrstuvwxyz0123456789AB</D></RSAKeyValue>' }
)

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
}

Describe 'Prefilter gates are loss-free (gated rule still detects a real positive)' {
    It 'detects <rule> when its trigger word is present' -ForEach $cases {
        $dir = Join-Path ([IO.Path]::GetTempPath()) ("tcpk-pf-" + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        try {
            Set-Content -LiteralPath (Join-Path $dir 'sample.txt') -Value $sample -Encoding UTF8
            $found = @(Test-TcpkSecrets -Path $dir | ForEach-Object { "$($_.RuleId)" })
            $found | Should -Contain "secrets.$rule"
        } finally { [IO.Directory]::Delete($dir, $true) }
    }
}
