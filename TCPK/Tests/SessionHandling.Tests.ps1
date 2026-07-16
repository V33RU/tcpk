#requires -Version 5.1
# Pester 5: Test-TcpkSessionHandling (A33) - static session-hygiene scan over shipped
# config + source. All findings must be Inferred (a string match proves the pattern is
# present, not that it governs a live session).

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force

    $script:fx = Join-Path ([System.IO.Path]::GetTempPath()) ('tcpk-sess-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:fx | Out-Null

    # web.config: insecure forms-auth + cookie config
    @'
<configuration>
  <system.web>
    <authentication mode="Forms">
      <forms requireSSL="false" timeout="2880" cookieless="UseUri" />
    </authentication>
    <httpCookies httpOnlyCookies="false" />
  </system.web>
</configuration>
'@ | Set-Content -LiteralPath (Join-Path $script:fx 'web.config') -Encoding UTF8

    # source: GUID session token, no-HttpOnly cookie, token in URL
    @'
public void Login() {
    var token = Guid.NewGuid();
    cookie.HttpOnly = false;
    var url = "https://api.example.com/data?access_token=" + token;
}
'@ | Set-Content -LiteralPath (Join-Path $script:fx 'Session.cs') -Encoding UTF8
}

AfterAll {
    if ($script:fx -and (Test-Path $script:fx)) { Remove-Item $script:fx -Recurse -Force -ErrorAction SilentlyContinue }
}

Describe 'Test-TcpkSessionHandling - exported and scans session hygiene' {
    It 'is available as a command' {
        Get-Command Test-TcpkSessionHandling -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
    }

    Context 'against the fixture' {
        BeforeAll { $script:f = @(Test-TcpkSessionHandling -Path $script:fx) }

        It 'flags <_>' -ForEach @(
            'session.cookie-not-httponly'
            'session.cookie-not-secure'
            'session.cookieless-session'
            'session.high-timeout'
            'session.weak-token-guid'
            'session.token-in-url'
        ) {
            ($script:f | Where-Object RuleId -eq $_) | Should -Not -BeNullOrEmpty
        }

        It 'reports every session finding as Inferred (not Confirmed)' {
            $sess = $script:f | Where-Object RuleId -like 'session.*'
            $sess | Should -Not -BeNullOrEmpty
            ($sess | Where-Object Confidence -ne 'Inferred') | Should -BeNullOrEmpty
        }

        It 'produces a copy-paste verify hint for a session finding' {
            $hint = & (Get-Module TCPK) { param($r,$file) Get-TcpkVerifyHint -RuleId $r -File $file } 'session.cookie-not-httponly' (Join-Path $script:fx 'web.config')
            $hint | Should -Match 'WHAT THIS CHECKS'
        }
    }
}
