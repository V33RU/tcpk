#requires -Version 5.1
# Pester 5: Test-TcpkCredentialLiveness (http) against a local HttpListener that returns 401
# without the right Basic auth and 200 with it. HttpListener + HttpClient are cross-platform,
# so this runs on Linux. Exercises the gate (Enable-TcpkExploit) and the -ConfirmActive ack.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force

    $l = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0); $l.Start()
    $script:port = ([System.Net.IPEndPoint]$l.LocalEndpoint).Port; $l.Stop()
    $script:url = "http://127.0.0.1:$($script:port)/secret"

    $script:job = Start-Job -ArgumentList $script:port -ScriptBlock {
        param($port)
        $expected = 'Basic ' + [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes('admin:s3cret'))
        $listener = [System.Net.HttpListener]::new()
        $listener.Prefixes.Add("http://127.0.0.1:$port/")
        $listener.Start()
        try {
            while ($true) {
                $ctx = $listener.GetContext()
                if ("$($ctx.Request.Headers['Authorization'])" -eq $expected) { $ctx.Response.StatusCode = 200 }
                else { $ctx.Response.StatusCode = 401; $ctx.Response.AddHeader('WWW-Authenticate', 'Basic realm=x') }
                $ctx.Response.Close()
            }
        } finally { $listener.Stop() }
    }
    Start-Sleep -Seconds 2
    Enable-TcpkExploit -Acknowledge | Out-Null
}
AfterAll {
    try { Disable-TcpkExploit | Out-Null } catch { }
    if ($script:job) { Stop-Job $script:job -ErrorAction SilentlyContinue; Remove-Job $script:job -Force -ErrorAction SilentlyContinue }
}

Describe 'Test-TcpkCredentialLiveness (http)' {
    It 'confirms a valid credential as an exploit' {
        $f = Test-TcpkCredentialLiveness -Target $script:url -Protocol http -Username admin -Password s3cret -ConfirmActive
        $f.Confidence | Should -Be 'Confirmed (exploit)'
        $f.Severity   | Should -Be 'CRITICAL'
        $f.RuleId     | Should -Be 'exploit.credential-live'
    }
    It 'does not confirm a wrong credential' {
        $f = Test-TcpkCredentialLiveness -Target $script:url -Protocol http -Username admin -Password WRONG -ConfirmActive
        $f.Confidence | Should -Be 'Inferred'
        $f.Title      | Should -Match 'rejected'
    }
    It 'is gated behind Enable-TcpkExploit' {
        Disable-TcpkExploit | Out-Null
        { Test-TcpkCredentialLiveness -Target $script:url -Protocol http -Username admin -Password s3cret -ConfirmActive } | Should -Throw
        Enable-TcpkExploit -Acknowledge | Out-Null
    }
    It 'requires -ConfirmActive' {
        { Test-TcpkCredentialLiveness -Target $script:url -Protocol http -Username admin -Password s3cret } | Should -Throw
    }
}
