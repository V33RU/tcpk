#requires -Version 5.1
# Pester 5: the interception flow-parser (Invoke-TcpkIntercept -FlowFile). Feeds a
# synthetic mitmproxy capture and asserts the intercept.* findings. Pure parsing, no
# mitmproxy and no network, so it runs anywhere PowerShell does (Windows or Linux).

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force

    $basic = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes('admin:S3cr3t!'))
    $flows = @(
        [ordered]@{ method = 'GET';  scheme = 'http';  host = 'api.evil.test'; port = 80;  path = '/login'; url = 'http://api.evil.test/login';  req_headers = @{ Authorization = "Basic $basic" }; req_body = '' }
        [ordered]@{ method = 'POST'; scheme = 'https'; host = 'api.good.test'; port = 443; path = '/auth';  url = 'https://api.good.test/auth'; req_headers = @{ Authorization = 'Bearer eyJhbGciOi.payload.sig' }; req_body = '' }
        [ordered]@{ method = 'POST'; scheme = 'http';  host = 'api.evil.test'; port = 80;  path = '/set';   url = 'http://api.evil.test/set';    req_headers = @{}; req_body = 'user=bob&password=hunter2&x=1' }
    )
    $script:fx = Join-Path ([System.IO.Path]::GetTempPath()) ('tcpk-flows-' + [guid]::NewGuid().ToString('N') + '.jsonl')
    $flows | ForEach-Object { $_ | ConvertTo-Json -Depth 6 -Compress } | Set-Content -LiteralPath $script:fx
}
AfterAll { if ($script:fx -and (Test-Path $script:fx)) { Remove-Item $script:fx -Force -ErrorAction SilentlyContinue } }

Describe 'Invoke-TcpkIntercept -FlowFile' {
    It 'recovers HTTP Basic credentials from the capture' {
        $cred = @(Invoke-TcpkIntercept -FlowFile $script:fx | Where-Object { $_.RuleId -eq 'intercept.cleartext-credential' -and $_.Evidence -match 'admin' })
        $cred.Count | Should -BeGreaterThan 0
    }
    It 'a Basic credential over http is CRITICAL / Confirmed (dynamic)' {
        $c = @(Invoke-TcpkIntercept -FlowFile $script:fx | Where-Object { $_.RuleId -eq 'intercept.cleartext-credential' -and $_.Evidence -match 'admin' })[0]
        $c.Severity   | Should -Be 'CRITICAL'
        $c.Confidence | Should -Be 'Confirmed (dynamic)'
    }
    It 'flags a credential parameter in the request body' {
        $p = @(Invoke-TcpkIntercept -FlowFile $script:fx | Where-Object { $_.RuleId -eq 'intercept.cleartext-credential' -and $_.Evidence -match 'password' })
        $p.Count | Should -BeGreaterThan 0
    }
    It 'flags a bearer/session token' {
        @(Invoke-TcpkIntercept -FlowFile $script:fx | Where-Object { $_.RuleId -eq 'intercept.session-token' }).Count | Should -BeGreaterThan 0
    }
    It 'flags cleartext http transport' {
        @(Invoke-TcpkIntercept -FlowFile $script:fx | Where-Object { $_.RuleId -eq 'intercept.weak-transport' }).Count | Should -BeGreaterThan 0
    }
    It 'confirms endpoints observed on the wire' {
        @(Invoke-TcpkIntercept -FlowFile $script:fx | Where-Object { $_.RuleId -eq 'intercept.endpoint-confirmed' }).Count | Should -BeGreaterThan 0
    }
    It 'does not mask away the recovered username' {
        $c = @(Invoke-TcpkIntercept -FlowFile $script:fx | Where-Object { $_.RuleId -eq 'intercept.cleartext-credential' -and $_.Evidence -match 'admin' })[0]
        $c.Evidence | Should -Not -Match 'hunter2'   # the password value stays masked
    }
}
