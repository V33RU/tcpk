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

Describe 'Invoke-TcpkIntercept -HookFile (Frida hook capture)' {
    BeforeAll {
        $b = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes('admin:S3cr3t!'))
        $lines = @(
            'TCPKHOOK ' + ([ordered]@{ dir = 'send'; func = 'SSL_write'; len = 1; data = "GET /login HTTP/1.1`r`nHost: api.hooktest`r`nAuthorization: Basic $b`r`n`r`n" } | ConvertTo-Json -Compress)
            'TCPKHOOK ' + ([ordered]@{ dir = 'send'; func = 'send';      len = 1; data = 'POST /set HTTP/1.1 password=hunter2&x=1' } | ConvertTo-Json -Compress)
            'TCPKHOOK ' + ([ordered]@{ dir = 'send'; func = 'SSL_write'; len = 1; data = "X`r`nAuthorization: Bearer eyJ.aa.bb`r`n" } | ConvertTo-Json -Compress)
        )
        $script:hf = Join-Path ([System.IO.Path]::GetTempPath()) ('tcpk-hook-' + [guid]::NewGuid().ToString('N') + '.log')
        Set-Content -LiteralPath $script:hf -Value $lines
    }
    AfterAll { if ($script:hf -and (Test-Path $script:hf)) { Remove-Item $script:hf -Force -ErrorAction SilentlyContinue } }

    It 'recovers Basic credentials captured at the API' {
        @(Invoke-TcpkIntercept -HookFile $script:hf | Where-Object { $_.RuleId -eq 'intercept.cleartext-credential' -and $_.Evidence -match 'admin' }).Count | Should -BeGreaterThan 0
    }
    It 'flags a credential parameter in a hooked buffer' {
        @(Invoke-TcpkIntercept -HookFile $script:hf | Where-Object { $_.Evidence -match 'password' }).Count | Should -BeGreaterThan 0
    }
    It 'flags a bearer token captured via the hook' {
        @(Invoke-TcpkIntercept -HookFile $script:hf | Where-Object { $_.RuleId -eq 'intercept.session-token' }).Count | Should -BeGreaterThan 0
    }
    It 'confirms the endpoint from the hooked HTTP request' {
        @(Invoke-TcpkIntercept -HookFile $script:hf | Where-Object { $_.RuleId -eq 'intercept.endpoint-confirmed' -and $_.File -match 'api.hooktest' }).Count | Should -BeGreaterThan 0
    }
    It 'notes TLS plaintext recovered when an SSL function was hooked' {
        @(Invoke-TcpkIntercept -HookFile $script:hf | Where-Object { $_.RuleId -eq 'intercept.api-hook-plaintext' }).Count | Should -BeGreaterThan 0
    }
}
