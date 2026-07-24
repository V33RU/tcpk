#requires -Version 5.1
# Interception uplift: (1) mine RESPONSE bodies for secrets / tokens / PII the server
# returns (the request-only scan missed these); (2) a tamper-differential verdict that
# flags when the backend returns success to a request whose value TCPK altered in flight.
# Both parse deterministically from a synthetic capture / log -- no network, no live proxy.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
    $script:work = Join-Path ([IO.Path]::GetTempPath()) ("tcpk-irsp-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:work -Force | Out-Null
}
AfterAll {
    if ($script:work -and (Test-Path -LiteralPath $script:work)) { try { [System.IO.Directory]::Delete($script:work, $true) } catch {} }
}

Describe 'Response-body mining (ConvertFrom-TcpkInterceptCapture)' {
    BeforeAll {
        $resp = '{"password":"hunter2secret","ssn":"123-45-6789","card":"4111111111111111","jwt":"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.s3cr3tSig"}'
        $flow = [ordered]@{ scheme = 'https'; host = 'api.example.test'; path = '/me'; url = 'https://api.example.test/me'; resp_body = $resp }
        $script:flowFile = Join-Path $script:work 'flows.jsonl'
        ($flow | ConvertTo-Json -Compress) | Set-Content -LiteralPath $script:flowFile -Encoding UTF8
        $script:f = @(InModuleScope TCPK -Parameters @{ ff = $script:flowFile } { param($ff) ConvertFrom-TcpkInterceptCapture -FlowFile $ff })
    }

    It 'flags a secret returned in the response body' {
        ($script:f | Where-Object { $_.RuleId -eq 'intercept.secret-in-response' }) | Should -Not -BeNullOrEmpty
    }
    It 'flags a JWT returned in the response body' {
        ($script:f | Where-Object { $_.RuleId -eq 'intercept.token-in-response' }) | Should -Not -BeNullOrEmpty
    }
    It 'flags an SSN and a Luhn-valid PAN returned in the response body' {
        $pii = @($script:f | Where-Object { $_.RuleId -eq 'intercept.pii-in-response' })
        ($pii | Where-Object { $_.Title -match 'SSN' }) | Should -Not -BeNullOrEmpty
        ($pii | Where-Object { $_.Title -match 'PAN' }) | Should -Not -BeNullOrEmpty
    }
    It 'does NOT flag a non-Luhn 16-digit number as a PAN (precision)' {
        $flow2 = [ordered]@{ scheme = 'https'; host = 'h.test'; path = '/x'; url = 'https://h.test/x'; resp_body = '{"n":"1234567812345678"}' }
        $ff2 = Join-Path $script:work 'flows2.jsonl'
        ($flow2 | ConvertTo-Json -Compress) | Set-Content -LiteralPath $ff2 -Encoding UTF8
        $r = @(InModuleScope TCPK -Parameters @{ ff = $ff2 } { param($ff) ConvertFrom-TcpkInterceptCapture -FlowFile $ff })
        ($r | Where-Object { $_.Title -match 'PAN' }) | Should -BeNullOrEmpty
    }
}

Describe 'Tamper-differential verdict (ConvertFrom-TcpkTamperLog)' {
    It 'flags an ACCEPTED tampered request (2xx) as HIGH' {
        $log = Join-Path $script:work 'tamper-accept.log'
        @('TCPKTAMPER req: ''role=user'' -> ''role=admin''', 'TCPKTAMPERRESP status=200 len=42') | Set-Content -LiteralPath $log -Encoding UTF8
        $r = @(InModuleScope TCPK -Parameters @{ lf = $log } { param($lf) ConvertFrom-TcpkTamperLog -LogFile $lf -Rules @('role=user=>role=admin') -Target 'app' })
        $acc = $r | Where-Object { $_.RuleId -eq 'intercept.tamper-accepted' }
        $acc | Should -Not -BeNullOrEmpty
        $acc.Severity | Should -Be 'HIGH'
    }
    It 'reports a REJECTED tampered request (4xx) as INFO, not accepted' {
        $log = Join-Path $script:work 'tamper-reject.log'
        @('TCPKTAMPER req: ''x'' -> ''y''', 'TCPKTAMPERRESP status=403 len=10') | Set-Content -LiteralPath $log -Encoding UTF8
        $r = @(InModuleScope TCPK -Parameters @{ lf = $log } { param($lf) ConvertFrom-TcpkTamperLog -LogFile $lf -Rules @('x=>y') -Target 'app' })
        ($r | Where-Object { $_.RuleId -eq 'intercept.tamper-accepted' }) | Should -BeNullOrEmpty
        ($r | Where-Object { $_.RuleId -eq 'intercept.tamper-rejected' }) | Should -Not -BeNullOrEmpty
    }
}
