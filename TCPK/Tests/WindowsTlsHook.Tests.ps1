#requires -Version 5.1
# Windows native-TLS hooks. Data/tcpk_hook.js gains SChannel (secur32 EncryptMessage/
# DecryptMessage via a SecBufferDesc walker) plus WinHTTP / WinINet read/write hooks, so
# native (non-.NET, non-OpenSSL) Windows apps have their TLS plaintext recovered too. The
# JS is a Frida agent (verified structurally with `node --check`; live capture needs a
# target); here we verify the PARSER side recognises the new function names as TLS sources
# and still mines secrets from what they capture.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
    $script:work = Join-Path ([IO.Path]::GetTempPath()) ("tcpk-wtls-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:work -Force | Out-Null
}
AfterAll {
    if ($script:work -and (Test-Path -LiteralPath $script:work)) { try { [System.IO.Directory]::Delete($script:work, $true) } catch {} }
}

Describe 'Windows native-TLS hook capture parsing' {
    It 'treats a WinHttpReadData capture as recovered TLS plaintext and mines its secret' {
        $hook = Join-Path $script:work 'winhttp.log'
        @(
            'TCPKHOOK {"dir":"recv","func":"WinHttpReadData","len":24,"data":"token=abcdef123456secret"}'
        ) | Set-Content -LiteralPath $hook -Encoding UTF8
        $f = @(InModuleScope TCPK -Parameters @{ hf = $hook } { param($hf) ConvertFrom-TcpkHookCapture -HookFile $hf })
        ($f | Where-Object { $_.RuleId -eq 'intercept.api-hook-plaintext' }) | Should -Not -BeNullOrEmpty
        ($f | Where-Object { $_.RuleId -eq 'intercept.cleartext-credential' }) | Should -Not -BeNullOrEmpty
    }

    It 'recognises SChannel and WinINet functions as TLS sources' {
        foreach ($fn in @('DecryptMessage', 'InternetReadFile', 'HttpSendRequestW')) {
            $hook = Join-Path $script:work "$fn.log"
            "TCPKHOOK {""dir"":""recv"",""func"":""$fn"",""len"":5,""data"":""hello world plaintext""}" | Set-Content -LiteralPath $hook -Encoding UTF8
            $f = @(InModuleScope TCPK -Parameters @{ hf = $hook } { param($hf) ConvertFrom-TcpkHookCapture -HookFile $hf })
            ($f | Where-Object { $_.RuleId -eq 'intercept.api-hook-plaintext' }) | Should -Not -BeNullOrEmpty -Because "$fn should count as a TLS source"
        }
    }
}
