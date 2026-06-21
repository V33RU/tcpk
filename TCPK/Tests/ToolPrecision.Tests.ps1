#requires -Version 5.1
# Precision fixes (v1.6.x): string-scanning checks must not misattribute the bundled Chromium
# runtime or stock helper binaries to the audited app. Telemetry domains inside Chromium, the
# NSIS / elevate stock-tool homepages (nsis.sf.net / int3.de), and cert-pin trust stores
# (cert-pins.json holds PUBLIC fingerprints) are the false-positive classes fixed here.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
    $script:work = Join-Path ([IO.Path]::GetTempPath()) ("tcpk-precision-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:work -Force | Out-Null
}
AfterAll {
    if ($script:work -and (Test-Path -LiteralPath $script:work)) { [IO.Directory]::Delete($script:work, $true) }
}

Describe 'Telemetry gating: Chromium runtime not attributed to the app' {
    It 'flags google-analytics in a first-party PE but NOT inside the bundled Chromium runtime' {
        $d = Join-Path $script:work 'tel'; New-Item -ItemType Directory -Path $d -Force | Out-Null
        [IO.File]::WriteAllText((Join-Path $d 'MyApp.dll'),     'MZ first-party app integrates GoogleAnalytics. via google-analytics.com')
        [IO.File]::WriteAllText((Join-Path $d 'chromerun.dll'), 'MZ google-analytics.com inside v8_context_snapshot Chromium Electron runtime')
        $f = @(Test-TcpkTelemetrySdks -Path $d | Where-Object RuleId -eq 'telemetry.googleanalytics')
        @($f).Count | Should -Be 1
        (Split-Path $f[0].File -Leaf) | Should -Be 'MyApp.dll'
    }
}

Describe 'Cleartext scheme gating: stock-tool homepages suppressed' {
    It 'flags a real http host but NOT nsis.sf.net / int3.de' {
        $d = Join-Path $script:work 'sch'; New-Item -ItemType Directory -Path $d -Force | Out-Null
        [IO.File]::WriteAllText((Join-Path $d 'App.dll'), 'MZ http://nsis.sf.net/x http://int3.de/y http://backend.realapp.example/api')
        $hosts = @(Test-TcpkInsecureSchemes -Path $d | Where-Object RuleId -eq 'scheme.cleartext-http' | ForEach-Object { ($_.Title -split ': ')[-1] })
        $hosts | Should -Contain 'backend.realapp.example'
        $hosts | Should -Not -Contain 'nsis.sf.net'
        $hosts | Should -Not -Contain 'int3.de'
    }
}

Describe 'Backend endpoint gating: stock-tool homepages suppressed' {
    It 'does not list nsis.sf.net / int3.de as backends but keeps a real one' {
        $d = Join-Path $script:work 'be'; New-Item -ItemType Directory -Path $d -Force | Out-Null
        [IO.File]::WriteAllText((Join-Path $d 'App.dll'), 'MZ https://api.realapp.example/v1 http://int3.de/z https://nsis.sf.net/dl')
        $titles = @(Test-TcpkBackendEndpoints -Path $d | Where-Object RuleId -eq 'backend.endpoint' | ForEach-Object Title) -join '|'
        $titles | Should -Match 'api\.realapp\.example'
        $titles | Should -Not -Match 'int3\.de'
        $titles | Should -Not -Match 'nsis\.sf\.net'
    }
}

Describe 'Entropy gating: cert-pin stores are public, not secrets' {
    It 'does not flag cert-pins.json but still flags a real keyed secret' {
        $d = Join-Path $script:work 'ent'; New-Item -ItemType Directory -Path $d -Force | Out-Null
        [IO.File]::WriteAllText((Join-Path $d 'cert-pins.json'), '{"vc4.local":["AAAaGVsbG8xMjM0NTY3ODkwQUJDREVGR0hJ9876543210xyzABCDEFGmn="]}')
        [IO.File]::WriteAllText((Join-Path $d 'app.config'),     'apiKey=AbCdEf0123456789ZxYwVu9876543210QqWwEeRrTtUuVv12')
        $cp   = @(Test-TcpkEntropySecrets -Path $d | Where-Object { (Split-Path $_.File -Leaf) -eq 'cert-pins.json' })
        $real = @(Test-TcpkEntropySecrets -Path $d | Where-Object { (Split-Path $_.File -Leaf) -eq 'app.config' })
        @($cp).Count   | Should -Be 0
        @($real).Count | Should -BeGreaterThan 0
    }
}
