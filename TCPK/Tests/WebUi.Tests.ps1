#requires -Version 5.1
# Pester 5: loopback HTTP + /api engine in _WebUi.ps1 (Invoke-TcpkWebApi and helpers).
# The standalone Start-TcpkWebUi entry point was removed in favour of the agentic workbench,
# but this engine still powers it (Start-TcpkAgentic delegates /api/* here). Tests the PURE
# pieces -- token, host/auth, target validation, the request dispatcher -- plus the ASYNC
# audit flow (background job -> /api/status poll -> result tabs), pause/resume/cancel, the
# list-all enumerator, and report-download path-traversal hardening. No real socket needed
# (the dispatcher is called directly); the audit runs as a real background job.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
    $script:psd1 = $psd1

    $script:fx = Join-Path ([IO.Path]::GetTempPath()) ("tcpk-webfx-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:fx -Force | Out-Null
    # web audits now write to <OutRoot>\out\<target>_<stamp> (GUI scheme); redirect to a temp
    # OutRoot so the suite never writes into the real out\ folder, and clean it in AfterAll.
    $script:webOutRoot = Join-Path ([IO.Path]::GetTempPath()) ("tcpk-weboutroot-" + [guid]::NewGuid().ToString('N'))
    Set-Content -LiteralPath (Join-Path $script:fx 'app.js') -Encoding ASCII `
        -Value 'const u = "http://updates.insecure.test/feed"; fetch(u);'

    function Invoke-Api($req, $state) {
        & (Get-Module TCPK) { param($r, $s) Invoke-TcpkWebApi -Request $r -State $s } $req $state
    }
    function New-State($port, $tok) {
        & (Get-Module TCPK) { param($p, $t, $d, $o) @{ Token = $t; Port = $p; Version = '9.9.9-test'; Stop = $false; Jobs = @{}; Psd1 = $d; ChkTotal = 135; OutRoot = $o } } $port $tok $script:psd1 $script:webOutRoot
    }
    function New-Req($method, $path, $port, $tok, $query, $body) {
        $h = @{ host = "127.0.0.1:$port" }; if ($tok) { $h['x-tcpk-token'] = $tok }
        @{ Method = $method; Path = $path; Query = $query; Body = "$body"; Headers = $h }
    }
}
AfterAll { foreach ($d in @($script:fx, $script:webOutRoot)) { if ($d -and (Test-Path $d)) { Remove-Item -LiteralPath $d -Recurse -Force } } }

Describe 'web token + host + auth (pure)' {
    It 'mints a long, unique session token' {
        & (Get-Module TCPK) { $a = New-TcpkWebToken; $b = New-TcpkWebToken; @(($a.Length -ge 32), ($a -ne $b)) } | Should -Not -Contain $false
    }
    It 'accepts loopback host on the right port, rejects everything else' {
        & (Get-Module TCPK) { Test-TcpkWebHost '127.0.0.1:5000' 5000 } | Should -BeTrue
        & (Get-Module TCPK) { Test-TcpkWebHost 'localhost:5000' 5000 } | Should -BeTrue
        & (Get-Module TCPK) { Test-TcpkWebHost '127.0.0.1:5001' 5000 } | Should -BeFalse
        & (Get-Module TCPK) { Test-TcpkWebHost 'evil.example.com:5000' 5000 } | Should -BeFalse
        & (Get-Module TCPK) { Test-TcpkWebHost $null 5000 } | Should -BeFalse
    }
    It 'requires an exact, case-sensitive token match' {
        $good = @{ Headers = @{ host = '127.0.0.1:5000'; 'x-tcpk-token' = 'abcDEF123' } }
        $bad  = @{ Headers = @{ host = '127.0.0.1:5000'; 'x-tcpk-token' = 'abcdef123' } }
        $none = @{ Headers = @{ host = '127.0.0.1:5000' } }
        (& (Get-Module TCPK) { param($r) Test-TcpkWebRequestAuth -Request $r -Token 'abcDEF123' -Port 5000 } $good) | Should -BeTrue
        (& (Get-Module TCPK) { param($r) Test-TcpkWebRequestAuth -Request $r -Token 'abcDEF123' -Port 5000 } $bad)  | Should -BeFalse
        (& (Get-Module TCPK) { param($r) Test-TcpkWebRequestAuth -Request $r -Token 'abcDEF123' -Port 5000 } $none) | Should -BeFalse
    }
}

Describe 'target validation (pure)' {
    It 'resolves an existing path and rejects junk / empty' {
        (& (Get-Module TCPK) { param($p) Resolve-TcpkWebTarget $p } $script:fx) | Should -Not -BeNullOrEmpty
        (& (Get-Module TCPK) { Resolve-TcpkWebTarget 'Z:\nope\nope\nope_12345' }) | Should -BeNullOrEmpty
        (& (Get-Module TCPK) { Resolve-TcpkWebTarget '' }) | Should -BeNullOrEmpty
    }
}

Describe 'installed-app discovery + identity (pure)' {
    BeforeAll {
        $script:idfx = Join-Path ([IO.Path]::GetTempPath()) ("tcpk-idfx-" + [guid]::NewGuid().ToString('N'))
        $script:waDir = Join-Path $script:idfx 'WindowsApps\Acme.Demo_1.0.0.0_x64__abcd1234efgh'
        New-Item -ItemType Directory -Path $script:waDir -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $script:waDir 'Acme.exe') -Value 'x' -Encoding ASCII
        $script:clDir = Join-Path $script:idfx 'AcmeApp'
        New-Item -ItemType Directory -Path $script:clDir -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $script:clDir 'AcmeApp.exe') -Value 'x' -Encoding ASCII
    }
    AfterAll { if ($script:idfx -and (Test-Path $script:idfx)) { Remove-Item -LiteralPath $script:idfx -Recurse -Force } }

    It 'Get-TcpkInstalledApps returns a FLAT array of app objects (regression: ,@() nesting)' {
        $apps = & (Get-Module TCPK) { @(Get-TcpkInstalledApps) }
        # when the host has apps, each element must be a flat object with a string path,
        # NOT a nested array (the ,@(...) bug made @(...) collapse to a single inner array)
        foreach ($a in (@($apps) | Select-Object -First 3)) { $a.path | Should -BeOfType [string] }
    }
    It 'Find-TcpkWebApps returns objects with non-empty name+path, [] for empty query' {
        (& (Get-Module TCPK) { @(Find-TcpkWebApps '').Count }) | Should -Be 0
        $hits = & (Get-Module TCPK) { @(Find-TcpkWebApps 'Microsoft') }
        foreach ($h in (@($hits) | Select-Object -First 3)) {
            $h.name | Should -Not -BeNullOrEmpty
            $h.path | Should -Not -BeNullOrEmpty
        }
    }
    It 'Resolve-TcpkWebIdentity derives package identity from a WindowsApps path' {
        $id = & (Get-Module TCPK) { param($p) Resolve-TcpkWebIdentity -Path $p } $script:waDir
        $id.packageName | Should -Be 'Acme.Demo'
        $id.packageFamilyName | Should -Be 'Acme.Demo_abcd1234efgh'
        $id.processName | Should -Be 'Acme'
    }
    It 'Resolve-TcpkWebIdentity derives identity from a classic install folder' {
        $id = & (Get-Module TCPK) { param($p) Resolve-TcpkWebIdentity -Path $p } $script:clDir
        $id.packageName | Should -Be 'AcmeApp'
        $id.processName | Should -Be 'AcmeApp'
    }
    It 'Resolve-TcpkWebIdentity returns a not-found note for a missing target' {
        $id = & (Get-Module TCPK) { Resolve-TcpkWebIdentity -Path 'Z:\nope_nope_12345' }
        $id.packageName | Should -BeNullOrEmpty
        $id.note | Should -Match 'not found'
    }
}

Describe 'request dispatcher (no socket)' {
    BeforeAll { $script:port = 54999; $script:tok = 'SECRET-tok-123'; $script:state = New-State $script:port $script:tok }

    It 'serves the self-contained SPA on GET /' {
        $resp = Invoke-Api (New-Req 'GET' '/' $script:port $null @{} '') $script:state
        $resp.Status | Should -Be 200
        $resp.ContentType | Should -Match 'text/html'
        $resp.Body | Should -Match 'TCPK'
        $resp.Body | Should -Match 'id="onlineCve"'   # live-CVE (OSV) opt-in toggle present in the SPA
        $resp.Body | Should -Not -Match '<script[^>]+src='
        $resp.Body | Should -Not -Match '<link\b'
    }
    It 'rejects a non-loopback Host with 403 (anti DNS-rebind)' {
        $req = @{ Method = 'GET'; Path = '/'; Query = @{}; Body = ''; Headers = @{ host = "evil.example.com:$script:port" } }
        (Invoke-Api $req $script:state).Status | Should -Be 403
    }
    It 'rejects /api without the token (401)' {
        (Invoke-Api (New-Req 'GET' '/api/ping' $script:port $null @{} '') $script:state).Status | Should -Be 401
    }
    It 'answers /api/ping with the token (200)' {
        $resp = Invoke-Api (New-Req 'GET' '/api/ping' $script:port $script:tok @{} '') $script:state
        $resp.Status | Should -Be 200
        ($resp.Body | ConvertFrom-Json).ok | Should -BeTrue
    }
    It 'lists installed apps on /api/apps' {
        $resp = Invoke-Api (New-Req 'GET' '/api/apps' $script:port $script:tok @{} '') $script:state
        $resp.Status | Should -Be 200
        (($resp.Body | ConvertFrom-Json).PSObject.Properties.Name) | Should -Contain 'apps'
    }
    It 'auto-detects package/process identity on POST /api/identify' {
        $resp = Invoke-Api (New-Req 'POST' '/api/identify' $script:port $script:tok @{} ('{"path":' + ($script:fx | ConvertTo-Json) + '}')) $script:state
        $resp.Status | Should -Be 200
        ($resp.Body | ConvertFrom-Json).PSObject.Properties.Name | Should -Contain 'packageName'
    }
    It '404s an unknown api verb' {
        (Invoke-Api (New-Req 'GET' '/api/nope' $script:port $script:tok @{} '') $script:state).Status | Should -Be 404
    }
    It 'rejects a missing target on /api/run (400)' {
        (Invoke-Api (New-Req 'POST' '/api/run' $script:port $script:tok @{} '{"target":"Z:\\nope_98765"}') $script:state).Status | Should -Be 400
    }
    It 'sets Stop on /api/shutdown' {
        $s2 = New-State $script:port $script:tok
        $out = & (Get-Module TCPK) { param($r, $s) $resp = Invoke-TcpkWebApi -Request $r -State $s; [pscustomobject]@{ status = $resp.Status; stop = $s.Stop } } (New-Req 'POST' '/api/shutdown' $script:port $script:tok @{} '') $s2
        $out.status | Should -Be 200
        $out.stop | Should -BeTrue
    }
}

Describe 'async audit run (real background job)' {
    It 'runs a job, streams progress, returns the full result, and gates downloads' {
        $port = 54998; $tok = 'run-tok-xyz'; $state = New-State $port $tok
        $run = (Invoke-Api (New-Req 'POST' '/api/run' $port $tok @{} ('{"target":' + ($script:fx | ConvertTo-Json) + '}')) $state).Body | ConvertFrom-Json
        $run.jobId | Should -Not -BeNullOrEmpty

        # pause/resume while running
        ((Invoke-Api (New-Req 'POST' '/api/pause' $port $tok @{ job = $run.jobId } '') $state).Body | ConvertFrom-Json).paused | Should -BeTrue
        ((Invoke-Api (New-Req 'POST' '/api/resume' $port $tok @{ job = $run.jobId } '') $state).Body | ConvertFrom-Json).paused | Should -BeFalse

        $st = $null; $sawRunning = $false
        for ($i = 0; $i -lt 90; $i++) {
            Start-Sleep -Seconds 1
            $st = (Invoke-Api (New-Req 'GET' '/api/status' $port $tok @{ job = $run.jobId } '') $state).Body | ConvertFrom-Json
            if ($st.state -eq 'running') { $sawRunning = $true }
            if ($st.done) { break }
        }
        $sawRunning | Should -BeTrue
        $st.done | Should -BeTrue
        $st.state | Should -Be 'done'
        @($st.result.model.findings).Count | Should -BeGreaterThan 0
        $st.result.recon | Should -Not -BeNullOrEmpty
        $st.result.sbom | Should -Not -BeNullOrEmpty
        (@($st.result.reports) | ForEach-Object { $_.file }) | Should -Contain 'index.html'

        # report download: path-traversal blocked, real file served as a File response
        (Invoke-Api (New-Req 'GET' '/api/report' $port $tok @{ job = $run.jobId; file = '..\..\windows\win.ini' } '') $state).Status | Should -Be 404
        $dl = Invoke-Api (New-Req 'GET' '/api/report' $port $tok @{ job = $run.jobId; file = 'index.html' } '') $state
        $dl.Status | Should -Be 200
        $dl.File | Should -Not -BeNullOrEmpty
    }

    It 'cancels a running job' {
        $port = 54997; $tok = 'cancel-tok'; $state = New-State $port $tok
        $run = (Invoke-Api (New-Req 'POST' '/api/run' $port $tok @{} ('{"target":' + ($script:fx | ConvertTo-Json) + '}')) $state).Body | ConvertFrom-Json
        ((Invoke-Api (New-Req 'POST' '/api/cancel' $port $tok @{ job = $run.jobId } '') $state).Body | ConvertFrom-Json).cancelled | Should -BeTrue
    }
}

Describe 'AI provider options are wired (not decorative)' {
    BeforeAll {
        $script:cfgPath = & (Get-Module TCPK) { Get-TcpkLlmConfigPath }
        $script:cfgOrig = if (Test-Path $script:cfgPath) { Get-Content -LiteralPath $script:cfgPath -Raw } else { $null }
    }
    AfterAll { if ($null -ne $script:cfgOrig) { Set-Content -LiteralPath $script:cfgPath -Value $script:cfgOrig -Encoding UTF8 -NoNewline } }

    It 'applies the chosen provider/model to llm-config.json (read by the audit job)' {
        $m = & (Get-Module TCPK) { Set-TcpkWebLlmConfig -Body ([pscustomobject]@{ provider = 'ollama'; model = 'unit-test-model'; apiKey = '' }); (Get-TcpkLlmConfig).model }
        $m | Should -Be 'unit-test-model'
    }
    It 'answers /api/testai with a reachable flag and cloud detection' {
        $port = 54996; $tok = 'ai-tok'; $state = New-State $port $tok
        $resp = Invoke-Api (New-Req 'POST' '/api/testai' $port $tok @{} '{"provider":"claude","model":"claude-sonnet-4-5"}') $state
        $resp.Status | Should -Be 200
        $d = $resp.Body | ConvertFrom-Json
        $d.cloud | Should -BeTrue
        ($d.PSObject.Properties.Name) | Should -Contain 'reachable'
    }
}
