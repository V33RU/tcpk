#requires -Version 5.1
# Pester 5: Confirm-TcpkAiInferenceServer, the gated live probe for local LLM inference
# servers, against real loopback listeners.
#
# Nothing here is a canned response object: every case sends real HTTP to a listener built in
# this file on System.Net.Sockets.TcpListener (no HttpListener, so no URL ACL and no
# elevation on Windows). The accept loop runs in a background runspace and shares one
# synchronized state table with the tests: a test sets the behaviour it wants, runs the
# cmdlet, and reads back the exact request lines the listener received. That last part is
# what lets a test prove a negative, such as "no request reached the redirect target".
#
# Two listeners are started: 'main' is the endpoint under test, 'other' stands in for a
# second origin (a redirect target, a proxy) whose request log must stay empty.

BeforeAll {
    Import-Module (Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1') -Force
    Enable-TcpkExploit -Acknowledge | Out-Null

    $script:psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    $script:root = Join-Path ([IO.Path]::GetTempPath()) ('tcpk-aiconfirm-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:root | Out-Null
    $script:targetDir = Join-Path $script:root 'target'
    New-Item -ItemType Directory -Path (Join-Path $script:targetDir 'bin') -Force | Out-Null
    $script:targetExe = Join-Path (Join-Path $script:targetDir 'bin') 'server.exe'
    Set-Content -LiteralPath $script:targetExe -Value 'MZ' -Encoding ASCII

    # Accept loop for one listener. Single-threaded on purpose: the cmdlet sends one request
    # at a time, each on its own connection.
    $script:MockServer = {
        param($Listener, $State)
        $reasons = @{ 200 = 'OK'; 204 = 'No Content'; 302 = 'Found'; 401 = 'Unauthorized'; 403 = 'Forbidden'; 404 = 'Not Found' }

        function Send-Mock {
            param($Stream, [int]$Code, [string]$Body = '', [string]$Type = 'text/plain', [hashtable]$Extra = @{}, [int]$DeclaredLength = -1)
            $bodyBytes = [System.Text.Encoding]::UTF8.GetBytes($Body)
            $len = $bodyBytes.Length
            if ($DeclaredLength -ge 0) { $len = $DeclaredLength }
            $head = "HTTP/1.1 $Code $($reasons[$Code])`r`n"
            if ($Code -ne 204) { $head += "Content-Type: $Type`r`nContent-Length: $len`r`n" }
            foreach ($k in $Extra.Keys) { $head += "${k}: $($Extra[$k])`r`n" }
            $head += "Connection: close`r`n`r`n"
            $hb = [System.Text.Encoding]::ASCII.GetBytes($head)
            $Stream.Write($hb, 0, $hb.Length)
            if ($bodyBytes.Length -gt 0) { $Stream.Write($bodyBytes, 0, $bodyBytes.Length) }
            $Stream.Flush()
        }

        # Keep the connection open, sending nothing more, until the client hangs up.
        function Wait-MockClientGone {
            param($Client, [int]$MaxMs)
            $until = [DateTime]::UtcNow.AddMilliseconds($MaxMs)
            while ([DateTime]::UtcNow -lt $until -and -not $State.Stop) {
                try {
                    if ($Client.Client.Poll(1000, [System.Net.Sockets.SelectMode]::SelectRead) -and $Client.Client.Available -eq 0) { return }
                } catch { return }
                Start-Sleep -Milliseconds 20
            }
        }

        $html = '<!doctype html><html><head><title>App</title></head><body><div id="root"></div></body></html>'
        while (-not $State.Stop) {
            $client = $null
            try {
                if (-not $Listener.Pending()) { Start-Sleep -Milliseconds 10; continue }
                $client = $Listener.AcceptTcpClient()
                $client.ReceiveTimeout = 2000
                $client.SendTimeout = 2000
                $stream = $client.GetStream()
                $buf = New-Object 'byte[]' 8192
                $text = ''
                while ($text.IndexOf("`r`n`r`n", [System.StringComparison]::Ordinal) -lt 0) {
                    $n = 0
                    try { $n = $stream.Read($buf, 0, $buf.Length) } catch { $n = 0 }
                    if ($n -le 0) { break }
                    $text += [System.Text.Encoding]::ASCII.GetString($buf, 0, $n)
                    if ($text.Length -gt 32768) { break }
                }
                # A bare TCP connect (the cmdlet's reachability check) sends no request.
                if ($text.IndexOf("`r`n`r`n", [System.StringComparison]::Ordinal) -ge 0) {
                    $lines = $text -split "`r`n"
                    $parts = $lines[0] -split ' '
                    $method = "$($parts[0])"
                    $target = "$($parts[1])"
                    $path = ($target -split '\?')[0]
                    $hdr = @{}
                    for ($i = 1; $i -lt $lines.Count; $i++) {
                        $ln = $lines[$i]
                        if (-not $ln) { break }
                        $ci = $ln.IndexOf([char]':')
                        if ($ci -gt 0) { $hdr[$ln.Substring(0, $ci).Trim().ToLowerInvariant()] = $ln.Substring($ci + 1).Trim() }
                    }
                    $entry = "$method $target|host=$($hdr['host'])|origin=$($hdr['origin'])|auth=$($hdr['authorization'])"
                    [void]$State.Log.Add($entry)
                    [void]$State.All.Add($entry)

                    $mode = "$($State.Mode)"
                    $json = 'application/json'
                    $hostHdr = "$($hdr['host'])"
                    $hostName = $hostHdr
                    $pc = $hostHdr.LastIndexOf([char]':')
                    if ($pc -gt 0 -and -not $hostHdr.EndsWith(']')) { $hostName = $hostHdr.Substring(0, $pc) }
                    $hostOk = ($hostName -eq '127.0.0.1' -or $hostName -eq 'localhost' -or $hostName -eq '[::1]')
                    $hasOrigin = $hdr.ContainsKey('origin')
                    $extra = @{}
                    if ($hasOrigin -and "$($State.Acao)" -eq '*')    { $extra['Access-Control-Allow-Origin'] = '*' }
                    if ($hasOrigin -and "$($State.Acao)" -eq 'echo') { $extra['Access-Control-Allow-Origin'] = "$($hdr['origin'])" }
                    if ($hasOrigin -and "$($State.Acao)" -eq 'fixed') { $extra['Access-Control-Allow-Origin'] = 'http://localhost:3000' }
                    if ($hasOrigin -and "$($State.Acao)" -eq 'double') { $extra['Access-Control-Allow-Origin'] = '*, http://localhost:3000' }
                    $verJson = '{"version":"' + "$($State.Version)" + '"}'

                    $guard = "$($State.Guard)"
                    $blocked = $false
                    if ($guard -eq 'strict' -and ($hasOrigin -or -not $hostOk)) { $blocked = $true }
                    if ($guard -eq 'host' -and -not $hostOk) { $blocked = $true }

                    if ($blocked) { Send-Mock -Stream $stream -Code 403 -Body '' }
                    elseif ($mode -eq 'ollama') {
                        if     ($path -eq '/')            { Send-Mock -Stream $stream -Code 200 -Body 'Ollama is running' -Extra $extra }
                        elseif ($path -eq '/api/version') { Send-Mock -Stream $stream -Code 200 -Body $verJson -Type $json -Extra $extra }
                        elseif ($path -eq '/api/tags')    { Send-Mock -Stream $stream -Code 200 -Body "$($State.Tags)" -Type $json -Extra $extra }
                        elseif ($path -eq '/v1/models')   { Send-Mock -Stream $stream -Code 200 -Body "$($State.V1)" -Type $json -Extra $extra }
                        else                              { Send-Mock -Stream $stream -Code 404 -Body '404 page not found' }
                    }
                    elseif ($mode -eq 'tags-only') {
                        # An app that is not Ollama: a models array and its own /api/version, no banner.
                        if     ($path -eq '/api/version') { Send-Mock -Stream $stream -Code 200 -Body $verJson -Type $json -Extra $extra }
                        elseif ($path -eq '/api/tags')    { Send-Mock -Stream $stream -Code 200 -Body "$($State.Tags)" -Type $json -Extra $extra }
                        else                              { Send-Mock -Stream $stream -Code 404 -Body 'not found' }
                    }
                    elseif ($mode -eq 'openai') {
                        # A /v1/models server that also happens to have its own /api/version.
                        if     ($path -eq '/api/version') { Send-Mock -Stream $stream -Code 200 -Body $verJson -Type $json -Extra $extra }
                        elseif ($path -eq '/v1/models')   { Send-Mock -Stream $stream -Code 200 -Body "$($State.V1)" -Type $json -Extra $extra }
                        else                              { Send-Mock -Stream $stream -Code 404 -Body 'not found' }
                    }
                    elseif ($mode -eq 'fakever-html') {
                        if ($path -eq '/api/version') { Send-Mock -Stream $stream -Code 200 -Body $verJson -Type $json }
                        else                          { Send-Mock -Stream $stream -Code 200 -Body $html -Type 'text/html' }
                    }
                    elseif ($mode -eq 'routes') {
                        # Per-route answers set by the test: $State.Routes maps a path to
                        # @{ Code; Body; Type; Extra }, $State.Default answers every other path.
                        $rt = $State.Default
                        if ($State.Routes.ContainsKey($path)) { $rt = $State.Routes[$path] }
                        $rx = @{}
                        foreach ($k in $extra.Keys) { $rx[$k] = $extra[$k] }
                        if ($rt.ContainsKey('Extra') -and $rt.Extra) { foreach ($k in $rt.Extra.Keys) { $rx[$k] = $rt.Extra[$k] } }
                        $rtType = 'text/plain'
                        if ($rt.ContainsKey('Type') -and $rt.Type) { $rtType = "$($rt.Type)" }
                        Send-Mock -Stream $stream -Code ([int]$rt.Code) -Body "$($rt.Body)" -Type $rtType -Extra $rx
                    }
                    elseif ($mode -eq 'html')       { Send-Mock -Stream $stream -Code 200 -Body $html -Type 'text/html' }
                    elseif ($mode -eq 'empty200')   { Send-Mock -Stream $stream -Code 200 -Body '' }
                    elseif ($mode -eq '204')        { Send-Mock -Stream $stream -Code 204 }
                    elseif ($mode -eq 'json-other') { Send-Mock -Stream $stream -Code 200 -Body '{"status":"ok","models":"none","data":{"x":1}}' -Type $json }
                    elseif ($mode -eq 'login302') {
                        if ($path -eq '/login') { Send-Mock -Stream $stream -Code 200 -Body '<html><form>login</form></html>' -Type 'text/html' }
                        else { Send-Mock -Stream $stream -Code 302 -Body '' -Extra @{ Location = '/login?session=SECRETTOKEN123' } }
                    }
                    elseif ($mode -eq 'redirect-cred') {
                        Send-Mock -Stream $stream -Code 302 -Body '' -Extra @{ Location = 'http://admin:Hunter2Pass@127.0.0.1:1/sso/Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZg/start' }
                    }
                    elseif ($mode -eq 'redirect-out') {
                        Send-Mock -Stream $stream -Code 302 -Body '' -Extra @{ Location = "http://127.0.0.1:$($State.OtherPort)$target" }
                    }
                    elseif ($mode -eq '401')     { Send-Mock -Stream $stream -Code 401 -Body '{"error":"unauthorized"}' -Type $json -Extra @{ 'WWW-Authenticate' = 'Bearer' } }
                    elseif ($mode -eq '403')     { Send-Mock -Stream $stream -Code 403 -Body '' }
                    elseif ($mode -eq '403-www') { Send-Mock -Stream $stream -Code 403 -Body '' -Extra @{ 'WWW-Authenticate' = 'Basic realm="x"' } }
                    elseif ($mode -eq 'big')     { Send-Mock -Stream $stream -Code 200 -Body "$($State.BigBody)" -Type $json }
                    elseif ($mode -eq 'stall') {
                        # Headers and one byte of a 1000-byte body, then silence.
                        Send-Mock -Stream $stream -Code 200 -Body '{' -Type $json -DeclaredLength 1000
                        Wait-MockClientGone -Client $client -MaxMs 15000
                    }
                    elseif ($mode -eq 'drip') {
                        # Headers at once, then one byte of a 1000-byte body every 100 ms.
                        Send-Mock -Stream $stream -Code 200 -Body '{' -Type $json -DeclaredLength 1000
                        $until = [DateTime]::UtcNow.AddMilliseconds(15000)
                        $one = [System.Text.Encoding]::ASCII.GetBytes(' ')
                        try {
                            while ([DateTime]::UtcNow -lt $until -and -not $State.Stop) {
                                $stream.Write($one, 0, 1); $stream.Flush()
                                Start-Sleep -Milliseconds 100
                            }
                        } catch { }
                    }
                    elseif ($mode -eq 'garbage') {
                        # Not HTTP at all: markup where the status line should be.
                        $gb = [System.Text.Encoding]::ASCII.GetBytes("<script>alert(1)</script> 1048576`r`n`r`n")
                        $stream.Write($gb, 0, $gb.Length); $stream.Flush()
                    }
                    elseif ($mode -eq 'hang') { Wait-MockClientGone -Client $client -MaxMs 15000 }
                    else { Send-Mock -Stream $stream -Code 404 -Body 'unknown mode' }
                }
            } catch {
            } finally {
                if ($client) { try { $client.Close() } catch { } }
            }
        }
        try { $Listener.Stop() } catch { }
    }

    # Bind first, in this runspace, so the socket is already listening when the tests start.
    # The port comes from a fixed loopback range and the first free one wins.
    function Start-AiMock {
        param([System.Net.IPAddress]$Address = [System.Net.IPAddress]::Loopback, [int]$First = 18300, [int]$Last = 18349)
        $listener = $null; $port = 0
        for ($p = $First; $p -le $Last; $p++) {
            $l = $null
            try {
                $l = [System.Net.Sockets.TcpListener]::new($Address, $p)
                $l.Start()
                $listener = $l; $port = $p
                break
            } catch { if ($l) { try { $l.Stop() } catch { } } }
        }
        if (-not $listener) { return $null }
        $state = [hashtable]::Synchronized(@{
            Mode = 'html'; Version = '0.30.4'; Guard = 'none'; Acao = ''; OtherPort = 0; Stop = $false
            Tags = ''; V1 = ''; BigBody = ''
            Routes = @{}; Default = @{ Code = 404; Body = 'not found'; Type = 'text/plain' }
            Log = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
            All = [System.Collections.ArrayList]::Synchronized((New-Object System.Collections.ArrayList))
        })
        $ps = [powershell]::Create()
        [void]$ps.AddScript($script:MockServer.ToString()).AddArgument($listener).AddArgument($state)
        $handle = $ps.BeginInvoke()
        return @{ Port = $port; State = $state; PS = $ps; Handle = $handle; Listener = $listener }
    }

    function Stop-AiMock {
        param($Mock)
        if (-not $Mock) { return }
        try { $Mock.State.Stop = $true } catch { }
        try { [void]$Mock.Handle.AsyncWaitHandle.WaitOne(3000) } catch { }
        try { $Mock.PS.Stop() } catch { }
        try { $Mock.PS.Dispose() } catch { }
        try { $Mock.Listener.Stop() } catch { }
    }

    $script:DefaultTags = '{"models":[{"name":"llama3:latest","model":"llama3:latest","size":1}]}'
    $script:DefaultV1   = '{"object":"list","data":[{"id":"llama3:latest","object":"model"}]}'
    # The answer a server gives when it checks an API key on a route and none was sent.
    $script:KeyError    = '{"error":{"code":401,"message":"Invalid API Key","type":"authentication_error"}}'

    # One answer for the 'routes' mode of the listener.
    function New-AiRoute {
        param([int]$Code = 200, [string]$Body = '', [string]$Type = 'application/json', [hashtable]$Extra = @{})
        return @{ Code = $Code; Body = $Body; Type = $Type; Extra = $Extra }
    }

    # Put one listener into a known state and empty its per-test request log.
    function Set-AiMock {
        param($Mock, [string]$Mode, [string]$Version = '0.30.4', [string]$Guard = 'none', [string]$Acao = '',
              [string]$Tags = $script:DefaultTags, [string]$V1 = $script:DefaultV1,
              [hashtable]$Routes = @{}, [hashtable]$Default = @{ Code = 404; Body = 'not found'; Type = 'text/plain' })
        $Mock.State.Mode = $Mode
        $Mock.State.Version = $Version
        $Mock.State.Guard = $Guard
        $Mock.State.Acao = $Acao
        $Mock.State.Tags = $Tags
        $Mock.State.V1 = $V1
        $Mock.State.Routes = $Routes
        $Mock.State.Default = $Default
        $Mock.State.Log.Clear()
    }

    # Request lines of the two header variants, as the listener logged them.
    function Get-AiVariantLog {
        param($Mock)
        return @($Mock.State.Log.ToArray() | Where-Object { $_ -match 'origin=http' -or $_ -match 'host=tcpk-probe' })
    }

    function Invoke-AiConfirm {
        param([string]$Endpoint = "127.0.0.1:$($script:main.Port)", [int]$TimeoutMs = 3000)
        # Unary comma: the caller always gets an array, also for zero or one finding.
        return ,@(Confirm-TcpkAiInferenceServer -Endpoint $Endpoint -TimeoutMs $TimeoutMs -WarningAction SilentlyContinue)
    }

    function Select-AiRule {
        param($Findings, [string]$RuleId)
        return ,@($Findings | Where-Object { $null -ne $_ -and $_.RuleId -eq $RuleId })
    }

    # Request lines the listener saw since the last Set-AiMock. A bare TCP connect is not
    # logged. Callers wrap the call in @() because the result is piped.
    function Get-AiLog { param($Mock) return @($Mock.State.Log.ToArray()) }

    $script:main  = Start-AiMock
    $script:other = Start-AiMock
    if ($script:main -and $script:other) {
        $script:main.State.OtherPort = $script:other.Port
        $script:main.State.BigBody = '{"models":[{"name":"' + ('a' * 1200000) + '"}]}'
        $script:ep = "127.0.0.1:$($script:main.Port)"
    }
}

AfterAll {
    Stop-AiMock -Mock $script:main
    Stop-AiMock -Mock $script:other
    try { Disable-TcpkExploit | Out-Null } catch { }
    if ($script:root -and (Test-Path -LiteralPath $script:root)) { Remove-Item -LiteralPath $script:root -Recurse -Force -ErrorAction SilentlyContinue }
}

# The listeners are a hard requirement. A failure to bind is a failing test, not a skip.
Describe 'test listeners' {
    It 'both loopback listeners came up' {
        $script:main  | Should -Not -BeNullOrEmpty
        $script:other | Should -Not -BeNullOrEmpty
        $script:main.Port | Should -Not -Be $script:other.Port
    }
}

Describe 'Confirm-TcpkAiInferenceServer: endpoint parsing' {

    It 'accepts <Text> as <H> port <P>' -ForEach @(
        @{ Text = '127.0.0.1:11434';                         H = '127.0.0.1'; P = 11434 }
        @{ Text = '[::1]:11434';                             H = '::1';       P = 11434 }
        @{ Text = '11434';                                   H = '127.0.0.1'; P = 11434 }
        @{ Text = 'localhost:1234';                          H = 'localhost'; P = 1234 }
        @{ Text = ' 127.0.0.1:1 ';                           H = '127.0.0.1'; P = 1 }
        @{ Text = 'http://127.0.0.1:11434';                  H = '127.0.0.1'; P = 11434 }
        @{ Text = 'http://127.0.0.1:11434/api/tags?x=1#f';   H = '127.0.0.1'; P = 11434 }
        @{ Text = 'HTTP://LocalHost:8080/';                  H = 'LocalHost'; P = 8080 }
        @{ Text = 'http://[::1]:11434/v1';                   H = '::1';       P = 11434 }
        @{ Text = '127.0.0.1:65535';                         H = '127.0.0.1'; P = 65535 }
    ) {
        $r = & (Get-Module TCPK) { param($t) ConvertTo-TcpkAiEndpoint -Text $t } $Text
        $r.Ok   | Should -BeTrue
        $r.Host | Should -Be $H
        $r.Port | Should -Be $P
    }

    It 'rejects <Text> with a reason' -ForEach @(
        @{ Text = 'host' }
        @{ Text = '127.0.0.1' }
        @{ Text = '127.0.0.1:0' }
        @{ Text = '127.0.0.1:65536' }
        @{ Text = '127.0.0.1:99999' }
        @{ Text = '127.0.0.1:123456789012' }
        @{ Text = '127.0.0.1:abc' }
        @{ Text = 'user@127.0.0.1:11434' }
        @{ Text = 'http://user:pw@127.0.0.1:11434/' }
        @{ Text = '::1' }
        @{ Text = '::1:11434' }
        @{ Text = '[::1]' }
        @{ Text = '[zz]:80' }
        @{ Text = 'http://127.0.0.1/' }
        @{ Text = 'bad host:80' }
        @{ Text = "evil'quote:80" }
        @{ Text = '   ' }
    ) {
        $r = & (Get-Module TCPK) { param($t) ConvertTo-TcpkAiEndpoint -Text $t } $Text
        $r.Ok     | Should -BeFalse
        $r.Reason | Should -Not -BeNullOrEmpty
    }

    It 'notes that a non-http scheme was ignored' {
        $r = & (Get-Module TCPK) { ConvertTo-TcpkAiEndpoint -Text 'https://127.0.0.1:8443/x' }
        $r.Ok   | Should -BeTrue
        $r.Note | Should -Match 'https'
    }

    It 'brackets an IPv6 literal in the URL authority and leaves IPv4 alone' {
        $six  = & (Get-Module TCPK) { Get-TcpkAiHostPort -Address ([System.Net.IPAddress]::IPv6Loopback) -Port 11434 }
        $four = & (Get-Module TCPK) { Get-TcpkAiHostPort -Address ([System.Net.IPAddress]::Loopback) -Port 11434 }
        $six  | Should -Be '[::1]:11434'
        $four | Should -Be '127.0.0.1:11434'
        $u = $null
        [Uri]::TryCreate("http://$six/api/tags", [UriKind]::Absolute, [ref]$u) | Should -BeTrue
    }

    It 'maps an IPv4-mapped IPv6 literal back to IPv4 and treats it as loopback' {
        $r = & (Get-Module TCPK) { Resolve-TcpkAiAddress -HostName '::ffff:127.0.0.1' }
        $r.Ok | Should -BeTrue
        @($r.Addresses)[0].ToString() | Should -Be '127.0.0.1'
        [System.Net.IPAddress]::IsLoopback(@($r.Addresses)[0]) | Should -BeTrue
    }

    It 'warns instead of returning nothing for an endpoint it cannot use' {
        $w = $null
        $r = @(Confirm-TcpkAiInferenceServer -Endpoint '127.0.0.1:99999' -WarningVariable w -WarningAction SilentlyContinue)
        $r.Count | Should -Be 0
        @($w).Count | Should -BeGreaterThan 0
        "$($w[0])" | Should -Match '65535'
    }

    It 'warns for user-info and for an unbracketed IPv6 literal' {
        $w = $null
        $r = @(Confirm-TcpkAiInferenceServer -Endpoint "user@$($script:ep)", '::1' -WarningVariable w -WarningAction SilentlyContinue)
        $r.Count | Should -Be 0
        @($w).Count | Should -Be 2
    }

    It 'warns when -Endpoint is supplied empty and does not fall back to a sweep' {
        Mock -ModuleName TCPK Get-TcpkAiDefaultEndpoint { return @('127.0.0.1:1') }
        $w = $null
        $r = @(Confirm-TcpkAiInferenceServer -Endpoint @('', '  ') -WarningVariable w -WarningAction SilentlyContinue)
        $r.Count | Should -Be 0
        @($w).Count | Should -BeGreaterThan 0
        Should -Invoke -ModuleName TCPK Get-TcpkAiDefaultEndpoint -Times 0 -Exactly
    }

    It 'validates -TimeoutMs' {
        { Confirm-TcpkAiInferenceServer -Endpoint $script:ep -TimeoutMs -5 } | Should -Throw
        { Confirm-TcpkAiInferenceServer -Endpoint $script:ep -TimeoutMs 0 }  | Should -Throw
    }
}

Describe 'aiserver.unauth-reachable' {

    It 'reports the model API of a proven Ollama, MEDIUM on loopback, Confirmed (dynamic)' {
        Set-AiMock -Mock $script:main -Mode 'ollama' -Guard 'strict'
        $f = Select-AiRule (Invoke-AiConfirm) 'aiserver.unauth-reachable'
        $f.Count | Should -Be 1
        $f[0].Severity   | Should -Be 'MEDIUM'
        $f[0].Confidence | Should -Be 'Confirmed (dynamic)'
        $f[0].Module     | Should -Be 'network'
        $f[0].File       | Should -Be $script:ep
        $f[0].Title      | Should -Be "Ollama model API on $($script:ep) answers without authentication"
        $f[0].Evidence   | Should -Match 'GET /api/tags -> 200, JSON model list \(1 entry: llama3:latest\)'
        $f[0].Evidence   | Should -Match 'connected address 127\.0\.0\.1 \(loopback\)'
        $f[0].Cwe        | Should -Contain 'CWE-306'
    }

    It 'rates a model list from a product that was not identified LOW, and says so in the Title' {
        Set-AiMock -Mock $script:main -Mode 'tags-only'
        $f = Select-AiRule (Invoke-AiConfirm) 'aiserver.unauth-reachable'
        $f.Count | Should -Be 1
        $f[0].Severity    | Should -Be 'LOW'
        $f[0].Confidence  | Should -Be 'Confirmed (dynamic)'
        $f[0].Title       | Should -Be "Model list on $($script:ep) is readable without a credential (product not identified)"
        $f[0].Evidence    | Should -Match 'GET /api/tags -> 200, JSON model list \(1 entry: llama3:latest\)'
        $f[0].Description | Should -Match 'whether those routes need a credential is not known'
        # No probed route answered 403 here, so nothing is said about one.
        $f[0].Description | Should -Not -Match 'answered with 403'
        $f[0].Fix         | Should -Match 'whether the inference routes of this server ask for a credential'
        $f[0].Cwe         | Should -Contain 'CWE-200'
        $f[0].Cwe         | Should -Not -Contain 'CWE-306'
        $c = & (Get-Module TCPK) { param($x) Get-TcpkCvssVector -Finding $x } $f[0]
        $c.Rating | Should -Be 'Low'
    }

    It 'does not also report the port as unidentified, or as asking for a credential, once a model list came back' {
        Set-AiMock -Mock $script:main -Mode 'tags-only'
        $all = Invoke-AiConfirm
        (Select-AiRule $all 'aiserver.port-open-unidentified').Count | Should -Be 0
        (Select-AiRule $all 'aiserver.reachable-authed').Count | Should -Be 0
    }

    It 'reports a JSON model list on /v1/models' {
        Set-AiMock -Mock $script:main -Mode 'openai'
        $f = Select-AiRule (Invoke-AiConfirm) 'aiserver.unauth-reachable'
        $f.Count | Should -Be 1
        $f[0].Severity | Should -Be 'LOW'
        $f[0].Evidence | Should -Match 'GET /v1/models -> 200, JSON model list'
        $f[0].Evidence | Should -Match 'GET /api/tags -> 404'
        # Every request that was sent is on record, the two extra routes included.
        $f[0].Evidence | Should -Match 'GET / -> 404'
        $f[0].Evidence | Should -Match 'GET /api/version -> 200, body not used \(the server is not identified as Ollama\)'
    }

    It 'does not name a product that was not identified' {
        Set-AiMock -Mock $script:main -Mode 'openai'
        $all = Invoke-AiConfirm
        foreach ($x in $all) { $x.Title | Should -Not -Match '(?i)ollama|lm studio|jan|gpt4all|anythingllm' }
    }

    It 'names Ollama only when the banner and the models array both came from the endpoint' {
        Set-AiMock -Mock $script:main -Mode 'ollama'
        $f = Select-AiRule (Invoke-AiConfirm) 'aiserver.unauth-reachable'
        $f[0].Title    | Should -Match '^Ollama model API'
        $f[0].Evidence | Should -Match 'GET / -> 200, Ollama banner'
        $f[0].Evidence | Should -Match 'version 0\.30\.4'
    }

    It 'treats <Mode> as port open, not identified' -ForEach @(
        @{ Mode = 'html';       Ev = 'markup body, not JSON' }
        @{ Mode = 'empty200';   Ev = 'empty body' }
        @{ Mode = '204';        Ev = '-> 204' }
        @{ Mode = 'json-other'; Ev = "JSON object without a 'models' array" }
    ) {
        Set-AiMock -Mock $script:main -Mode $Mode
        $all = Invoke-AiConfirm
        (Select-AiRule $all 'aiserver.unauth-reachable').Count | Should -Be 0
        $u = Select-AiRule $all 'aiserver.port-open-unidentified'
        $u.Count | Should -Be 1
        $u[0].Severity | Should -Be 'INFO'
        $u[0].Evidence | Should -Match ([regex]::Escape($Ev))
        $all.Count | Should -Be 1
    }

    It 'does not accept a models array whose entries are not model records' {
        Set-AiMock -Mock $script:main -Mode 'tags-only' -Tags '{"models":[1,2,3]}'
        $all = Invoke-AiConfirm
        (Select-AiRule $all 'aiserver.unauth-reachable').Count | Should -Be 0
        (Select-AiRule $all 'aiserver.port-open-unidentified').Count | Should -Be 1
    }

    It 'does not accept an empty array with nothing else identifying the server' {
        Set-AiMock -Mock $script:main -Mode 'tags-only' -Tags '{"models":[]}'
        (Select-AiRule (Invoke-AiConfirm) 'aiserver.unauth-reachable').Count | Should -Be 0
        Set-AiMock -Mock $script:main -Mode 'openai' -V1 '{"data":[]}'
        (Select-AiRule (Invoke-AiConfirm) 'aiserver.unauth-reachable').Count | Should -Be 0
    }

    It 'does not call an empty <Key> array a model list in Evidence when it was not counted as one' -ForEach @(
        @{ Key = 'data';   Mode = 'openai';    Body = '{"data":[]}' }
        @{ Key = 'models'; Mode = 'tags-only'; Body = '{"models":[]}' }
    ) {
        if ($Key -eq 'data') { Set-AiMock -Mock $script:main -Mode $Mode -V1 $Body }
        else                 { Set-AiMock -Mock $script:main -Mode $Mode -Tags $Body }
        $all = Invoke-AiConfirm
        $all.Count | Should -Be 1
        $all[0].RuleId      | Should -Be 'aiserver.port-open-unidentified'
        $all[0].Evidence    | Should -Match "-> 200, JSON object with an empty '$Key' array, not counted as a model list"
        $all[0].Evidence    | Should -Not -Match 'JSON model list'
        $all[0].Description | Should -Match 'neither /api/tags nor /v1/models returned a JSON model list'
    }

    It 'accepts an empty array when the server identifies itself' {
        Set-AiMock -Mock $script:main -Mode 'ollama' -Tags '{"models":[]}' -V1 '{"object":"list","data":[]}'
        $f = Select-AiRule (Invoke-AiConfirm) 'aiserver.unauth-reachable'
        $f.Count | Should -Be 1
        $f[0].Evidence | Should -Match 'JSON model list with 0 entries'
    }

    It 'states only the observed effect in the Description' {
        Set-AiMock -Mock $script:main -Mode 'ollama' -Guard 'strict'
        $f = Select-AiRule (Invoke-AiConfirm) 'aiserver.unauth-reachable'
        $f[0].Description | Should -Not -Match '(?i)any website|csrf|rebinding|any local user'
        $f[0].Description | Should -Match 'no credential'
    }

    It 'does not report the same listener twice when it is named two ways' {
        Set-AiMock -Mock $script:main -Mode 'openai'
        $all = @(Confirm-TcpkAiInferenceServer -Endpoint $script:ep, "http://127.0.0.1:$($script:main.Port)/", "127.1:$($script:main.Port)" -TimeoutMs 3000 -WarningAction SilentlyContinue)
        (Select-AiRule $all 'aiserver.unauth-reachable').Count | Should -Be 1
        # One pass only: the four routes and the two header variants, not three times that.
        @(Get-AiLog $script:main).Count | Should -Be 6
    }
}

Describe 'aiserver.origin-unchecked' {

    It 'is HIGH when a foreign Host header is accepted' {
        Set-AiMock -Mock $script:main -Mode 'ollama' -Guard 'none'
        $f = Select-AiRule (Invoke-AiConfirm) 'aiserver.origin-unchecked'
        $f.Count | Should -Be 1
        $f[0].Severity   | Should -Be 'HIGH'
        $f[0].Confidence | Should -Be 'Confirmed (dynamic)'
        $f[0].Title      | Should -Match 'foreign Host header'
        $f[0].Evidence   | Should -Match 'with Host: tcpk-probe\.invalid:\d+ -> 200'
        $f[0].Cwe        | Should -Contain 'CWE-346'
    }

    It 'is not emitted when only a foreign Origin is accepted and no permissive header comes back' {
        # A foreign Host is refused and no Access-Control-Allow-Origin is returned: a page on
        # another site can neither reach the listener by rebinding nor read the answer.
        Set-AiMock -Mock $script:main -Mode 'ollama' -Guard 'host'
        $all = Invoke-AiConfirm
        (Select-AiRule $all 'aiserver.origin-unchecked').Count | Should -Be 0
        $u = Select-AiRule $all 'aiserver.unauth-reachable'
        $u.Count | Should -Be 1
        # What was seen is still on record, in the finding that was emitted.
        $u[0].Evidence    | Should -Match 'with Origin: http://tcpk-probe\.invalid -> 200.*no Access-Control-Allow-Origin'
        $u[0].Evidence    | Should -Match 'with Host: tcpk-probe\.invalid:\d+ -> 403'
        $u[0].Description | Should -Match 'foreign Origin header returned the list as well, with no permissive Access-Control-Allow-Origin'
        $u[0].Description | Should -Not -Match 'aiserver\.origin-unchecked'
    }

    It 'is HIGH when a foreign Origin is accepted with Access-Control-Allow-Origin: <Acao>' -ForEach @(
        @{ Acao = '*';    Shown = 'Access-Control-Allow-Origin: \*' }
        @{ Acao = 'echo'; Shown = 'Access-Control-Allow-Origin: http://tcpk-probe\.invalid' }
    ) {
        Set-AiMock -Mock $script:main -Mode 'ollama' -Guard 'host' -Acao $Acao
        $f = Select-AiRule (Invoke-AiConfirm) 'aiserver.origin-unchecked'
        $f.Count | Should -Be 1
        $f[0].Severity | Should -Be 'HIGH'
        $f[0].Evidence | Should -Match $Shown
        $f[0].Cwe      | Should -Contain 'CWE-942'
    }

    It 'is not emitted when the Access-Control-Allow-Origin that comes back names some other origin' {
        Set-AiMock -Mock $script:main -Mode 'ollama' -Guard 'host' -Acao 'fixed'
        $all = Invoke-AiConfirm
        (Select-AiRule $all 'aiserver.origin-unchecked').Count | Should -Be 0
        $u = Select-AiRule $all 'aiserver.unauth-reachable'
        $u[0].Evidence | Should -Match 'Access-Control-Allow-Origin: http://localhost:3000'
    }

    It 'is not emitted when Access-Control-Allow-Origin arrives with more than one value' {
        # A proxy and the application each add the header, so it arrives as two values. A
        # browser refuses such a response: it does not let a page on another site read the
        # list, so one of the values being '*' must not be read as permissive.
        Set-AiMock -Mock $script:main -Mode 'ollama' -Guard 'host' -Acao 'double'
        $all = Invoke-AiConfirm
        (Select-AiRule $all 'aiserver.origin-unchecked').Count | Should -Be 0
        $u = Select-AiRule $all 'aiserver.unauth-reachable'
        $u.Count | Should -Be 1
    }

    It 'builds its Fix from the variants that were accepted' {
        # Host refused, Origin answered with a wildcard: only the Origin advice applies.
        Set-AiMock -Mock $script:main -Mode 'ollama' -Guard 'host' -Acao '*'
        $f = Select-AiRule (Invoke-AiConfirm) 'aiserver.origin-unchecked'
        $f[0].Fix   | Should -Match 'allowed origins'
        $f[0].Fix   | Should -Not -Match 'Host header'
        $f[0].Title | Should -Not -Match 'Host header'
        # Host accepted, no Access-Control-Allow-Origin: only the Host advice applies.
        Set-AiMock -Mock $script:main -Mode 'ollama' -Guard 'none'
        $g = Select-AiRule (Invoke-AiConfirm) 'aiserver.origin-unchecked'
        $g[0].Fix   | Should -Match 'Host header'
        $g[0].Fix   | Should -Not -Match 'allowed origins|Access-Control-Allow-Origin'
        $g[0].Title | Should -Be "Ollama model API on $($script:ep) accepts a foreign Host header"
        $g[0].Cwe   | Should -Not -Contain 'CWE-942'
    }

    It 'is rated no higher than the model-list finding on a product that was not identified' {
        Set-AiMock -Mock $script:main -Mode 'openai' -Acao 'echo'
        $all = Invoke-AiConfirm
        $u = Select-AiRule $all 'aiserver.unauth-reachable'
        $f = Select-AiRule $all 'aiserver.origin-unchecked'
        $u.Count | Should -Be 1
        $f.Count | Should -Be 1
        $u[0].Severity    | Should -Be 'LOW'
        $f[0].Severity    | Should -Be 'LOW'
        $f[0].Title       | Should -Match '^Model-list route on '
        $f[0].Title       | Should -Not -Match '(?i)ollama'
        $f[0].Description | Should -Match 'rated no higher than the model-list finding'
    }

    It 'is not emitted when the server rejects both the foreign Origin and the foreign Host' {
        Set-AiMock -Mock $script:main -Mode 'ollama' -Guard 'strict'
        $all = Invoke-AiConfirm
        (Select-AiRule $all 'aiserver.origin-unchecked').Count | Should -Be 0
        # The rejection is still on record in the finding that was emitted.
        $u = Select-AiRule $all 'aiserver.unauth-reachable'
        $u.Count | Should -Be 1
        $u[0].Evidence | Should -Match 'with Origin: http://tcpk-probe\.invalid -> 403'
        $u[0].Evidence | Should -Match 'with Host: tcpk-probe\.invalid:\d+ -> 403'
    }

    It 'sends the two header variants only after a model list was confirmed' {
        Set-AiMock -Mock $script:main -Mode 'html'
        $null = Invoke-AiConfirm
        $log = Get-AiLog $script:main
        @($log | Where-Object { $_ -match 'origin=http' }).Count | Should -Be 0
        @($log | Where-Object { $_ -match 'host=tcpk-probe' }).Count | Should -Be 0
    }
}

Describe 'aiserver.ollama-probllama-version' {

    It 'fires for a proven Ollama whose live version is below 0.1.34' {
        Set-AiMock -Mock $script:main -Mode 'ollama' -Version '0.1.33' -Guard 'strict'
        $f = Select-AiRule (Invoke-AiConfirm) 'aiserver.ollama-probllama-version'
        $f.Count | Should -Be 1
        $f[0].Severity   | Should -Be 'HIGH'
        $f[0].Confidence | Should -Be 'Confirmed (dynamic)'
        $f[0].Title      | Should -Match 'Ollama 0\.1\.33 .*CVE-2024-37032'
        $f[0].Evidence   | Should -Match 'identity: GET / -> 200, Ollama banner'
        $f[0].Evidence   | Should -Match 'the affected route was not requested'
        $f[0].Cwe        | Should -Contain 'CWE-22'
    }

    It 'stays silent for version <Version>' -ForEach @(
        @{ Version = '0.1.34' }
        @{ Version = '0.30.4' }
        @{ Version = '1.0.0' }
        @{ Version = '0.0.0' }
        @{ Version = '99999999999.0.0' }
        @{ Version = '0.1.9 <img src=x onerror=alert(1)>' }
        @{ Version = '0.1' }
        @{ Version = '0.1.33-rc5' }
        @{ Version = 'v0.1.20' }
    ) {
        Set-AiMock -Mock $script:main -Mode 'ollama' -Version $Version
        $all = @()
        { $script:lastAll = Invoke-AiConfirm } | Should -Not -Throw
        $all = $script:lastAll
        (Select-AiRule $all 'aiserver.ollama-probllama-version').Count | Should -Be 0
        (Select-AiRule $all 'aiserver.unauth-reachable').Count | Should -Be 1
        foreach ($x in $all) {
            $x.Title    | Should -Not -Match '<|CVE-'
            $x.Evidence | Should -Not -Match '<img|alert\('
        }
    }

    It 'says in Evidence why 0.0.0 was not compared' {
        Set-AiMock -Mock $script:main -Mode 'ollama' -Version '0.0.0'
        $f = Select-AiRule (Invoke-AiConfirm) 'aiserver.unauth-reachable'
        $f[0].Evidence | Should -Match 'version 0\.0\.0 \(unstamped build, not comparable\)'
    }

    It 'does not fire for an app that has a models array and its own /api/version but no Ollama banner' {
        Set-AiMock -Mock $script:main -Mode 'tags-only' -Version '0.1.20'
        $all = Invoke-AiConfirm
        (Select-AiRule $all 'aiserver.ollama-probllama-version').Count | Should -Be 0
        foreach ($x in $all) {
            $x.Title | Should -Not -Match '(?i)ollama|CVE-'
            # Identity failed, so the version this app reports is never read or printed.
            "$($x.Evidence) $($x.Description)" | Should -Not -Match '0\.1\.20'
        }
        (Select-AiRule $all 'aiserver.unauth-reachable')[0].Evidence | Should -Match 'GET /api/version -> 200, body not used'
    }

    It 'does not fire for a /v1/models server that has its own /api/version' {
        Set-AiMock -Mock $script:main -Mode 'openai' -Version '0.1.20'
        $all = Invoke-AiConfirm
        (Select-AiRule $all 'aiserver.ollama-probllama-version').Count | Should -Be 0
        foreach ($x in $all) { $x.Title | Should -Not -Match '(?i)ollama|CVE-' }
    }

    It 'does not fire for a web app that serves HTML everywhere and has its own /api/version' {
        Set-AiMock -Mock $script:main -Mode 'fakever-html' -Version '0.1.20'
        $all = Invoke-AiConfirm
        $all.Count | Should -Be 1
        $all[0].RuleId | Should -Be 'aiserver.port-open-unidentified'
    }

    It 'defers its CVSS to the advisory instead of carrying an anchored vector' {
        Set-AiMock -Mock $script:main -Mode 'ollama' -Version '0.1.33' -Guard 'strict'
        $f = Select-AiRule (Invoke-AiConfirm) 'aiserver.ollama-probllama-version'
        $c = & (Get-Module TCPK) { param($x) Get-TcpkCvssVector -Finding $x } $f[0]
        $c.Source | Should -Be 'nvd'
        $c.Vector | Should -BeNullOrEmpty
    }

    It 'gives the loopback unauth finding a local vector, not a network one' {
        Set-AiMock -Mock $script:main -Mode 'ollama' -Guard 'strict'
        $f = Select-AiRule (Invoke-AiConfirm) 'aiserver.unauth-reachable'
        $c = & (Get-Module TCPK) { param($x) Get-TcpkCvssVector -Finding $x } $f[0]
        $c.Vector | Should -Match '/AV:L/'
        $c.Rating | Should -Be 'Medium'
    }
}

Describe 'aiserver.reachable-authed' {

    It 'reports a 401 as reachable, requires auth (INFO)' {
        Set-AiMock -Mock $script:main -Mode '401'
        $all = Invoke-AiConfirm
        $all.Count | Should -Be 1
        $all[0].RuleId   | Should -Be 'aiserver.reachable-authed'
        $all[0].Severity | Should -Be 'INFO'
        $all[0].Evidence | Should -Match '-> 401 with WWW-Authenticate'
    }

    It 'reports a 403 that carries WWW-Authenticate the same way' {
        Set-AiMock -Mock $script:main -Mode '403-www'
        $all = Invoke-AiConfirm
        $all.Count | Should -Be 1
        $all[0].RuleId | Should -Be 'aiserver.reachable-authed'
    }

    It 'reports a bare 403 as forbidden, cause not established, with no posture wording' {
        Set-AiMock -Mock $script:main -Mode '403'
        $all = Invoke-AiConfirm
        $all.Count | Should -Be 1
        $all[0].RuleId   | Should -Be 'aiserver.port-open-unidentified'
        $all[0].Severity | Should -Be 'INFO'
        $all[0].Title    | Should -Match 'cause not established'
        "$($all[0].Title) $($all[0].Description) $($all[0].Evidence)" | Should -Not -Match '(?i)good posture|requires auth|credential required|enforces authentication'
    }

    It 'does not call a listener that asks for a credential an inference server' {
        Set-AiMock -Mock $script:main -Mode '401'
        $all = Invoke-AiConfirm
        $all[0].Title | Should -Not -Match '(?i)inference server|ollama'
    }
}

Describe 'a readable model list beside a route that asks for a credential' {

    It 'is not an unauthenticated API when /api/tags answers 401 and /v1/models returns the list' {
        # A server started with an API key that keeps its model list public: every other
        # route answers 401, and the request Origin is reflected on every answer.
        Set-AiMock -Mock $script:main -Mode 'routes' -Acao 'echo' -Routes @{
            '/'          = (New-AiRoute -Body '<!doctype html><html><body>ui</body></html>' -Type 'text/html')
            '/v1/models' = (New-AiRoute -Body $script:DefaultV1)
        } -Default (New-AiRoute -Code 401 -Body $script:KeyError)
        $all = Invoke-AiConfirm
        $all.Count | Should -Be 1
        $all[0].RuleId      | Should -Be 'aiserver.reachable-authed'
        $all[0].Severity    | Should -Be 'INFO'
        $all[0].Title       | Should -Be "Listener on $($script:ep) asks for a credential on /api/tags and /api/version; its model list on /v1/models is readable without one"
        $all[0].Evidence    | Should -Match 'GET /api/tags -> 401 without WWW-Authenticate'
        $all[0].Evidence    | Should -Match 'GET /v1/models -> 200, JSON model list \(1 entry: llama3:latest\)'
        $all[0].Evidence    | Should -Match 'header variants: not sent'
        $all[0].Description | Should -Match 'not reported as an API without authentication'
        $all[0].Cwe.Count   | Should -Be 0
        # No header variant went out, and nothing beyond the four paths.
        @(Get-AiVariantLog $script:main).Count | Should -Be 0
        @(Get-AiLog $script:main).Count | Should -Be 4
    }

    It 'sees the key check on /api/version when both model routes are public' {
        Set-AiMock -Mock $script:main -Mode 'routes' -Acao 'echo' -Routes @{
            '/'          = (New-AiRoute -Body '<!doctype html><html><body>ui</body></html>' -Type 'text/html')
            '/api/tags'  = (New-AiRoute -Body $script:DefaultTags)
            '/v1/models' = (New-AiRoute -Body $script:DefaultV1)
        } -Default (New-AiRoute -Code 401 -Body $script:KeyError)
        $all = Invoke-AiConfirm
        $all.Count | Should -Be 1
        $all[0].RuleId   | Should -Be 'aiserver.reachable-authed'
        $all[0].Severity | Should -Be 'INFO'
        $all[0].Title    | Should -Match 'asks for a credential on /api/version; its model list on /api/tags is readable without one'
        $all[0].Evidence | Should -Match 'GET /api/version -> 401 without WWW-Authenticate'
        @(Get-AiVariantLog $script:main).Count | Should -Be 0
    }

    It 'treats a 403 that carries WWW-Authenticate on the other model route the same way' {
        Set-AiMock -Mock $script:main -Mode 'routes' -Routes @{
            '/api/tags'  = (New-AiRoute -Code 403 -Body '' -Extra @{ 'WWW-Authenticate' = 'Basic realm="x"' })
            '/v1/models' = (New-AiRoute -Body $script:DefaultV1)
        }
        $all = Invoke-AiConfirm
        $all.Count | Should -Be 1
        $all[0].RuleId      | Should -Be 'aiserver.reachable-authed'
        $all[0].Title       | Should -Match 'asks for a credential on /api/tags; its model list on /v1/models is readable without one'
        $all[0].Description | Should -Match 'answered with 403 together with a WWW-Authenticate header'
    }

    It 'does not read a 403 without WWW-Authenticate on the other model route as a credential check' {
        Set-AiMock -Mock $script:main -Mode 'routes' -Routes @{
            '/api/tags'  = (New-AiRoute -Code 403 -Body '')
            '/v1/models' = (New-AiRoute -Body $script:DefaultV1)
        }
        $all = Invoke-AiConfirm
        (Select-AiRule $all 'aiserver.reachable-authed').Count | Should -Be 0
        $u = Select-AiRule $all 'aiserver.unauth-reachable'
        $u.Count | Should -Be 1
        $u[0].Severity | Should -Be 'LOW'
        $u[0].Evidence | Should -Match 'GET /api/tags -> 403 without WWW-Authenticate'
        # The Description does not pass over that answer: it names the route and says the
        # cause is not known, so "no probed route asked for a credential" is not read as more.
        $u[0].Description | Should -Match 'GET /api/tags was answered with 403 and no WWW-Authenticate header'
        $u[0].Description | Should -Match 'counted neither as a credential check nor as the lack of one'
    }

    It 'names every probed route that answered 403 without WWW-Authenticate beside a readable list' {
        Set-AiMock -Mock $script:main -Mode 'routes' -Routes @{
            '/v1/models' = (New-AiRoute -Body $script:DefaultV1)
        } -Default (New-AiRoute -Code 403 -Body '')
        $all = Invoke-AiConfirm
        (Select-AiRule $all 'aiserver.reachable-authed').Count | Should -Be 0
        $u = Select-AiRule $all 'aiserver.unauth-reachable'
        $u.Count | Should -Be 1
        $u[0].Severity    | Should -Be 'LOW'
        $u[0].Description | Should -Match 'GET /api/tags, GET / and GET /api/version were answered with 403 and no WWW-Authenticate header'
    }

    It 'names every route that asked for a credential, and both kinds of answer' {
        Set-AiMock -Mock $script:main -Mode 'routes' -Routes @{
            '/v1/models'   = (New-AiRoute -Body $script:DefaultV1)
            '/api/version' = (New-AiRoute -Code 403 -Body '' -Extra @{ 'WWW-Authenticate' = 'Bearer' })
        } -Default (New-AiRoute -Code 401 -Body $script:KeyError)
        $all = Invoke-AiConfirm
        $all.Count | Should -Be 1
        $all[0].RuleId      | Should -Be 'aiserver.reachable-authed'
        $all[0].Title       | Should -Be "Listener on $($script:ep) asks for a credential on /api/tags, / and /api/version; its model list on /v1/models is readable without one"
        $all[0].Description | Should -Match 'GET /api/tags, GET / and GET /api/version, sent the same way to the same listener, were answered with 401, or with 403 together with a WWW-Authenticate header'
    }

    It 'joins route names as running text' {
        $r = & (Get-Module TCPK) {
            @(
                (Join-TcpkAiWord -Items @())
                (Join-TcpkAiWord -Items @('a'))
                (Join-TcpkAiWord -Items @('a', 'b'))
                (Join-TcpkAiWord -Items @('a', 'b', 'c'))
            )
        }
        (@($r) -join '|') | Should -Be '|a|a and b|a, b and c'
    }

    It 'still reports a proven Ollama version below 0.1.34 when another route asks for a credential' {
        Set-AiMock -Mock $script:main -Mode 'routes' -Routes @{
            '/'            = (New-AiRoute -Body 'Ollama is running' -Type 'text/plain')
            '/api/tags'    = (New-AiRoute -Body $script:DefaultTags)
            '/api/version' = (New-AiRoute -Body '{"version":"0.1.33"}')
            '/v1/models'   = (New-AiRoute -Code 401 -Body '{"error":"unauthorized"}' -Extra @{ 'WWW-Authenticate' = 'Bearer' })
        }
        $all = Invoke-AiConfirm
        $all.Count | Should -Be 2
        (Select-AiRule $all 'aiserver.unauth-reachable').Count | Should -Be 0
        (Select-AiRule $all 'aiserver.origin-unchecked').Count | Should -Be 0
        $a = Select-AiRule $all 'aiserver.reachable-authed'
        $a.Count | Should -Be 1
        $a[0].Title | Should -Match 'asks for a credential on /v1/models; its model list on /api/tags is readable without one'
        (Select-AiRule $all 'aiserver.ollama-probllama-version').Count | Should -Be 1
    }
}

Describe 'aiserver.port-open-unidentified and redirects' {

    It 'treats a 302 to a login page as its own outcome and never requests the login page' {
        Set-AiMock -Mock $script:main -Mode 'login302'
        $all = Invoke-AiConfirm
        $all.Count | Should -Be 1
        $all[0].RuleId   | Should -Be 'aiserver.port-open-unidentified'
        $all[0].Title    | Should -Match 'redirect, not followed'
        $all[0].Evidence | Should -Match '-> 302 redirect to /login \(not followed\)'
        @(Get-AiLog $script:main | Where-Object { $_ -match '^GET /login' }).Count | Should -Be 0
    }

    It 'never prints the query string of a redirect target' {
        Set-AiMock -Mock $script:main -Mode 'login302'
        $all = Invoke-AiConfirm
        "$($all[0].Evidence) $($all[0].Title) $($all[0].Description)" | Should -Not -Match 'SECRETTOKEN123'
    }

    It 'does not follow a 302 to another origin: that origin receives no request' {
        Set-AiMock -Mock $script:other -Mode 'ollama' -Version '0.1.20'
        Set-AiMock -Mock $script:main -Mode 'redirect-out'
        $all = Invoke-AiConfirm
        $all.Count | Should -Be 1
        $all[0].RuleId   | Should -Be 'aiserver.port-open-unidentified'
        $all[0].Evidence | Should -Match '-> 302 redirect to http://127\.0\.0\.1:\d+/api/tags \(not followed\)'
        $all[0].Evidence | Should -Not -Match 'llama3|0\.1\.20'
        @(Get-AiLog $script:other).Count | Should -Be 0
        @(Get-AiLog $script:main).Count  | Should -Be 2
    }

    It 'returns nothing, and does not throw, for a closed port' {
        $l = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
        $l.Start()
        $closed = ([System.Net.IPEndPoint]$l.LocalEndpoint).Port
        $l.Stop()
        { $script:lastAll = Invoke-AiConfirm -Endpoint "127.0.0.1:$closed" } | Should -Not -Throw
        @($script:lastAll).Count | Should -Be 0
    }

    It 'returns nothing, and does not throw, for a closed IPv6 loopback port' {
        $l = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
        $l.Start()
        $closed = ([System.Net.IPEndPoint]$l.LocalEndpoint).Port
        $l.Stop()
        { $script:lastAll = Invoke-AiConfirm -Endpoint "[::1]:$closed" } | Should -Not -Throw
        @($script:lastAll).Count | Should -Be 0
    }
}

Describe 'Confirm-TcpkAiInferenceServer: addressing' {

    It 'accepts a URL-form endpoint and strips the scheme and path' {
        Set-AiMock -Mock $script:main -Mode 'openai'
        $all = Invoke-AiConfirm -Endpoint "http://127.0.0.1:$($script:main.Port)/api/tags?x=1"
        (Select-AiRule $all 'aiserver.unauth-reachable').Count | Should -Be 1
        @(Get-AiLog $script:main | Where-Object { $_ -match '\?x=1' }).Count | Should -Be 0
    }

    It 'accepts a bare port as loopback' {
        Set-AiMock -Mock $script:main -Mode 'openai'
        $all = Invoke-AiConfirm -Endpoint "$($script:main.Port)"
        (Select-AiRule $all 'aiserver.unauth-reachable').Count | Should -Be 1
    }

    It 'rates <Form> as loopback (MEDIUM) from the address actually connected' -ForEach @(
        @{ Form = '127.1' }
        @{ Form = '2130706433' }
        @{ Form = 'localhost' }
        @{ Form = '[::ffff:127.0.0.1]' }
    ) {
        Set-AiMock -Mock $script:main -Mode 'ollama' -Guard 'strict'
        $all = Invoke-AiConfirm -Endpoint "${Form}:$($script:main.Port)"
        $f = Select-AiRule $all 'aiserver.unauth-reachable'
        $f.Count | Should -Be 1
        $f[0].Severity | Should -Be 'MEDIUM'
        $f[0].File     | Should -Be $script:ep
        $f[0].Evidence | Should -Match 'connected address 127\.0\.0\.1 \(loopback\)'
    }

    It 'sends the connected address as the Host header, not the name it was given' {
        Set-AiMock -Mock $script:main -Mode 'ollama' -Guard 'strict'
        $all = Invoke-AiConfirm -Endpoint "localhost:$($script:main.Port)"
        (Select-AiRule $all 'aiserver.unauth-reachable').Count | Should -Be 1
        @(Get-AiLog $script:main | Where-Object { $_ -match '^GET /api/tags\|host=127\.0\.0\.1:' }).Count | Should -BeGreaterThan 0
    }

    It 'rates a non-loopback address HIGH (probe mocked, nothing is sent)' {
        Set-AiMock -Mock $script:main -Mode 'ollama' -Guard 'strict'
        $port = $script:main.Port
        $script:fakeObs = & (Get-Module TCPK) { param($p) Invoke-TcpkAiProbe -EndpointHost '127.0.0.1' -Port $p -TimeoutMs 3000 } $port
        $script:fakeObs.Address    = [System.Net.IPAddress]::Parse('192.0.2.10')
        $script:fakeObs.HostPort   = '192.0.2.10:8080'
        $script:fakeObs.IsLoopback = $false
        Mock -ModuleName TCPK Invoke-TcpkAiProbe { return $script:fakeObs }
        Mock -ModuleName TCPK Test-TcpkAiLocalAddress { return $false }
        $all = @(Confirm-TcpkAiInferenceServer -Endpoint '192.0.2.10:8080' -WarningAction SilentlyContinue)
        $f = Select-AiRule $all 'aiserver.unauth-reachable'
        $f.Count | Should -Be 1
        $f[0].Severity | Should -Be 'HIGH'
        $f[0].Evidence | Should -Match 'connected address 192\.0\.2\.10 \(not loopback\)'
        $f[0].Evidence | Should -Match 'not looked up'
        $c = & (Get-Module TCPK) { param($x) Get-TcpkCvssVector -Finding $x } $f[0]
        $c.Vector | Should -Match '/AV:N/'
    }

    # Gated to Windows so that, on the Linux development box, every test listener stays on
    # 127.0.0.1. The case itself is not Windows-specific.
    It 'reaches a listener on the IPv6 loopback address' -Skip:($IsWindows -eq $false) {
        $six = Start-AiMock -Address ([System.Net.IPAddress]::IPv6Loopback)
        if (-not $six) { Set-ItResult -Skipped -Because 'this host did not bind an IPv6 loopback listener'; return }
        try {
            Set-AiMock -Mock $six -Mode 'ollama' -Guard 'strict'
            $all = Invoke-AiConfirm -Endpoint "[::1]:$($six.Port)"
            $f = Select-AiRule $all 'aiserver.unauth-reachable'
            $f.Count | Should -Be 1
            $f[0].Severity | Should -Be 'MEDIUM'
            $f[0].File     | Should -Be "[::1]:$($six.Port)"
        } finally { Stop-AiMock -Mock $six }
    }
}

Describe 'Confirm-TcpkAiInferenceServer: transport limits' {

    It 'bounds a body that <What>, and reports no status for a response that never completed' -ForEach @(
        @{ Mode = 'stall'; What = 'stalls after the headers' }
        @{ Mode = 'drip';  What = 'arrives one byte at a time' }
    ) {
        Set-AiMock -Mock $script:main -Mode $Mode
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $all = Invoke-AiConfirm -TimeoutMs 400
        $sw.Stop()
        # Two requests, each bounded by the timeout plus the client's own slack.
        $sw.ElapsedMilliseconds | Should -BeLessThan 8000
        $all.Count | Should -Be 1
        $all[0].RuleId   | Should -Be 'aiserver.port-open-unidentified'
        $all[0].Evidence | Should -Match 'GET /api/tags -> no complete HTTP response within the timeout'
        $all[0].Evidence | Should -Not -Match '-> 200'
    }

    It 'bounds a listener that accepts and never answers' {
        Set-AiMock -Mock $script:main -Mode 'hang'
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $all = Invoke-AiConfirm -TimeoutMs 300
        $sw.Stop()
        $sw.ElapsedMilliseconds | Should -BeLessThan 8000
        $all.Count | Should -Be 1
        $all[0].RuleId   | Should -Be 'aiserver.port-open-unidentified'
        $all[0].Evidence | Should -Match 'no complete HTTP response within the timeout'
    }

    It 'caps the response size and does not parse an over-size body' {
        Set-AiMock -Mock $script:main -Mode 'big'
        $all = Invoke-AiConfirm
        $all.Count | Should -Be 1
        $all[0].RuleId   | Should -Be 'aiserver.port-open-unidentified'
        # The size limit is the client's. Its error names the limit; if a runtime words it
        # differently the line still says no complete response came back.
        $all[0].Evidence | Should -Match 'GET /api/tags -> (response over the \d+-byte cap, not read|no HTTP response)'
        $all[0].Evidence | Should -Not -Match '-> 200'
    }

    It 'masks an over-long model name without holding the probe, inside the size cap' {
        # 900 KB of "eyJ" with no dot: under the 1 MB cap, and the worst case for a pattern
        # that looks for a three-part token.
        $long = 'eyJ' * 300000
        Set-AiMock -Mock $script:main -Mode 'tags-only' -Tags ('{"models":[{"name":"' + $long + '"},{"name":"llama3:latest"}]}')
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $all = Invoke-AiConfirm -TimeoutMs 3000
        $sw.Stop()
        # Six requests that each complete at once: a few multiples of the timeout is generous.
        $sw.ElapsedMilliseconds | Should -BeLessThan 12000
        $u = Select-AiRule $all 'aiserver.unauth-reachable'
        $u.Count | Should -Be 1
        $u[0].Evidence | Should -Match '2 entries: <masked>, llama3:latest'
        foreach ($x in $all) { $x.Evidence | Should -Not -Match 'eyJeyJ' }
    }

    It 'bounds server-supplied text before a pattern runs on it' {
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $r = & (Get-Module TCPK) { Get-TcpkAiSafeName -Text ('eyJ' * 100000) }
        $sw.Stop()
        $r | Should -Be '<masked>'
        $sw.ElapsedMilliseconds | Should -BeLessThan 2000
        # The limit is 256 characters: a name of that length is still looked at.
        $atLimit = & (Get-Module TCPK) { Get-TcpkAiSafeName -Text ('a-' * 128) -Max 60 }
        $over    = & (Get-Module TCPK) { Get-TcpkAiSafeName -Text (('a-' * 128) + 'b') -Max 60 }
        $atLimit | Should -Be (('a-' * 30) + '...')
        $over    | Should -Be '<masked>'
        $t = & (Get-Module TCPK) { Get-TcpkAiSafeText -Text ('x<' * 250000) -Max 40 }
        $t | Should -Be (('x?' * 20) + '...')
        $loc = & (Get-Module TCPK) { Get-TcpkAiSafeLocation -Text ('/a/' + ('b.' * 200000)) }
        $loc.Length | Should -BeLessOrEqual 123
    }

    It 'sets the client timeout and the response-size cap where the request is built' {
        $src = [IO.File]::ReadAllText((Join-Path (Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'Private') '_AiProbe.ps1'))
        $src | Should -Match 'client\.Timeout\s*=\s*\[TimeSpan\]::FromMilliseconds\(\$TimeoutMs\)'
        $src | Should -Match 'MaxResponseContentBufferSize\s*='
        $src | Should -Match 'UseDefaultCredentials\s*=\s*\$false'
    }

    It 'refuses to send a request for a path that is not on the allow-list' {
        Set-AiMock -Mock $script:main -Mode 'ollama'
        $port = $script:main.Port
        $r = & (Get-Module TCPK) { param($p) Invoke-TcpkAiHttpGet -Address ([System.Net.IPAddress]::Loopback) -Port $p -Path '/api/pull' -TimeoutMs 2000 } $port
        $r.Status | Should -Be 0
        $r.Error  | Should -Match 'allow-list'
        @(Get-AiLog $script:main).Count | Should -Be 0
    }

    It 'ignores an http_proxy environment variable: the proxy never sees the request' {
        Set-AiMock -Mock $script:main -Mode '401'
        Set-AiMock -Mock $script:other -Mode 'ollama' -Version '0.1.1'
        $exe = (Get-Process -Id $PID).Path
        $oldLower = [Environment]::GetEnvironmentVariable('http_proxy')
        $oldUpper = [Environment]::GetEnvironmentVariable('HTTP_PROXY')
        $out = ''
        try {
            $proxy = "http://127.0.0.1:$($script:other.Port)"
            [Environment]::SetEnvironmentVariable('http_proxy', $proxy)
            [Environment]::SetEnvironmentVariable('HTTP_PROXY', $proxy)
            $cmd = "Import-Module '$($script:psd1)' -Force; Enable-TcpkExploit -Acknowledge | Out-Null; " +
                   "'RULES=' + ((Confirm-TcpkAiInferenceServer -Endpoint '$($script:ep)' -TimeoutMs 3000 | ForEach-Object { `$_.RuleId }) -join ',')"
            $out = (& $exe -NoProfile -Command $cmd | Out-String)
        } finally {
            [Environment]::SetEnvironmentVariable('http_proxy', $oldLower)
            [Environment]::SetEnvironmentVariable('HTTP_PROXY', $oldUpper)
        }
        $out | Should -Match 'RULES=aiserver\.reachable-authed'
        $out | Should -Not -Match 'unauth-reachable|probllama'
        @(Get-AiLog $script:other).Count | Should -Be 0
        @(Get-AiLog $script:main).Count  | Should -Be 2
    }

    It 'turns redirects and the proxy off where the request is built' {
        $src = [IO.File]::ReadAllText((Join-Path (Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'Private') '_AiProbe.ps1'))
        $src | Should -Match 'AllowAutoRedirect\s*=\s*\$false'
        $src | Should -Match 'UseProxy\s*=\s*\$false'
        $cmdlet = [IO.File]::ReadAllText((Join-Path (Join-Path (Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'Public') 'Verify') 'Confirm-TcpkAiInferenceServer.ps1'))
        $cmdlet | Should -Not -Match 'Invoke-RestMethod|Invoke-WebRequest'
        $src    | Should -Not -Match 'Invoke-RestMethod|Invoke-WebRequest'
    }
}

Describe 'Confirm-TcpkAiInferenceServer: secrets and server-supplied text' {

    It 'masks a token-shaped model name in Evidence' {
        $jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJlLXZhbHVl'
        Set-AiMock -Mock $script:main -Mode 'tags-only' -Tags ('{"models":[{"name":"' + $jwt + '"}]}')
        $all = Invoke-AiConfirm
        (Select-AiRule $all 'aiserver.unauth-reachable').Count | Should -Be 1
        foreach ($x in $all) {
            "$($x.Evidence) $($x.Title) $($x.Description)" | Should -Not -Match 'eyJhbGciOiJIUzI1NiJ9'
        }
    }

    It 'keeps markup in a model name out of Evidence' {
        Set-AiMock -Mock $script:main -Mode 'tags-only' -Tags '{"models":[{"name":"<script>alert(1)</script>"}]}'
        $all = Invoke-AiConfirm
        foreach ($x in $all) { "$($x.Evidence) $($x.Title)" | Should -Not -Match '<script>' }
    }

    It 'masks a model name shaped like <Kind>' -ForEach @(
        @{ Kind = 'an API key with a known prefix'; Name = 'sk-proj-Ab12Cd34Ef56Gh78'; Leak = 'Ab12Cd34Ef56' }
        @{ Kind = 'a long unbroken token';          Name = '0123456789abcdef0123456789abcdef01234567'; Leak = '0123456789abcdef' }
        @{ Kind = 'a cloud access key id';          Name = 'AKIAIOSFODNN7EXAMPLE'; Leak = 'IOSFODNN7' }
    ) {
        Set-AiMock -Mock $script:main -Mode 'tags-only' -Tags ('{"models":[{"name":"' + $Name + '"},{"name":"llama3:latest"}]}')
        $all = Invoke-AiConfirm
        $u = Select-AiRule $all 'aiserver.unauth-reachable'
        $u.Count | Should -Be 1
        $u[0].Evidence | Should -Match '2 entries: <masked>, llama3:latest'
        foreach ($x in $all) { "$($x.Evidence) $($x.Title) $($x.Description)" | Should -Not -Match ([regex]::Escape($Leak)) }
    }

    It 'masks a model id shaped like <Kind>' -ForEach @(
        @{ Kind = 'a URL with user-info';                 Name = 'https://svcuser:Winter2026pw@models.internal.example/v1/llama'; Leak = 'Winter2026pw|svcuser' }
        @{ Kind = 'a query string that carries a key';    Name = 'azure/gpt-4o?api-key=3f9a1c2b7d8e4f60a1b2';                     Leak = '3f9a1c2b7d8e4f60a1b2' }
        @{ Kind = 'a key=value pair';                     Name = 'password=Sup3rS3cret!';                                         Leak = 'Sup3rS3cret' }
        @{ Kind = 'user:password@host with no scheme';    Name = 'svcuser:Hunter2Pass@models.example/llama';                      Leak = 'Hunter2Pass|svcuser' }
    ) {
        Set-AiMock -Mock $script:main -Mode 'openai' -V1 ('{"object":"list","data":[{"id":"' + $Name + '"},{"id":"llama3:latest"}]}')
        $all = Invoke-AiConfirm
        $u = Select-AiRule $all 'aiserver.unauth-reachable'
        $u.Count | Should -Be 1
        $u[0].Evidence | Should -Match '2 entries: <masked>, llama3:latest'
        foreach ($x in $all) { "$($x.Evidence) $($x.Title) $($x.Description)" | Should -Not -Match $Leak }
    }

    It 'prints ordinary model names unchanged' {
        $names = & (Get-Module TCPK) {
            @('llama3:latest', 'mistral-7b-instruct-v0.2.Q4_K_M.gguf', 'hf.co/bartowski/Llama-3.2-3B-Instruct-GGUF:Q4_K_M', 'text-embedding-3-small', 'sk-roberta-base', 'asia-llm-7b-chat-v2', 'publishers/vendor/models/chat-large@20240620') |
                ForEach-Object { Get-TcpkAiSafeName -Text $_ -Max 60 }
        }
        @($names) -join '|' | Should -Be 'llama3:latest|mistral-7b-instruct-v0.2.Q4_K_M.gguf|hf.co/bartowski/Llama-3.2-3B-Instruct-GGUF:Q4_K_M|text-embedding-3-small|sk-roberta-base|asia-llm-7b-chat-v2|publishers/vendor/models/chat-large@20240620'
    }

    It 'removes user-info and a token-shaped path segment from a redirect target' {
        Set-AiMock -Mock $script:main -Mode 'redirect-cred'
        $all = Invoke-AiConfirm
        $all.Count | Should -Be 1
        $all[0].RuleId   | Should -Be 'aiserver.port-open-unidentified'
        $all[0].Evidence | Should -Match '-> 302 redirect to http://127\.0\.0\.1:1/sso/<masked>/start \(not followed\)'
        "$($all[0].Evidence) $($all[0].Title) $($all[0].Description)" | Should -Not -Match 'Hunter2Pass|admin:|Zm9vYmFy'
    }

    It 'keeps bytes quoted in a client error out of Evidence, and does not mistake them for the size cap' {
        Set-AiMock -Mock $script:main -Mode 'garbage'
        $all = Invoke-AiConfirm
        $all.Count | Should -Be 1
        $all[0].RuleId   | Should -Be 'aiserver.port-open-unidentified'
        $all[0].Evidence | Should -Match 'GET /api/tags -> no HTTP response'
        $all[0].Evidence | Should -Not -Match '<script>|byte cap'
    }

    It 'does not echo a password typed into an endpoint URL back in the warning' {
        $w = $null
        $r = @(Confirm-TcpkAiInferenceServer -Endpoint 'http://operator:S3cretPw9@127.0.0.1:1/' -WarningVariable w -WarningAction SilentlyContinue)
        $r.Count | Should -Be 0
        @($w).Count | Should -Be 1
        "$($w[0])" | Should -Match '<redacted>@127\.0\.0\.1:1'
        "$($w[0])" | Should -Not -Match 'S3cretPw9|operator'
    }

    It 'does not echo a password that holds <What> back in the warning' -ForEach @(
        @{ What = 'an at sign';         Url = 'http://operator:p@ssW0rd9@127.0.0.1:1';  Leak = 'ssW0rd9|operator|p@' }
        @{ What = 'a slash';            Url = 'http://operator:pa/ssW0rd9@127.0.0.1:1'; Leak = 'ssW0rd9|operator|pa/' }
        @{ What = 'no scheme in front'; Url = 'operator:S3cretPw9@127.0.0.1:1';         Leak = 'S3cretPw9|operator' }
    ) {
        $w = $null
        $r = @(Confirm-TcpkAiInferenceServer -Endpoint $Url -WarningVariable w -WarningAction SilentlyContinue)
        $r.Count | Should -Be 0
        @($w).Count | Should -Be 1
        "$($w[0])" | Should -Match "endpoint '(http://)?<redacted>@127\.0\.0\.1:1' was not probed: user-info"
        "$($w[0])" | Should -Not -Match $Leak
    }
}

Describe 'Confirm-TcpkAiInferenceServer: attribution' {

    It 'reports a listener found by the default sweep, without -Path, as INFO and unattributed' {
        Set-AiMock -Mock $script:main -Mode 'ollama' -Version '0.1.33' -Guard 'none'
        Mock -ModuleName TCPK Get-TcpkAiDefaultEndpoint { return @($script:ep) }
        $all = @(Confirm-TcpkAiInferenceServer -TimeoutMs 3000 -WarningAction SilentlyContinue)
        $all.Count | Should -Be 3
        foreach ($x in $all) {
            $x.Severity         | Should -Be 'INFO'
            $x.AttributionBasis | Should -Be 'unproven'
            $x.Title            | Should -Match 'not shown to belong to the audited target'
            $x.Evidence         | Should -Match 'scope: default loopback port sweep'
        }
        $u = Select-AiRule $all 'aiserver.unauth-reachable'
        $u[0].Title       | Should -Match '^Local Ollama server on this host'
        $u[0].Description | Should -Match 'not as a finding about the audited target'
        Should -Invoke -ModuleName TCPK Get-TcpkAiDefaultEndpoint -Times 1 -Exactly
    }

    It 'does not call a swept listener an inference server when it returned no model list' {
        Set-AiMock -Mock $script:main -Mode 'html'
        Mock -ModuleName TCPK Get-TcpkAiDefaultEndpoint { return @($script:ep) }
        $all = @(Confirm-TcpkAiInferenceServer -TimeoutMs 3000 -WarningAction SilentlyContinue)
        $all.Count | Should -Be 1
        $all[0].RuleId           | Should -Be 'aiserver.port-open-unidentified'
        $all[0].Severity         | Should -Be 'INFO'
        $all[0].AttributionBasis | Should -Be 'unproven'
        $all[0].Title            | Should -Match 'not shown to belong to the audited target'
        $all[0].Description      | Should -Match 'reported as a listener on this host'
        "$($all[0].Title) $($all[0].Description)" | Should -Not -Match 'reported as a local inference server'
    }

    It 'stays INFO through the attribution filter, which marks it AMBIENT' {
        Set-AiMock -Mock $script:main -Mode 'ollama' -Guard 'strict'
        Mock -ModuleName TCPK Get-TcpkAiDefaultEndpoint { return @($script:ep) }
        $all = @(Confirm-TcpkAiInferenceServer -TimeoutMs 3000 -WarningAction SilentlyContinue)
        $out = @(& (Get-Module TCPK) { param($x) @(Invoke-TcpkAttributionFilter -Findings $x) } $all)
        $out.Count | Should -Be 1
        $out[0].Severity | Should -Be 'INFO'
        $out[0].Title    | Should -Match '^AMBIENT: '
    }

    It 'keeps actionable severity in a sweep when the owning image is under -Path' {
        Set-AiMock -Mock $script:main -Mode 'ollama' -Guard 'strict'
        Mock -ModuleName TCPK Get-TcpkAiDefaultEndpoint { return @($script:ep) }
        Mock -ModuleName TCPK Get-TcpkAiListenerOwner {
            return [pscustomobject]@{ Resolved = $true; ProcessId = 4242; ProcessName = 'server'; ImagePath = 'C:\TcpkAiTarget\bin\server.exe'; Note = '' }
        }
        $all = @(Confirm-TcpkAiInferenceServer -Path 'C:\TcpkAiTarget' -TimeoutMs 3000 -WarningAction SilentlyContinue)
        $u = Select-AiRule $all 'aiserver.unauth-reachable'
        $u.Count | Should -Be 1
        $u[0].Severity         | Should -Be 'MEDIUM'
        $u[0].AttributionBasis | Should -Be 'established-footprint'
        $u[0].Title            | Should -Not -Match 'not shown to belong'
        $u[0].Evidence         | Should -Match 'listener owner: PID 4242 \(server\) C:\\TcpkAiTarget\\bin\\server\.exe; image is under -Path'
        Should -Invoke -ModuleName TCPK Get-TcpkAiListenerOwner -Times 1 -Exactly
    }

    It 'stays INFO in a sweep when the owning image is outside -Path' {
        Set-AiMock -Mock $script:main -Mode 'ollama' -Guard 'strict'
        Mock -ModuleName TCPK Get-TcpkAiDefaultEndpoint { return @($script:ep) }
        Mock -ModuleName TCPK Get-TcpkAiListenerOwner {
            return [pscustomobject]@{ Resolved = $true; ProcessId = 777; ProcessName = 'ollama'; ImagePath = 'C:\Users\op\AppData\Local\Programs\Ollama\ollama.exe'; Note = '' }
        }
        $all = @(Confirm-TcpkAiInferenceServer -Path 'C:\TcpkAiTarget' -TimeoutMs 3000 -WarningAction SilentlyContinue)
        $u = Select-AiRule $all 'aiserver.unauth-reachable'
        $u[0].Severity         | Should -Be 'INFO'
        $u[0].AttributionBasis | Should -Be 'unproven'
        $u[0].Evidence         | Should -Match 'image is not under -Path'
        # -Path was given and the image was measured outside it: the text says that, and
        # does not tell the operator to pass a -Path that was already passed.
        $u[0].Description      | Should -Match 'runs from an image that is not under -Path'
        $u[0].Description      | Should -Not -Match 'pass its install root with -Path'
    }

    It 'stays INFO in a sweep when the owner cannot be resolved' {
        Set-AiMock -Mock $script:main -Mode 'ollama' -Guard 'strict'
        Mock -ModuleName TCPK Get-TcpkAiDefaultEndpoint { return @($script:ep) }
        Mock -ModuleName TCPK Get-TcpkAiListenerOwner {
            return [pscustomobject]@{ Resolved = $false; ProcessId = 4; ProcessName = ''; ImagePath = ''; Note = 'the image path of the owning process could not be read' }
        }
        $all = @(Confirm-TcpkAiInferenceServer -Path 'C:\TcpkAiTarget' -TimeoutMs 3000 -WarningAction SilentlyContinue)
        $u = Select-AiRule $all 'aiserver.unauth-reachable'
        $u[0].Severity         | Should -Be 'INFO'
        $u[0].AttributionBasis | Should -Be 'unproven'
        $u[0].Evidence         | Should -Match 'listener owner: not resolved'
    }

    It 'keeps severity for an endpoint the operator named, and never claims a baseline diff' {
        Set-AiMock -Mock $script:main -Mode 'ollama' -Version '0.1.33' -Guard 'none'
        $all = Invoke-AiConfirm
        $all.Count | Should -Be 3
        foreach ($x in $all) {
            $x.AttributionBasis | Should -Be 'established-code'
            $x.AttributionBasis | Should -Not -Be 'established-baseline-diff'
            $x.Severity         | Should -Not -Be 'INFO'
            $x.Evidence         | Should -Match 'scope: endpoint named with -Endpoint'
        }
        $out = @(& (Get-Module TCPK) { param($x) @(Invoke-TcpkAttributionFilter -Findings $x) } $all)
        @($out | Where-Object { $_.Title -match '^AMBIENT' }).Count | Should -Be 0
    }

    It 'records footprint for a named endpoint whose owning image is under -Path' {
        Set-AiMock -Mock $script:main -Mode 'ollama' -Guard 'strict'
        Mock -ModuleName TCPK Get-TcpkAiListenerOwner {
            return [pscustomobject]@{ Resolved = $true; ProcessId = 4242; ProcessName = 'server'; ImagePath = 'C:\TcpkAiTarget\bin\server.exe'; Note = '' }
        }
        $all = @(Confirm-TcpkAiInferenceServer -Endpoint $script:ep -Path 'C:\TcpkAiTarget' -TimeoutMs 3000 -WarningAction SilentlyContinue)
        $u = Select-AiRule $all 'aiserver.unauth-reachable'
        $u[0].Severity         | Should -Be 'MEDIUM'
        $u[0].AttributionBasis | Should -Be 'established-footprint'
    }

    It 'reports a named endpoint as INFO and unattributed when its owning image is measured outside -Path' {
        # The operator's own Ollama, named with -Endpoint while auditing some other target.
        Set-AiMock -Mock $script:main -Mode 'ollama' -Version '0.1.33' -Guard 'none'
        Mock -ModuleName TCPK Get-TcpkAiListenerOwner {
            return [pscustomobject]@{ Resolved = $true; ProcessId = 777; ProcessName = 'ollama'; ImagePath = 'C:\Users\op\AppData\Local\Programs\Ollama\ollama.exe'; Note = '' }
        }
        $w = $null
        $all = @(Confirm-TcpkAiInferenceServer -Endpoint $script:ep -Path 'C:\TcpkAiTarget' -TimeoutMs 3000 -WarningVariable w -WarningAction SilentlyContinue)
        $all.Count | Should -Be 3
        foreach ($x in $all) {
            $x.Severity         | Should -Be 'INFO'
            $x.AttributionBasis | Should -Be 'unproven'
            $x.Title            | Should -Match 'not shown to belong to the audited target'
            $x.Evidence         | Should -Match 'scope: endpoint named with -Endpoint'
            $x.Evidence         | Should -Match 'image is not under -Path'
            $x.Description      | Should -Match 'measurement outranks the statement of scope'
            $x.Description      | Should -Not -Match 'sweeping the default loopback ports'
        }
        @($w | Where-Object { "$_" -match 'not under -Path' }).Count | Should -Be 1
        # The record no longer contradicts itself, so the filter can act on it.
        $out = @(& (Get-Module TCPK) { param($x) @(Invoke-TcpkAttributionFilter -Findings $x) } $all)
        @($out | Where-Object { $_.Title -match '^AMBIENT: ' }).Count | Should -Be 3
        @($out | Where-Object { $_.Severity -ne 'INFO' }).Count | Should -Be 0
    }

    It 'keeps a named endpoint on the operator statement when -Path is given but the owner is not resolved' {
        Set-AiMock -Mock $script:main -Mode 'ollama' -Guard 'strict'
        Mock -ModuleName TCPK Get-TcpkAiListenerOwner {
            return [pscustomobject]@{ Resolved = $false; ProcessId = 4; ProcessName = ''; ImagePath = ''; Note = 'the image path of the owning process could not be read' }
        }
        $all = @(Confirm-TcpkAiInferenceServer -Endpoint $script:ep -Path 'C:\TcpkAiTarget' -TimeoutMs 3000 -WarningAction SilentlyContinue)
        $u = Select-AiRule $all 'aiserver.unauth-reachable'
        $u[0].Severity         | Should -Be 'MEDIUM'
        $u[0].AttributionBasis | Should -Be 'established-code'
        $u[0].Evidence         | Should -Match 'listener owner: not resolved'
    }

    It 'keeps a named endpoint on the operator statement when -Path is not given, whatever owns the port' {
        Set-AiMock -Mock $script:main -Mode 'ollama' -Guard 'strict'
        Mock -ModuleName TCPK Get-TcpkAiListenerOwner {
            return [pscustomobject]@{ Resolved = $true; ProcessId = 777; ProcessName = 'ollama'; ImagePath = 'C:\Users\op\AppData\Local\Programs\Ollama\ollama.exe'; Note = '' }
        }
        $w = $null
        $all = @(Confirm-TcpkAiInferenceServer -Endpoint $script:ep -TimeoutMs 3000 -WarningVariable w -WarningAction SilentlyContinue)
        $u = Select-AiRule $all 'aiserver.unauth-reachable'
        $u[0].Severity         | Should -Be 'MEDIUM'
        $u[0].AttributionBasis | Should -Be 'established-code'
        $u[0].Evidence         | Should -Match '-Path not given'
        @($w).Count | Should -Be 0
    }

    It 'resolves the real owner of a listening port to this process' -Skip:($IsWindows -eq $false) {
        $port = $script:main.Port
        $o = & (Get-Module TCPK) { param($p) Get-TcpkAiListenerOwner -Port $p -Address ([System.Net.IPAddress]::Loopback) } $port
        $o.Resolved  | Should -BeTrue
        $o.ProcessId | Should -Be $PID
        $o.ImagePath | Should -Not -BeNullOrEmpty
    }

    It 'attributes a swept listener by its real owning image and an existing -Path' -Skip:($IsWindows -eq $false) {
        Set-AiMock -Mock $script:main -Mode 'ollama' -Guard 'strict'
        Mock -ModuleName TCPK Get-TcpkAiDefaultEndpoint { return @($script:ep) }
        # The listener lives in this PowerShell process, so its image folder is the "target".
        $hostDir = Split-Path -Parent (Get-Process -Id $PID).Path
        $all = @(Confirm-TcpkAiInferenceServer -Path $hostDir -TimeoutMs 3000 -WarningAction SilentlyContinue)
        $u = Select-AiRule $all 'aiserver.unauth-reachable'
        $u[0].Severity         | Should -Be 'MEDIUM'
        $u[0].AttributionBasis | Should -Be 'established-footprint'
        # An unrelated, existing folder must not attribute.
        $all2 = @(Confirm-TcpkAiInferenceServer -Path $script:targetDir -TimeoutMs 3000 -WarningAction SilentlyContinue)
        (Select-AiRule $all2 'aiserver.unauth-reachable')[0].Severity | Should -Be 'INFO'
    }

    It 'takes a file passed as -Path as its folder' -Skip:($IsWindows -eq $false) {
        Set-AiMock -Mock $script:main -Mode 'ollama' -Guard 'strict'
        Mock -ModuleName TCPK Get-TcpkAiDefaultEndpoint { return @($script:ep) }
        $img = $script:targetExe
        Mock -ModuleName TCPK Get-TcpkAiListenerOwner {
            return [pscustomobject]@{ Resolved = $true; ProcessId = 4242; ProcessName = 'server'; ImagePath = $script:targetExe; Note = '' }
        }
        $all = @(Confirm-TcpkAiInferenceServer -Path $img -TimeoutMs 3000 -WarningAction SilentlyContinue)
        (Select-AiRule $all 'aiserver.unauth-reachable')[0].AttributionBasis | Should -Be 'established-footprint'
    }

    It 'warns when -Path does not exist' {
        Set-AiMock -Mock $script:main -Mode 'html'
        $w = $null
        $missing = Join-Path $script:root 'no-such-folder'
        $null = @(Confirm-TcpkAiInferenceServer -Endpoint $script:ep -Path $missing -TimeoutMs 3000 -WarningVariable w -WarningAction SilentlyContinue)
        @($w | Where-Object { "$_" -match 'does not exist' }).Count | Should -Be 1
    }
}

Describe 'Get-TcpkAiListenerOwner: listener-table logic' {

    # The lookup is Windows-only, so its row selection would otherwise run nowhere but on the
    # owner's machine. The one call that needs Windows (the listener table) sits behind
    # Get-TcpkAiListenRow; with that mocked the selection logic runs on any host.
    BeforeAll {
        function New-AiTable([object[]]$Rows) {
            return @{ Ok = $true; Rows = @($Rows); Note = '' }
        }
        function New-AiRow([string]$Address, [int]$OwnerId) {
            return [pscustomobject]@{ LocalAddress = $Address; OwningProcess = $OwnerId }
        }
        function Get-AiOwner([string]$Address = '127.0.0.1') {
            return & (Get-Module TCPK) { param($a) Get-TcpkAiListenerOwner -Port 11434 -Address ([System.Net.IPAddress]::Parse($a)) } $Address
        }
    }

    It 'prefers the socket bound to the connected address over a wildcard bind' {
        Mock -ModuleName TCPK Test-TcpkIsWindows { return $true }
        Mock -ModuleName TCPK Get-TcpkAiListenRow { return (New-AiTable @((New-AiRow '0.0.0.0' 111), (New-AiRow '127.0.0.1' 222))) }
        Mock -ModuleName TCPK Get-Process { return [pscustomobject]@{ ProcessName = 'server'; Path = 'C:\TcpkAiTarget\bin\server.exe' } }
        $o = Get-AiOwner
        $o.Resolved    | Should -BeTrue
        $o.ProcessId   | Should -Be 222
        $o.ProcessName | Should -Be 'server'
        $o.ImagePath   | Should -Be 'C:\TcpkAiTarget\bin\server.exe'
    }

    It 'falls back to a wildcard bind of the same family, then to the dual-stack wildcard' {
        Mock -ModuleName TCPK Test-TcpkIsWindows { return $true }
        Mock -ModuleName TCPK Get-Process { return [pscustomobject]@{ ProcessName = 'server'; Path = 'C:\x\server.exe' } }
        Mock -ModuleName TCPK Get-TcpkAiListenRow { return (New-AiTable @((New-AiRow '::' 333), (New-AiRow '0.0.0.0' 444))) }
        (Get-AiOwner).ProcessId | Should -Be 444
        (Get-AiOwner '::1').ProcessId | Should -Be 333
        Mock -ModuleName TCPK Get-TcpkAiListenRow { return (New-AiTable @((New-AiRow '::' 555))) }
        (Get-AiOwner).ProcessId | Should -Be 555
    }

    It 'does not resolve when two processes hold the same address' {
        Mock -ModuleName TCPK Test-TcpkIsWindows { return $true }
        Mock -ModuleName TCPK Get-Process { return [pscustomobject]@{ ProcessName = 'server'; Path = 'C:\x\server.exe' } }
        Mock -ModuleName TCPK Get-TcpkAiListenRow { return (New-AiTable @((New-AiRow '127.0.0.1' 1), (New-AiRow '127.0.0.1' 2))) }
        $o = Get-AiOwner
        $o.Resolved | Should -BeFalse
        $o.Note     | Should -Match 'more than one process'
    }

    It 'does not resolve when no listening socket is reported' {
        Mock -ModuleName TCPK Test-TcpkIsWindows { return $true }
        Mock -ModuleName TCPK Get-TcpkAiListenRow { return @{ Ok = $false; Rows = @(); Note = 'no listening socket was found for this port' } }
        $o = Get-AiOwner
        $o.Resolved | Should -BeFalse
        $o.Note     | Should -Match 'no listening socket'
    }

    It 'does not resolve when only another address is bound' {
        Mock -ModuleName TCPK Test-TcpkIsWindows { return $true }
        Mock -ModuleName TCPK Get-TcpkAiListenRow { return (New-AiTable @((New-AiRow '192.0.2.7' 9))) }
        $o = Get-AiOwner
        $o.Resolved | Should -BeFalse
        $o.Note     | Should -Match 'no listening socket matches'
    }

    It 'uses the process table when Get-Process cannot read the image path' {
        Mock -ModuleName TCPK Test-TcpkIsWindows { return $true }
        Mock -ModuleName TCPK Get-TcpkAiListenRow { return (New-AiTable @((New-AiRow '127.0.0.1' 4242))) }
        Mock -ModuleName TCPK Get-Process { return [pscustomobject]@{ ProcessName = 'svc'; Path = $null } }
        Mock -ModuleName TCPK Get-TcpkCimSafe { return @([pscustomobject]@{ ProcessId = 4242; Name = 'svc.exe'; ExecutablePath = 'C:\TcpkAiTarget\svc.exe' }) }
        $o = Get-AiOwner
        $o.Resolved  | Should -BeTrue
        $o.ImagePath | Should -Be 'C:\TcpkAiTarget\svc.exe'
        Should -Invoke -ModuleName TCPK Get-TcpkCimSafe -Times 1 -Exactly
    }

    It 'fails closed when the image path cannot be read at all' {
        Mock -ModuleName TCPK Test-TcpkIsWindows { return $true }
        Mock -ModuleName TCPK Get-TcpkAiListenRow { return (New-AiTable @((New-AiRow '127.0.0.1' 6120))) }
        Mock -ModuleName TCPK Get-Process { return [pscustomobject]@{ ProcessName = 'svc'; Path = $null } }
        Mock -ModuleName TCPK Get-TcpkCimSafe { return @() }
        $o = Get-AiOwner
        $o.Resolved  | Should -BeFalse
        $o.ProcessId | Should -Be 6120
        $o.Note      | Should -Match 'image path'
    }

    It 'says that a port owned by the System process hides the application behind it' {
        Mock -ModuleName TCPK Test-TcpkIsWindows { return $true }
        Mock -ModuleName TCPK Get-TcpkAiListenRow { return (New-AiTable @((New-AiRow '0.0.0.0' 4))) }
        Mock -ModuleName TCPK Get-Process { return [pscustomobject]@{ ProcessName = 'System'; Path = $null } }
        Mock -ModuleName TCPK Get-TcpkCimSafe { return @() }
        $o = Get-AiOwner
        $o.Resolved  | Should -BeFalse
        $o.ProcessId | Should -Be 4
        $o.Note      | Should -Match 'System process'
    }

    It 'says so when the listener-table cmdlet is not present' {
        Mock -ModuleName TCPK Get-Command { return $null } -ParameterFilter { "$Name" -eq 'Get-NetTCPConnection' }
        $t = & (Get-Module TCPK) { Get-TcpkAiListenRow -Port 11434 }
        $t.Ok   | Should -BeFalse
        $t.Note | Should -Match 'Get-NetTCPConnection is not available'
        Mock -ModuleName TCPK Test-TcpkIsWindows { return $true }
        $o = Get-AiOwner
        $o.Resolved | Should -BeFalse
        $o.Note     | Should -Match 'Get-NetTCPConnection is not available'
    }

    It 'does not look at the listener table on a non-Windows host' {
        Mock -ModuleName TCPK Test-TcpkIsWindows { return $false }
        Mock -ModuleName TCPK Get-TcpkAiListenRow { return (New-AiTable @((New-AiRow '127.0.0.1' 4242))) }
        $o = Get-AiOwner
        $o.Resolved | Should -BeFalse
        Should -Invoke -ModuleName TCPK Get-TcpkAiListenRow -Times 0 -Exactly
    }

    It 'treats a non-local address as not this machine, so the lookup is skipped for it' {
        $isLocal = & (Get-Module TCPK) { Test-TcpkAiLocalAddress -Address ([System.Net.IPAddress]::Parse('192.0.2.10')) }
        $isLoop  = & (Get-Module TCPK) { Test-TcpkAiLocalAddress -Address ([System.Net.IPAddress]::Parse('127.0.0.53')) }
        $isLocal | Should -BeFalse
        $isLoop  | Should -BeTrue
    }
}

Describe 'Confirm-TcpkAiInferenceServer: pipeline, wiring and gate' {

    It 'passes piped findings through unchanged and still probes' {
        Set-AiMock -Mock $script:main -Mode 'openai'
        $leads = & (Get-Module TCPK) {
            @(
                New-TcpkFinding -Module 'network' -RuleId 'aiserver.local-server' -Severity 'MEDIUM' -Confidence 'Inferred' -Title 'lead one' -File 'C:\app\a.dll'
                New-TcpkFinding -Module 'static' -RuleId 'secrets.generic' -Severity 'LOW' -Confidence 'Inferred' -Title 'unrelated' -File 'C:\app\b.dll'
            )
        }
        $errs = $null
        $out = @($leads | Confirm-TcpkAiInferenceServer -Endpoint $script:ep -TimeoutMs 3000 -ErrorVariable errs -ErrorAction SilentlyContinue -WarningAction SilentlyContinue)
        @($errs).Count | Should -Be 0
        (Select-AiRule $out 'aiserver.local-server').Count | Should -Be 1
        (Select-AiRule $out 'secrets.generic').Count | Should -Be 1
        (Select-AiRule $out 'aiserver.local-server')[0].Confidence | Should -Be 'Inferred'
        (Select-AiRule $out 'aiserver.unauth-reachable').Count | Should -Be 1
    }

    It 'has a verify hint that names the cmdlet and fills in a live endpoint' {
        $h = & (Get-Module TCPK) { Get-TcpkVerifyHint -RuleId 'aiserver.unauth-reachable' -File '127.0.0.1:11434' -Evidence 'x' }
        $h | Should -Match "Confirm-TcpkAiInferenceServer -Endpoint '127\.0\.0\.1:11434'"
        $h | Should -Match 'Enable-TcpkExploit -Acknowledge'
        # The hint must describe what -Path does and how the two ratings differ.
        $h | Should -Match 'outside that folder, the records are reported as INFO'
        $h | Should -Match 'LOW on a product that was not identified'
        $h | Should -Not -Match 'foreign Origin or Host header was accepted'
        $s = & (Get-Module TCPK) { Get-TcpkVerifyHint -RuleId 'aiserver.local-server' -File 'C:\app\x.dll' -Evidence 'port 11434' }
        $s | Should -Match 'Confirm-TcpkAiInferenceServer'
        $s | Should -Not -Match 'x\.dll'
    }

    It 'maps the three actionable rules to a category and leaves the INFO records unmapped' {
        $c = & (Get-Module TCPK) {
            [pscustomobject]@{
                Unauth = Get-TcpkCategoryText -RuleId 'aiserver.unauth-reachable'
                Origin = Get-TcpkCategoryText -RuleId 'aiserver.origin-unchecked'
                Cve    = Get-TcpkCategoryText -RuleId 'aiserver.ollama-probllama-version'
                Authed = Get-TcpkCategoryText -RuleId 'aiserver.reachable-authed'
                Open   = Get-TcpkCategoryText -RuleId 'aiserver.port-open-unidentified'
            }
        }
        $c.Unauth | Should -Not -BeNullOrEmpty
        $c.Origin | Should -Not -BeNullOrEmpty
        $c.Cve    | Should -Match 'Dependencies'
        $c.Authed | Should -BeNullOrEmpty
        $c.Open   | Should -BeNullOrEmpty
    }

    It 'returns no field that nothing reads' {
        $a = & (Get-Module TCPK) { Resolve-TcpkAiAddress -HostName '127.0.0.1' }
        $a.Ok | Should -BeTrue
        $a.ContainsKey('Literal') | Should -BeFalse
        Set-AiMock -Mock $script:main -Mode 'ollama'
        $port = $script:main.Port
        $g = & (Get-Module TCPK) { param($p) Invoke-TcpkAiHttpGet -Address ([System.Net.IPAddress]::Loopback) -Port $p -Path '/api/tags' -TimeoutMs 2000 } $port
        $g.Status | Should -Be 200
        $g.ContainsKey('BodyBytes') | Should -BeFalse
    }

    It 'is exported and documents exactly the requests it sends' {
        Get-Command Confirm-TcpkAiInferenceServer -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
        $help = (Get-Command Confirm-TcpkAiInferenceServer).ScriptBlock.ToString()
        foreach ($p in '/api/tags', '/v1/models', '/api/version', 'foreign Origin', 'foreign Host', 'never followed', 'no proxy') {
            $help | Should -Match ([regex]::Escape($p))
        }
        $paths = & (Get-Module TCPK) { @($script:TcpkAiProbePaths) }
        ($paths -join ' ') | Should -Be '/ /api/version /api/tags /v1/models'
    }

    It 'sends six credential-free GET requests to a proven Ollama, and nothing else in any case above' {
        # The longest exchange there is: both routes, the banner, the version, both variants.
        Set-AiMock -Mock $script:main -Mode 'ollama' -Version '0.1.33' -Guard 'none'
        $null = Invoke-AiConfirm
        $log = @(Get-AiLog $script:main)
        $log.Count | Should -Be 6
        (($log | ForEach-Object { ($_ -split '\|')[0] }) -join ', ') | Should -Be 'GET /api/tags, GET /v1/models, GET /, GET /api/version, GET /api/tags, GET /api/tags'

        # Every request either listener has received since the file started, this run included.
        $seen = @($script:main.State.All.ToArray()) + @($script:other.State.All.ToArray())
        $seen.Count | Should -BeGreaterThan 5
        $bad = @($seen | Where-Object { $_ -notmatch '^GET (/|/api/version|/api/tags|/v1/models)\|' })
        $bad.Count | Should -Be 0
        @($seen | Where-Object { $_ -notmatch '\|auth=$' }).Count | Should -Be 0
    }

    It 'refuses to run, and sends nothing, without Enable-TcpkExploit' {
        Set-AiMock -Mock $script:main -Mode 'ollama'
        Disable-TcpkExploit | Out-Null
        try {
            { Confirm-TcpkAiInferenceServer -Endpoint $script:ep } | Should -Throw -ExpectedMessage '*gated*'
            { Confirm-TcpkAiInferenceServer } | Should -Throw -ExpectedMessage '*gated*'
            @(Get-AiLog $script:main).Count | Should -Be 0
        } finally {
            Enable-TcpkExploit -Acknowledge | Out-Null
        }
    }
}

Describe 'Confirm-TcpkAiInferenceServer: text taken from the listener' {

    It 'removes user-info from a redirect target up to the last @, in every slash form' {
        InModuleScope TCPK {
            Get-TcpkAiSafeLocation -Text 'https://svc:Winter@2026pw@idp.example/login' | Should -Be 'https://idp.example/login'
            Get-TcpkAiSafeLocation -Text 'https:\\svc:pw@idp.example\login'           | Should -Be 'https://idp.example/login'
            Get-TcpkAiSafeLocation -Text 'https:///svc:pw@idp.example/x'               | Should -Not -Match 'svc|pw@'
        }
    }

    It 'masks the authority when a password is cut short by a query or fragment mark' {
        InModuleScope TCPK {
            $r = Get-TcpkAiSafeLocation -Text 'https://svc:pa?ss@idp.example/x'
            $r | Should -Not -Match 'svc|pa'
            $r | Should -Match '<masked>'
        }
    }

    It 'leaves a plain host, a host with a port and an IPv6 literal unchanged' {
        InModuleScope TCPK {
            Get-TcpkAiSafeLocation -Text 'https://idp.example:8443/sso' | Should -Be 'https://idp.example:8443/sso'
            Get-TcpkAiSafeLocation -Text 'http://[::1]:8080/a'          | Should -Be 'http://[::1]:8080/a'
        }
    }

    It 'does not count a plain REST collection at /v1/models as a model list' {
        InModuleScope TCPK {
            $plain = Get-TcpkAiModelList -Body '{"data":[{"id":"a1"},{"id":"a2"}]}' -Route '/v1/models'
            $plain.Shape | Should -Be 'unmarked-list'
            (Test-TcpkAiListAccepted -List $plain -Route '/v1/models') | Should -BeFalse
        }
    }

    It 'counts /v1/models when the body or an entry carries the list or model marker' {
        InModuleScope TCPK {
            $a = Get-TcpkAiModelList -Body '{"object":"list","data":[{"id":"m1"}]}' -Route '/v1/models'
            $b = Get-TcpkAiModelList -Body '{"data":[{"id":"m1","object":"model"}]}' -Route '/v1/models'
            (Test-TcpkAiListAccepted -List $a -Route '/v1/models') | Should -BeTrue
            (Test-TcpkAiListAccepted -List $b -Route '/v1/models') | Should -BeTrue
        }
    }

    It 'prints display-name and file-path model ids as sent, and replaces markup with _' {
        InModuleScope TCPK {
            Get-TcpkAiSafeName -Text 'Mistral Instruct (7B)' | Should -Be 'Mistral Instruct (7B)'
            Get-TcpkAiSafeName -Text 'C:\models\phi-3.gguf'  | Should -Be 'C:\models\phi-3.gguf'
            Get-TcpkAiSafeName -Text 'evil<script>|x'        | Should -Be 'evil_script__x'
        }
    }
}
