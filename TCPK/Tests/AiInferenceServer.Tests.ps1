#requires -Version 5.1
# Pester 5: Test-TcpkAiInferenceServer (F13), the STATIC detector for a local LLM inference
# server shipped inside the audited target.
#
# The check separates three roles: a server (a listener for a model API), an in-process
# engine library, and a client of a separately installed server. Only the server is a
# weakness. Every fixture is built at run time under the temp folder. Most are a few lines of
# text in a file with a PE or config extension, which is all a string scan reads; the cases
# that depend on encoding (UTF-16 literals of a managed assembly, raw bytes) write bytes.
#
# The first Describe holds one positive and one negative case per rule. The second holds one
# regression case per defect an independent review proved in the first version of the check.
# The third holds one per defect a second review proved in the reworked version; its
# compiled-assembly cases build a real .NET assembly, because a managed PE keeps a member
# name and a string literal in different heaps and source text in a .dll does not show that.

BeforeAll {
    Import-Module (Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1') -Force
    $script:root = Join-Path ([IO.Path]::GetTempPath()) ('tcpk-ais-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:root | Out-Null

    # One scan root. Keys are file names relative to it, with '/' between folders; values are
    # text (written as UTF-8 without a byte order mark) or a byte array.
    function New-AiTree([hashtable]$Files) {
        $p = Join-Path $script:root ([guid]::NewGuid().ToString('N').Substring(0, 8))
        New-Item -ItemType Directory -Path $p -Force | Out-Null
        foreach ($name in $Files.Keys) {
            $full = $p
            foreach ($seg in ($name -split '/')) { $full = Join-Path $full $seg }
            $dir = Split-Path -Parent $full
            if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
            $v = $Files[$name]
            if ($v -is [byte[]]) { [IO.File]::WriteAllBytes($full, $v) }
            else { [IO.File]::WriteAllBytes($full, [Text.Encoding]::UTF8.GetBytes([string]$v)) }
        }
        return $p
    }
    # Always wrap the result of these in @(): one finding comes back as a scalar.
    function Get-AiFindings([string]$p) { Test-TcpkAiInferenceServer -Path $p 6>$null }
    function Get-AiRules([string]$p)    { Test-TcpkAiInferenceServer -Path $p 6>$null | ForEach-Object { $_.RuleId } }
    function Get-AiServer([string]$p) {
        Test-TcpkAiInferenceServer -Path $p 6>$null |
            Where-Object { $_.RuleId -eq 'aiserver.bind-all-interfaces' -or $_.RuleId -eq 'aiserver.local-server' }
    }

    # Three distinct C API symbols of the tensor / model runtime, as a native DLL exports them.
    $script:EngineLib = "ggml_init`0ggml_free`0ggml_new_tensor_1d`0llama_model_load_from_file`0"
}
AfterAll { if ($script:root -and (Test-Path $script:root)) { Remove-Item $script:root -Recurse -Force -ErrorAction SilentlyContinue } }

Describe 'Test-TcpkAiInferenceServer rules' {

    Context 'aiserver.bind-all-interfaces' {
        It 'is HIGH when a launcher assigns the engine host variable an all-interfaces address' {
            $p = New-AiTree @{ 'start.bat' = "@echo off`r`nset OLLAMA_HOST=0.0.0.0:11434`r`nbin\ollama.exe serve`r`n" }
            $f = @(Get-AiFindings $p)
            $f.Count         | Should -Be 1
            $f[0].RuleId     | Should -Be 'aiserver.bind-all-interfaces'
            $f[0].Severity   | Should -Be 'HIGH'
            $f[0].Confidence | Should -Be 'Inferred'
            $f[0].Module     | Should -Be 'network'
            $f[0].Cwe        | Should -Contain 'CWE-1327'
            $f[0].Evidence   | Should -Match 'start\.bat: all-interfaces bind OLLAMA_HOST=0\.0\.0\.0:11434 \(engine host variable\)'
            $f[0].AttributionBasis | Should -Be 'established-footprint'
        }

        It 'is not raised when the same variable holds a loopback address' {
            $p = New-AiTree @{ 'start.bat' = "@echo off`r`nset OLLAMA_HOST=127.0.0.1:11434`r`n" }
            @(Get-AiServer $p) | Should -BeNullOrEmpty
        }
    }

    Context 'aiserver.local-server' {
        It 'is MEDIUM for a known engine server binary with no all-interfaces bind' {
            $p = New-AiTree @{ 'bin/llama-server.exe' = 'MZ stub' }
            $f = @(Get-AiFindings $p)
            $f.Count         | Should -Be 1
            $f[0].RuleId     | Should -Be 'aiserver.local-server'
            $f[0].Severity   | Should -Be 'MEDIUM'
            $f[0].Confidence | Should -Be 'Inferred'
            $f[0].Module     | Should -Be 'network'
            $f[0].Cwe        | Should -Contain 'CWE-306'
            $f[0].Title      | Should -Match '^Local LLM inference server shipped in '
            $f[0].Evidence   | Should -Match 'llama-server\.exe: inference server binary by file name'
            $f[0].File       | Should -Match 'llama-server\.exe$'
            $f[0].AttributionBasis | Should -Be 'established-footprint'
        }

        It 'is not raised for a cloud API client that lists local providers' {
            $p = New-AiTree @{ 'AcmeChat.exe' = "Supported backends: OpenAI, LM Studio, Ollama, Azure`nhttps://api.openai.com/v1/chat/completions`n" }
            @(Get-AiFindings $p) | Should -BeNullOrEmpty
        }
    }

    Context 'aiserver.engine-library' {
        It 'is one INFO inventory record for in-process engine libraries' {
            $p = New-AiTree @{ 'lib/ggml-base.dll' = $script:EngineLib; 'lib/llama.dll' = $script:EngineLib }
            $f = @(Get-AiFindings $p)
            $f.Count       | Should -Be 1
            $f[0].RuleId   | Should -Be 'aiserver.engine-library'
            $f[0].Severity | Should -Be 'INFO'
            $f[0].Title    | Should -Match '\(2 file\(s\)\)'
            $f[0].Title    | Should -Not -Match '(?i)server'
            $f[0].Evidence | Should -Match 'ggml-base\.dll, llama\.dll'
            @($f[0].Affected).Count | Should -Be 2
            $f[0].AttributionBasis  | Should -Be 'established-footprint'
        }

        It 'is not raised for a model file name with no engine API symbols' {
            $p = New-AiTree @{ 'Dictation.dll' = "whisper_init_from_file_with_params`nmodels/ggml-base.en.bin`nwhisper_full`n" }
            @(Get-AiFindings $p) | Should -BeNullOrEmpty
        }
    }

    Context 'aiserver.local-llm-client' {
        It 'is one INFO record for a concrete loopback inference endpoint' {
            $p = New-AiTree @{ 'App.Core.dll' = 'var url = "http://localhost:11434/api/generate"; // call the user-installed Ollama' }
            $f = @(Get-AiFindings $p)
            $f.Count       | Should -Be 1
            $f[0].RuleId   | Should -Be 'aiserver.local-llm-client'
            $f[0].Severity | Should -Be 'INFO'
            $f[0].Evidence | Should -Match 'http://localhost:11434 \(Ollama default port\)'
            # The server it points at is not part of the target: a string match, not attribution.
            $f[0].AttributionBasis | Should -Be 'name-match-only'
        }

        It 'is not raised for a product name with no endpoint' {
            $p = New-AiTree @{ 'AcmeNotes.Core.dll' = "AcmeNotes.Settings.AiProvider`nOpenAI`nAnthropic`nOllama`nAzureOpenAI`n" }
            @(Get-AiFindings $p) | Should -BeNullOrEmpty
        }

        It 'is not raised when the scan root also holds the server' {
            $p = New-AiTree @{ 'bin/ollama.exe' = 'MZ stub'; 'App.Core.dll' = 'Ollama base http://localhost:11434' }
            $rules = @(Get-AiRules $p)
            $rules | Should -Contain 'aiserver.local-server'
            $rules | Should -Not -Contain 'aiserver.local-llm-client'
        }

        It 'is not raised for a loopback URL on an inference port that leads somewhere else' {
            $p = New-AiTree @{ 'App.dll' = "LM Studio`nredirect_uri=http://localhost:1234/callback`n" }
            @(Get-AiFindings $p) | Should -BeNullOrEmpty
        }
    }
}

Describe 'Test-TcpkAiInferenceServer regressions' {

    # aiserver-wildcard-host-as-bind, aiserver-high-wildcard-url-fp
    It 'does not read a wildcard domain as a bind: <Name>' -ForEach @(
        @{ Name = 'CSP source';           Text = "app talks to ollama when installed`nContent-Security-Policy: connect-src https://*.example.com`n" }
        @{ Name = 'endpoint pattern';     Text = "Provider: Ollama`nAzureEndpointPattern=https://*.openai.azure.com`n" }
        @{ Name = 'match pattern';        Text = "ollama`nhttp://*/*`n" }
        @{ Name = 'wildcard with a port'; Text = "ollama`nhttp://*.example.com:11434/`n" }
    ) {
        $p = New-AiTree @{ 'App.Core.dll' = $Text }
        @(Get-AiFindings $p) | Should -BeNullOrEmpty
    }

    It 'does not read a wildcard domain as a bind in the UTF-16 literals of a managed assembly' {
        $bytes = [byte[]]([byte[]](0x4D, 0x5A, 0x90, 0x00) + [Text.Encoding]::Unicode.GetBytes("Provider: Ollama`0https://*.acme.example.com`0"))
        $p = New-AiTree @{ 'AcmeNotes.Core.dll' = $bytes }
        @(Get-AiFindings $p) | Should -BeNullOrEmpty
    }

    # aiserver-port-substring-escalation, aiserver-high-port-substring-fp
    It 'matches the port exactly: <Port> is not an inference port' -ForEach @(
        @{ Port = '12345' }
        @{ Port = '51234' }
        @{ Port = '13370' }
        @{ Port = '8080' }
    ) {
        $p = New-AiTree @{ 'AcmeWriter.exe' = "POST /v1/chat/completions`nlistener prefix http://0.0.0.0:$Port/`n" }
        @(Get-AiFindings $p) | Should -BeNullOrEmpty
    }

    It 'does not rate an inference-port address that is text in a compiled file' {
        # A string in a compiled file can be a message or a help screen. It is never rated
        # and never establishes a server by itself.
        $p = New-AiTree @{ 'AcmeWriter.exe' = "POST /v1/chat/completions`nlistener prefix http://0.0.0.0:11434/`n" }
        @(Get-AiFindings $p) | Should -BeNullOrEmpty
    }

    # aiserver-first-bind-only, aiserver-first-match-only-fn
    It 'inspects every bind, whatever comes first: <Name>' -ForEach @(
        @{ Name = 'unrelated bind first';  Text = "/api/generate`nhealth: http://0.0.0.0:8080/healthz`nlisten: http://0.0.0.0:11434`n" }
        @{ Name = 'inference bind first';  Text = "/api/generate`nlisten: http://0.0.0.0:11434`nhealth: http://0.0.0.0:8080/healthz`n" }
        @{ Name = 'wildcard domain first'; Text = "cors: https://*.example.com`n/api/generate`nlisten: http://0.0.0.0:11434`nhealth: http://0.0.0.0:8080/healthz`n" }
    ) {
        # A configuration file next to the server binary: every address in it is looked at.
        $p = New-AiTree @{ 'server.ini' = $Text; 'bin/ollama.exe' = 'MZ stub' }
        $f = @(Get-AiFindings $p)
        $f.Count       | Should -Be 1
        $f[0].RuleId   | Should -Be 'aiserver.bind-all-interfaces'
        $f[0].Evidence | Should -Match 'all-interfaces bind http://0\.0\.0\.0:11434 on the Ollama default port'
        $f[0].Evidence | Should -Match 'not rated: http://0\.0\.0\.0:8080'
    }

    # aiserver-client-flagged-as-bundled-server
    It 'does not call a client a server: <Name>' -ForEach @(
        @{ Name = 'URL to a user-installed engine'; Text = 'var url = "http://localhost:11434/api/generate"; // call the user-installed Ollama' }
        @{ Name = 'cloud API with an OAuth loopback redirect'; Text = "POST https://api.openai.com/v1/chat/completions`nredirect_uri=http://localhost:8400/callback`n" }
        @{ Name = 'speech-to-text model file name'; Text = 'whisper.cpp speech-to-text: ggml-base.en.bin' }
        @{ Name = 'one bare route'; Text = 'route /api/tags only' }
        @{ Name = 'engine client package with its routes as bare literals'; Text = "github.com/ollama/ollama/api`0/api/generate`0/api/chat`0/api/tags`0/api/show`0OLLAMA_HOST`0" }
        @{ Name = 'HTTP client calls on a model API'; Text = 'const c = axios.create({baseURL: u}); c.post("/v1/chat/completions", b); client.post("/v1/embeddings", b); const n = "ollama";' }
    ) {
        $p = New-AiTree @{ 'App.Core.dll' = $Text }
        @(Get-AiServer $p) | Should -BeNullOrEmpty
    }

    # aiserver-evidence-duplicate-markers
    It 'names a marker once in Evidence, whatever its casing in the file' {
        $p = New-AiTree @{ 'Chat.dll' = "GPT4All gpt4all Gpt4All backend`n/v1/chat/completions`n/v1/models`n/v1/models/<arg>`n" }
        $f = @(Get-AiServer $p)
        $f.Count | Should -Be 1
        $f[0].Evidence | Should -Match 'with marker gpt4all and router path parameter /v1/models/<arg>'
        ([regex]::Matches($f[0].Evidence, '(?i)gpt4all')).Count | Should -Be 1
    }

    It 'emits nothing for product names with no listener form' {
        $p = New-AiTree @{ 'App.Core.dll' = 'gpt4all backend; AnythingLLM workspace' }
        @(Get-AiFindings $p) | Should -BeNullOrEmpty
    }

    # aiserver-client-only-fp
    It 'emits nothing for a provider name: <Name>' -ForEach @(
        @{ Name = 'provider drop-down';  File = 'TCPK.exe';     Text = "ollama (local)`0claude`0openai`0deepseek`0custom`0" }
        @{ Name = 'provider enum';       File = 'Notes.dll';    Text = "Provider: Ollama`nOpenAI / Anthropic / Ollama / AzureOpenAI`n" }
        @{ Name = 'backend option';      File = 'AcmeChat.exe'; Text = "Supported backends: OpenAI, LM Studio, Azure`nhttps://api.openai.com/v1/chat/completions`n" }
    ) {
        $p = New-AiTree @{ $File = $Text }
        @(Get-AiFindings $p) | Should -BeNullOrEmpty
    }

    # aiserver-ggml-random-bytes-fp
    It 'does not match a short marker in raw bytes: <Name>' -ForEach @(
        @{ Name = 'Ggml'; Bytes = [byte[]](0x00, 0x9f, 0x12, 0x47, 0x67, 0x6d, 0x6c, 0x08, 0x01, 0xfe) }
        @{ Name = 'gGMl'; Bytes = [byte[]](0x00, 0x9f, 0x12, 0x67, 0x47, 0x4d, 0x6c, 0x08, 0x01, 0xfe) }
    ) {
        $p = New-AiTree @{ 'Payload.dll' = $Bytes }
        @(Get-AiFindings $p) | Should -BeNullOrEmpty
    }

    # aiserver-ollama-routes-generic-fp
    It 'does not match a route inside another REST path: <Url>' -ForEach @(
        @{ Url = 'https://teamtalk.example.com/api/chat/rooms' }
        @{ Url = 'GET https://cms.example.com/api/tags?post=42' }
        @{ Url = 'https://tv.example.com/api/shows/today' }
        @{ Url = 'https://git.example.com/api/pullrequests/17/merge' }
        @{ Url = 'https://dcim.example.com/api/psu/status' }
        @{ Url = 'https://erp.example.com/api/generateReport?id=7' }
    ) {
        $p = New-AiTree @{ 'Client.dll' = $Url }
        @(Get-AiFindings $p) | Should -BeNullOrEmpty
    }

    # aiserver-high-unrelated-listener-fp
    It 'does not tie an unrelated all-interfaces listener to a product name in the same file' {
        $p = New-AiTree @{ 'AcmeNotes.Core.dll' = "Provider: Ollama`nMetricsExporter.Listen(http://0.0.0.0:9464/metrics)`n" }
        @(Get-AiFindings $p) | Should -BeNullOrEmpty
    }

    # aiserver-openai-localhost-corroboration-fp
    It 'does not take a localhost URL as proof of a server: <Name>' -ForEach @(
        @{ Name = 'OAuth loopback redirect';      Text = "https://api.openai.com/v1/chat/completions`nhttp://localhost/oauth2/callback`n" }
        @{ Name = 'health URL on another port';   Text = "https://api.acme-cad.example.com/v1/models/list`nhttp://127.0.0.1:5000/health`n" }
        @{ Name = 'host name that starts alike';  Text = "https://api.openai.com/v1/models`nhttps://localhost.acme-cdn.example/assets`n" }
    ) {
        $p = New-AiTree @{ 'AcmeWriter.exe' = $Text }
        @(Get-AiFindings $p) | Should -BeNullOrEmpty
    }

    # aiserver-port-regex-identity-fp
    It 'matches a port only in a host:port context: <Name>' -ForEach @(
        @{ Name = 'JSON value';             Text = "https://api.openai.com/v1/chat/completions`n{`"retry`":3,`"maxTokens`":1234,`"model`":`"gpt-4o`"}`n" }
        @{ Name = 'port on another host';   Text = "https://api.openai.com/v1/chat/completions`nws://devtools.example.com:3001/hmr`n" }
        @{ Name = 'IPv6 group';             Text = "https://api.openai.com/v1/models`nfallback dns 2001:db8:1234::53`n" }
    ) {
        $p = New-AiTree @{ 'AcmeWriter.exe' = $Text }
        @(Get-AiFindings $p) | Should -BeNullOrEmpty
    }

    It 'names the product of a port only when that product marker is in the file' {
        $srv = 'const app=require("express")(); app.post("/v1/chat/completions", h); app.listen(11434, "127.0.0.1");'
        $plain = New-AiTree @{ 'resources/app/main.js' = $srv; 'server.ini' = "[llm]`r`nhost = 0.0.0.0`r`nport = 11434`r`n" }
        $named = New-AiTree @{ 'resources/app/main.js' = $srv; 'server.ini' = "[ollama]`r`nhost = 0.0.0.0`r`nport = 11434`r`n" }
        $a = @(Get-AiServer $plain)
        $b = @(Get-AiServer $named)
        $a.Count | Should -Be 1
        $b.Count | Should -Be 1
        $a[0].Evidence | Should -Match 'host=0\.0\.0\.0 port=11434 on a known inference port'
        $a[0].Evidence | Should -Not -Match '(?i)ollama'
        $b[0].Evidence | Should -Match 'host=0\.0\.0\.0 port=11434 on the Ollama default port'
    }

    It 'does not tie a development port to a model API on a bare route: port <Port>' -ForEach @(
        @{ Port = '1234' }
        @{ Port = '1337' }
        @{ Port = '3001' }
        @{ Port = '4891' }
    ) {
        # These numbers are ordinary development ports and a client holds the route too.
        $p = New-AiTree @{ 'App.dll' = "/v1/chat/completions`nhttp://0.0.0.0:$Port`n" }
        @(Get-AiFindings $p) | Should -BeNullOrEmpty
    }

    # aiserver-engine-library-fanout
    It 'reports one server finding and one library record per scan root, not one per file' {
        $p = New-AiTree @{
            'ollama.exe'                 = 'MZ stub'
            'lib/ollama/llama-server.exe' = 'MZ stub'
            'lib/ollama/ggml-base.dll'   = $script:EngineLib
            'lib/ollama/ggml-cpu.dll'    = $script:EngineLib
            'lib/ollama/llama.dll'       = $script:EngineLib
        }
        $f = @(Get-AiFindings $p)
        $f.Count | Should -Be 2
        $srv = @($f | Where-Object { $_.RuleId -eq 'aiserver.local-server' })
        $lib = @($f | Where-Object { $_.RuleId -eq 'aiserver.engine-library' })
        $srv.Count | Should -Be 1
        $lib.Count | Should -Be 1
        $srv[0].Evidence | Should -Match 'server evidence in 2 file\(s\)'
        $srv[0].Evidence | Should -Match 'ollama\.exe: inference server binary by file name'
        $srv[0].Evidence | Should -Match 'llama-server\.exe: inference server binary by file name'
        @($srv[0].Affected).Count | Should -Be 2
        # The shallowest server file is the one the finding is filed under.
        $srv[0].File  | Should -Match '[\\/]ollama\.exe$'
        $lib[0].Title | Should -Match '\(3 file\(s\)\)'
        $lib[0].Severity | Should -Be 'INFO'
    }

    # aiserver-js-asar-config-fn
    It 'reads the server from an .asar archive' {
        $p = New-AiTree @{ 'resources/app.asar' = 'const app = require("express")(); app.post("/v1/chat/completions", h); app.get("/api/tags", t); app.listen(3001, "0.0.0.0");' }
        $f = @(Get-AiServer $p)
        $f.Count | Should -Be 1
        $f[0].RuleId   | Should -Be 'aiserver.bind-all-interfaces'
        $f[0].Evidence | Should -Match 'app\.asar: all-interfaces listen call \.listen\(3001, 0\.0\.0\.0\) on a known inference port'
        $f[0].Evidence | Should -Match 'model API route registration app\.post\("/v1/chat/completions"\)'
    }

    It 'reads the server from loose JavaScript in an unpacked app tree' {
        $p = New-AiTree @{ 'resources/app/.webpack/main/index.js' = 'const r=["/v1/chat/completions","/v1/models","/api/v0/models/:model(*)"];const n="LM Studio";const u="ws://127.0.0.1:1234";' }
        $f = @(Get-AiServer $p)
        $f.Count | Should -Be 1
        $f[0].RuleId   | Should -Be 'aiserver.local-server'
        $f[0].File     | Should -Match 'index\.js$'
        $f[0].Evidence | Should -Match 'index\.js: model API routes /v1/chat/completions, /v1/models with marker lm studio and router path parameter /api/v0/models/:model'
        $f[0].Evidence | Should -Match 'loopback endpoint ws://127\.0\.0\.1:1234 \(LM Studio default port\)'
    }

    It 'reads the bind from configuration files and names each file once' {
        $p = New-AiTree @{
            '.env'                    = "OLLAMA_HOST=0.0.0.0:11434`n"
            'resources/settings.json' = '{"host":"0.0.0.0","port":3001}'
            'resources/app.asar'      = 'const app = require("express")(); app.post("/v1/chat/completions", h); app.listen(3001, "0.0.0.0");'
        }
        $f = @(Get-AiFindings $p)
        $f.Count | Should -Be 1
        $f[0].RuleId   | Should -Be 'aiserver.bind-all-interfaces'
        $f[0].Evidence | Should -Match 'server evidence in 3 file\(s\)'
        $f[0].Evidence | Should -Match '\.env: all-interfaces bind OLLAMA_HOST=0\.0\.0\.0:11434'
        # The settings file ties nothing by itself: its port is the one the archive serves.
        $f[0].Evidence | Should -Match 'settings\.json: all-interfaces bind host=0\.0\.0\.0 port=3001 on a known inference port \(a server on that port is established elsewhere under the scan root\)'
        $f[0].Evidence | Should -Match 'app\.asar: all-interfaces listen call'
        @($f[0].Affected).Count | Should -Be 3
    }

    It 'ignores script and configuration that is not the product''s own: <Name>' -ForEach @(
        @{ Name = 'third-party package';      File = 'resources/app/node_modules/srv/index.js'; Text = 'app.post("/v1/chat/completions", h); app.listen(11434, "0.0.0.0"); // ollama' }
        @{ Name = 'commented-out script';     File = 'resources/app/main.js';                   Text = "// app.listen(11434, `"0.0.0.0`"); ollama`nconst x = 1;`n" }
        @{ Name = 'commented-out variable';   File = '.env';                                    Text = "# OLLAMA_HOST=0.0.0.0:11434`n" }
        @{ Name = 'commented-out XML';        File = 'App.exe.config';                          Text = '<configuration><!-- <add key="OllamaEndpoint" value="0.0.0.0:11434" /> --></configuration>' }
        @{ Name = 'batch @rem line';          File = 'run.bat';                                 Text = "@echo off`r`n@rem set OLLAMA_HOST=0.0.0.0`r`n" }
        @{ Name = 'JSON block comment';       File = 'config/settings.json';                    Text = "{`n  /* to expose on the LAN:`n     `"OLLAMA_HOST`": `"0.0.0.0:11434`",`n  */`n  `"theme`": `"dark`"`n}`n" }
        @{ Name = 'configuration template';   File = 'config/settings.example.json';            Text = '{"ollama":{"host":"0.0.0.0","port":11434}}' }
        @{ Name = 'test file';                File = 'resources/app/server.test.js';            Text = 'app.post("/v1/chat/completions", h); app.listen(11434, "0.0.0.0"); // ollama' }
    ) {
        $p = New-AiTree @{ $File = $Text }
        @(Get-AiFindings $p) | Should -BeNullOrEmpty
    }

    # aiserver-bind-nonurl-fn
    It 'recognises the bind form: <Name>' -ForEach @(
        @{ Name = 'host variable without a port';     File = 'run.cmd';        Text = 'set OLLAMA_HOST=0.0.0.0';                                              Expect = 'OLLAMA_HOST=0\.0\.0\.0 \(engine host variable\)' }
        @{ Name = 'host variable in a JSON env block'; File = 'env.json';      Text = '{"env":{"OLLAMA_HOST":"0.0.0.0:11434"}}';                               Expect = 'OLLAMA_HOST=0\.0\.0\.0:11434 \(engine host variable; the ollama server binary is under the scan root\)' }
        @{ Name = 'host variable set with setx';      File = 'install.cmd';    Text = 'setx OLLAMA_HOST 0.0.0.0 /M';                                           Expect = 'OLLAMA_HOST=0\.0\.0\.0 \(engine host variable\)' }
        @{ Name = 'host variable set from script';    File = 'setup.ps1';      Text = '[Environment]::SetEnvironmentVariable("OLLAMA_HOST", "0.0.0.0:11434", "User")'; Expect = 'OLLAMA_HOST=0\.0\.0\.0:11434' }
        @{ Name = 'host variable in an appSettings entry'; File = 'Launcher.exe.config'; Text = '<appSettings><add key="OLLAMA_HOST" value="0.0.0.0" /></appSettings>'; Expect = 'OLLAMA_HOST=0\.0\.0\.0 \(engine host variable\)' }
        @{ Name = 'host variable set on the process environment'; File = 'resources/app/main.js'; Text = 'process.env["OLLAMA_HOST"] = "0.0.0.0:11434"; spawn(ollamaPath, ["serve"]);'; Expect = 'OLLAMA_HOST=0\.0\.0\.0:11434 \(engine host variable; the ollama server binary is under the scan root\)' }
        @{ Name = 'llama.cpp server host variable';   File = 'server.env';     Text = "LLAMA_ARG_HOST=0.0.0.0`nLLAMA_ARG_PORT=8080`n";                         Expect = 'LLAMA_ARG_HOST=0\.0\.0\.0 \(engine host variable\)' }
        @{ Name = 'engine host flag after the port';  File = 'run.cmd';        Text = 'llama-server.exe -m a.gguf --port 8081 --host 0.0.0.0';                 Expect = 'llama-server --host 0\.0\.0\.0 \(engine host flag\)' }
        @{ Name = 'engine host flag in an argument array'; File = 'launch.json'; Text = '{"cmd":["bin/llama-server.exe","--host","0.0.0.0","--port","8080"]}'; Expect = 'llama-server --host 0\.0\.0\.0 \(engine host flag; the llama\.cpp server binary is under the scan root\)' }
        @{ Name = 'scheme-less host:port';            File = 'App.exe.config'; Text = '<add key="OllamaEndpoint" value="0.0.0.0:11434" />';                    Expect = 'all-interfaces bind 0\.0\.0\.0:11434 on the Ollama default port' }
        @{ Name = 'host / port pair';                 File = 'server.ini';     Text = "[ollama]`r`nhost = 0.0.0.0`r`nport = 11434`r`n";                         Expect = 'host=0\.0\.0\.0 port=11434 on the Ollama default port' }
    ) {
        # The engines' server binaries are under the root. A setting in a launcher or
        # classic configuration file counts by itself; in a script bundle or a JSON file,
        # and for an address on a port, it counts only next to the server it is for.
        $p = New-AiTree @{ $File = $Text; 'bin/ollama.exe' = 'MZ stub'; 'bin/llama-server.exe' = 'MZ stub' }
        $f = @(Get-AiServer $p)
        $f.Count | Should -Be 1
        $f[0].RuleId   | Should -Be 'aiserver.bind-all-interfaces'
        $f[0].Severity | Should -Be 'HIGH'
        $f[0].Evidence | Should -Match $Expect
    }

    It 'never rates a bind form that is text in a compiled file: <Name>' -ForEach @(
        @{ Name = 'host variable as a URL';  File = 'App.Core.dll'; Text = "POST /v1/chat/completions`nOLLAMA_HOST=http://0.0.0.0:11434`n" }
        @{ Name = 'engine host flag';        File = 'Launcher.exe'; Text = 'llama-server.exe --host 0.0.0.0 --port 8080 -m model.gguf' }
        @{ Name = 'IPv6 all-interfaces URL'; File = 'Engine.dll';   Text = "ollama serve`nhttp://[::]:11434/`n" }
    ) {
        @(Get-AiServer (New-AiTree @{ $File = $Text })) | Should -BeNullOrEmpty
        # Next to the server binaries the server is reported, and the text does not rate it.
        $f = @(Get-AiServer (New-AiTree @{ $File = $Text; 'bin/ollama.exe' = 'MZ stub'; 'bin/llama-server.exe' = 'MZ stub' }))
        $f.Count | Should -Be 1
        $f[0].RuleId   | Should -Be 'aiserver.local-server'
        $f[0].Severity | Should -Be 'MEDIUM'
    }

    It 'does not read these as an inference bind: <Name>' -ForEach @(
        @{ Name = 'host flag with no engine on the line';  File = 'package.json'; Text = '{"scripts":{"dev":"vite --host 0.0.0.0 --port 3001"}}' }
        @{ Name = 'help text for the flag';                File = 'cli.dll';      Text = 'usage: llama-server --host HOST --port PORT' }
        @{ Name = 'bind on an inference port with nothing that ties it to a model API'; File = 'App.dll'; Text = 'listener http://0.0.0.0:11434/' }
        @{ Name = 'host variable name and an address as two adjacent literals'; File = 'tool.exe'; Text = "Run a model`0List models`0OLLAMA_HOST0.0.0.0:8000`0" }
        @{ Name = 'all-interfaces HTTPS prefix next to a route'; File = 'App.dll'; Text = "https://+:443/`n/v1/chat/completions`n" }
    ) {
        $p = New-AiTree @{ $File = $Text }
        @(Get-AiFindings $p) | Should -BeNullOrEmpty
    }

    It 'looks at every host flag on a line, not only the first' {
        $p = New-AiTree @{ 'run.cmd' = 'llama-server.exe --host 127.0.0.1 --port 8080 & llama-server.exe -m b.gguf --port 8081 --host 0.0.0.0' }
        $f = @(Get-AiServer $p)
        $f.Count | Should -Be 1
        $f[0].RuleId   | Should -Be 'aiserver.bind-all-interfaces'
        $f[0].Evidence | Should -Match 'llama-server --host 0\.0\.0\.0 \(engine host flag\)'
        $f[0].Evidence | Should -Match 'engine server launch llama-server --host 127\.0\.0\.1'
    }

    It 'rates a listen call with no host argument MEDIUM and says what the file shows' {
        $p = New-AiTree @{ 'resources/app/main.js' = 'const n = "LM Studio"; app.post("/v1/chat/completions", h); server.listen(1234);' }
        $f = @(Get-AiServer $p)
        $f.Count | Should -Be 1
        $f[0].RuleId   | Should -Be 'aiserver.local-server'
        $f[0].Evidence | Should -Match 'listen call \.listen\(1234\) on the LM Studio default port, no host argument'
    }

    It 'ties a bare bind on a product port to that product''s server elsewhere under the root' {
        $with = New-AiTree @{ 'bin/ollama.exe' = 'MZ stub'; 'config/settings.json' = '{"server":{"host":"0.0.0.0","port":11434}}' }
        $other = New-AiTree @{ 'bin/ollama.exe' = 'MZ stub'; 'config/settings.json' = '{"server":{"host":"0.0.0.0","port":1234}}' }
        $alone = New-AiTree @{ 'config/settings.json' = '{"server":{"host":"0.0.0.0","port":11434}}' }

        $a = @(Get-AiServer $with)
        $a.Count | Should -Be 1
        $a[0].RuleId   | Should -Be 'aiserver.bind-all-interfaces'
        $a[0].Evidence | Should -Match 'settings\.json: all-interfaces bind host=0\.0\.0\.0 port=11434 on the Ollama default port'

        # Another product's port is not this server's bind.
        $b = @(Get-AiServer $other)
        $b.Count | Should -Be 1
        $b[0].RuleId   | Should -Be 'aiserver.local-server'
        $b[0].Evidence | Should -Not -Match '1234'

        @(Get-AiFindings $alone) | Should -BeNullOrEmpty
    }

    It 'finds a bind held as a UTF-16 literal at either byte alignment' {
        $wide = [Text.Encoding]::Unicode.GetBytes("ollama serve`0http://0.0.0.0:11434`0")
        foreach ($head in @([byte[]](0x4D, 0x5A, 0x90, 0x00), [byte[]](0x4D, 0x5A, 0x90, 0x00, 0x03))) {
            $p = New-AiTree @{ 'Engine.dll' = ([byte[]]($head + $wide)) }
            # The reader sees the literal at either alignment ...
            $read = & (Get-Module TCPK) { param($f) Read-TcpkAiFileSignals -Path $f -Kind 'pe' } (Join-Path $p 'Engine.dll')
            (@($read.Acc.Binds.Keys) -join ' ') | Should -Match 'http://0\.0\.0\.0:11434'
            $read.Acc.Markers.ContainsKey('ollama') | Should -BeTrue
            # ... and, being text in a compiled file, it is not rated.
            @(Get-AiServer $p) | Should -BeNullOrEmpty
        }
    }

    # aiserver-aggregation-drops-evidence
    It 'keeps the bind in Evidence through report aggregation' {
        $p = New-AiTree @{ '.env' = 'OLLAMA_HOST=0.0.0.0:11434'; 'bin/ollama.exe' = 'MZ stub'; 'bin/llama-server.exe' = 'MZ stub'; 'lib/ggml-base.dll' = $script:EngineLib }
        $raw = @(Get-AiFindings $p)
        $agg = @($raw | Resolve-TcpkFindings -AggregateOnly 6>$null)
        $srv = @($agg | Where-Object { $_.RuleId -eq 'aiserver.bind-all-interfaces' })
        $srv.Count | Should -Be 1
        $srv[0].Evidence | Should -Match 'OLLAMA_HOST=0\.0\.0\.0:11434'
        $srv[0].Evidence | Should -Match 'ollama\.exe: inference server binary by file name'
        $srv[0].Title    | Should -Not -Match 'more affected'
    }

    # aiserver-marker-substring-fp
    It 'does not find a marker inside another word: <Word>' -ForEach @(
        @{ Word = 'Acme.Workers.PollAmazonSqsQueue'; Bind = 'http://0.0.0.0:11434'; Loop = 'http://localhost:11434' }
        @{ Word = 'Acme.Devices.EnrollAmazonDevice';  Bind = 'http://0.0.0.0:11434'; Loop = 'http://localhost:11434' }
        @{ Word = 'contact: jan.aiello@example.com'; Bind = 'http://0.0.0.0:1337';  Loop = 'http://localhost:1337' }
        @{ Word = 'Trojan.AIDetectionName';          Bind = 'http://0.0.0.0:1337';  Loop = 'http://localhost:1337' }
    ) {
        # With the product marker either of these lines would be reported. Without it, neither is.
        $p = New-AiTree @{ 'Worker.dll' = "$Word`n$Bind`n$Loop`n" }
        @(Get-AiFindings $p) | Should -BeNullOrEmpty
    }

    It 'finds a marker that is a hump of an identifier' {
        $p = New-AiTree @{ 'Worker.dll' = "OllamaSharp.OllamaApiClient`nhttp://0.0.0.0:11434`n" }
        $read = & (Get-Module TCPK) { param($f) Read-TcpkAiFileSignals -Path $f -Kind 'pe' } (Join-Path $p 'Worker.dll')
        $read.Acc.Markers.ContainsKey('ollama') | Should -BeTrue
    }

    # aiserver-medium-evidence-omits-bind
    It 'shows an all-interfaces bind it could not tie to the inference server' {
        $p = New-AiTree @{ 'LocalAi.Server.dll' = "app.MapPost(`"/v1/chat/completions`"`n`"urls`": `"http://*:5005`"`n" }
        $f = @(Get-AiFindings $p)
        $f.Count | Should -Be 1
        $f[0].RuleId   | Should -Be 'aiserver.local-server'
        $f[0].Severity | Should -Be 'MEDIUM'
        $f[0].Evidence | Should -Match 'model API route registration MapPost\("/v1/chat/completions"\)'
        $f[0].Evidence | Should -Match 'all-interfaces address text seen but not rated: http://\*:5005'
    }

    # aiserver-selfhost-duplicate-conflicting-severity
    It 'carries the observation fields the redundancy classifier keys on' {
        $p = New-AiTree @{ '.env' = 'OLLAMA_HOST=0.0.0.0:11434'; 'bin/ollama.exe' = 'MZ stub' }
        $f = @(Get-AiServer $p)
        $f.Count | Should -Be 1
        $f[0].Dimension | Should -Be 'listener-bind'
        $f[0].Basis     | Should -Be 'Inferred'
        $f[0].ObsValue  | Should -Be '"OLLAMA_HOST=0.0.0.0:11434"'
        $f[0].Subject   | Should -Be $f[0].File
    }

    # aiserver-mcp-missing-category-map, aiserver-no-verify-hint-confirmer-orphaned
    It 'maps the two listener rules to a security category' {
        foreach ($rid in 'aiserver.bind-all-interfaces', 'aiserver.local-server') {
            $c = @(& (Get-Module TCPK) { param($r) Get-TcpkCategoryList -RuleId $r } $rid)
            $c | Should -Contain 'Network Communication'
        }
    }

    It 'points the re-validation step at the live confirmer, with the port from Evidence' {
        $p = New-AiTree @{ '.env' = 'OLLAMA_HOST=0.0.0.0:11434' }
        $f = @(Get-AiServer $p)
        $hint = & (Get-Module TCPK) { param($x) Get-TcpkVerifyHint -RuleId $x.RuleId -File $x.File -Evidence $x.Evidence } $f[0]
        $hint | Should -Match "Confirm-TcpkAiInferenceServer -Endpoint '127\.0\.0\.1:11434'"
        $hint | Should -Not -Match 'Re-run the TCPK check for rule'

        $none = & (Get-Module TCPK) { Get-TcpkVerifyHint -RuleId 'aiserver.local-server' -File 'C:\App\bin\llama-server.exe' -Evidence 'server evidence in 1 file(s) | bin\llama-server.exe: inference server binary by file name' }
        $none | Should -Match "Confirm-TcpkAiInferenceServer -Endpoint '127\.0\.0\.1:<port>'"
    }

    It 'scores the loopback-class lead with a local vector and the all-interfaces one with a network vector' {
        $loop = New-AiTree @{ 'bin/llama-server.exe' = 'MZ stub' }
        $wide = New-AiTree @{ '.env' = 'OLLAMA_HOST=0.0.0.0:11434' }
        $a = @(Get-AiServer $loop)
        $b = @(Get-AiServer $wide)
        (& (Get-Module TCPK) { param($x) Get-TcpkCvssVector -Finding $x } $a[0]).Vector | Should -Match '/AV:L/'
        (& (Get-Module TCPK) { param($x) Get-TcpkCvssVector -Finding $x } $b[0]).Vector | Should -Match '/AV:N/'
    }

    It 'never names a CVE, never prints a credential, and stays ASCII' {
        $secret = 'sk-live-0123456789abcdef0123456789abcdef'
        $trees = @(
            (New-AiTree @{ 'server.env' = "OLLAMA_HOST=0.0.0.0:11434`nOLLAMA_API_KEY=$secret`n" })
            (New-AiTree @{ 'bin/llama-server.exe' = 'MZ stub'; 'lib/ggml.dll' = $script:EngineLib })
            (New-AiTree @{ 'App.dll' = "Ollama`nhttp://localhost:11434/api/generate`napi_key=$secret`n" })
            (New-AiTree @{ 'App.dll' = "http://127.0.0.1:1234/v1/chat/completions/$secret`n" })
        )
        $all = @($trees | ForEach-Object { Get-AiFindings $_ })
        $all.Count | Should -Be 5
        foreach ($f in $all) {
            $text = "$($f.Title) $($f.Description) $($f.Evidence) $($f.Fix)"
            $text | Should -Not -Match 'CVE-\d'
            $text | Should -Not -Match ([regex]::Escape($secret))
            $text | Should -Not -Match '[^\x00-\x7F]'
            $f.Confidence | Should -Be 'Inferred'
        }
        # A model API route on a loopback URL is printed as the route alone.
        ($all | Where-Object { $_.Evidence -match '127\.0\.0\.1:1234' }).Evidence | Should -Match 'http://127\.0\.0\.1:1234/v1/chat/completions \(model API route on a known inference port\)'
    }

    It 'accepts a single file as the scan root' {
        $p = New-AiTree @{ 'launch.cmd' = 'bin\llama-server.exe --host 0.0.0.0 --port 8080'; 'main.js' = 'app.post("/v1/chat/completions", h); server.listen(1234, "127.0.0.1");' }
        (@(Get-AiRules (Join-Path $p 'launch.cmd')) -join ',') | Should -Be 'aiserver.bind-all-interfaces'
        (@(Get-AiRules (Join-Path $p 'main.js')) -join ',')    | Should -Be 'aiserver.local-server'
    }

    It 'returns nothing and does not throw for a path that does not exist' {
        $missing = Join-Path $script:root 'no-such-folder'
        { Test-TcpkAiInferenceServer -Path $missing } | Should -Not -Throw
        @(Test-TcpkAiInferenceServer -Path $missing) | Should -BeNullOrEmpty
    }

    It 'keeps the findings from script and config files when PE enumeration fails' {
        $p = New-AiTree @{ '.env' = 'OLLAMA_HOST=0.0.0.0:11434' }
        Mock -CommandName Get-TcpkPeFiles -ModuleName TCPK -MockWith { throw 'enumeration failed' }
        $r = @(Test-TcpkAiInferenceServer -Path $p 6>$null)
        Should -Invoke -CommandName Get-TcpkPeFiles -ModuleName TCPK -Times 1 -Exactly
        @($r | ForEach-Object { $_.RuleId }) | Should -Contain 'aiserver.bind-all-interfaces'
    }

    It 'stops at the per-check budget and records the shortfall' {
        $p = New-AiTree @{ 'settings.env' = 'OLLAMA_HOST=0.0.0.0:11434' }
        $before = & (Get-Module TCPK) { (Get-TcpkScanStats).BudgetStoppedCount }
        try {
            & (Get-Module TCPK) { $script:TcpkCheckDeadline = (Get-Date).AddSeconds(-5) }
            @(Get-AiFindings $p) | Should -BeNullOrEmpty
        } finally {
            & (Get-Module TCPK) { Clear-TcpkCheckBudget }
        }
        $after = & (Get-Module TCPK) { (Get-TcpkScanStats).BudgetStoppedCount }
        $after | Should -BeGreaterThan $before
        # With no deadline armed the same tree is reported.
        @(Get-AiRules $p) | Should -Contain 'aiserver.bind-all-interfaces'
    }

    It 'reads a configuration file that carries the Hidden attribute' -Skip:($IsWindows -eq $false) {
        $p = New-AiTree @{ 'settings.env' = 'OLLAMA_HOST=0.0.0.0:11434' }
        $file = Get-Item -LiteralPath (Join-Path $p 'settings.env') -Force
        $file.Attributes = $file.Attributes -bor [IO.FileAttributes]::Hidden
        @(Get-AiRules $p) | Should -Contain 'aiserver.bind-all-interfaces'
    }

    It 'is exported and runs in the audit' {
        Get-Command Test-TcpkAiInferenceServer -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
        $moduleRoot = Split-Path (Split-Path $PSCommandPath -Parent) -Parent
        $audit = [IO.File]::ReadAllText((Join-Path (Join-Path $moduleRoot 'Public') 'Invoke-TcpkAudit.ps1'))
        $audit | Should -Match "_RunCheck 'Test-TcpkAiInferenceServer'"
    }
}

Describe 'Test-TcpkAiInferenceServer second-review regressions' {

    BeforeAll {
        # Real managed assemblies, compiled once. The sources stay inside what the C# 5
        # compiler of Windows PowerShell 5.1 accepts. A host that cannot compile leaves
        # AsmOk false and the cases that need an assembly are reported as skipped.
        $script:AsmDir = Join-Path $script:root 'asm'
        New-Item -ItemType Directory -Path $script:AsmDir -Force | Out-Null
        function New-AiAssembly([string]$Name, [string]$Source) {
            $out = Join-Path $script:AsmDir $Name
            Add-Type -TypeDefinition $Source -OutputAssembly $out -OutputType Library -ErrorAction Stop
            # The comma keeps the byte array whole: a bare array is unrolled on return.
            return , ([IO.File]::ReadAllBytes($out))
        }
        $script:AsmOk = $true
        $script:Asm = @{}
        try {
            # A model API server: the mapping member is a name in one heap, each route a
            # UTF-16 literal in another.
            $script:Asm['server'] = New-AiAssembly 'srv.dll' @'
namespace Acme.LocalAi {
  public static class Routes {
    public static void MapPost(object app, string pattern) {}
    public static void MapGet(object app, string pattern) {}
    public static void UseUrls(object app, string urls) {}
  }
  public class Server {
    public static void Run() {
      object app = new object();
      Routes.UseUrls(app, "http://0.0.0.0:8080");
      Routes.MapPost(app, "/v1/chat/completions");
      Routes.MapPost(app, "/v1/completions");
      Routes.MapPost(app, "/v1/embeddings");
      Routes.MapGet(app, "/v1/models");
    }
  }
}
'@
            # A client of somebody else's model API: the same route literals, nothing mapped.
            $script:Asm['client'] = New-AiAssembly 'cli.dll' @'
namespace Acme.Chat {
  public class Client {
    public string BaseUrl = "";
    public string Chat() { return BaseUrl + "/v1/chat/completions"; }
    public string Embed() { return BaseUrl + "/v1/embeddings"; }
  }
}
'@
            # A launcher that names the engine executable and sets its host variable.
            $script:Asm['launcher'] = New-AiAssembly 'lau.dll' @'
using System.Diagnostics;
namespace Acme {
  public class Launcher {
    public static void Start(string dir) {
      ProcessStartInfo psi = new ProcessStartInfo(System.IO.Path.Combine(dir, "ollama.exe"), "serve");
      psi.UseShellExecute = false;
      psi.EnvironmentVariables["OLLAMA_HOST"] = "0.0.0.0";
      Process.Start(psi);
    }
  }
}
'@
            # The same launcher with the executable path handed in from outside.
            $script:Asm['launcher-noexe'] = New-AiAssembly 'lne.dll' @'
using System.Diagnostics;
namespace Acme {
  public class Launcher {
    public static void Start(string exe) {
      ProcessStartInfo psi = new ProcessStartInfo(exe, "serve");
      psi.UseShellExecute = false;
      psi.EnvironmentVariables["OLLAMA_HOST"] = "0.0.0.0";
      Process.Start(psi);
    }
  }
}
'@
            # A client that only reads the variable and compares it: the same two adjacent
            # literals, no member that sets an environment variable.
            $script:Asm['reader'] = New-AiAssembly 'rdr.dll' @'
namespace Acme {
  public class Probe {
    public static bool Exposed() {
      return System.Environment.GetEnvironmentVariable("OLLAMA_HOST") == "0.0.0.0";
    }
  }
}
'@
            # A client whose only relevant literal is a sentence of help text.
            $script:Asm['help'] = New-AiAssembly 'hlp.dll' @'
namespace AcmeChat {
  public class OllamaClient {
    public string BaseUrl = "";
    public string Help() { return "Cannot reach Ollama. If it runs on another machine, start it there with OLLAMA_HOST=0.0.0.0 and enter its address in Settings."; }
    public string Tags() { return BaseUrl + "/api/tags"; }
  }
}
'@
            foreach ($k in @($script:Asm.Keys)) { if ($script:Asm[$k] -isnot [byte[]]) { $script:AsmOk = $false } }
        } catch { $script:AsmOk = $false }
    }

    # aiserver-bind-form-prose-high-fp
    It 'does not read a sentence that quotes a bind form as a bind: <Name>' -ForEach @(
        @{ Name = 'help string in a locale file';     File = 'resources/locales/en.json'; Text = '{"settings.provider.ollama.help": "AcmeChat connects to an Ollama server you run yourself. To reach it from another device, start it with OLLAMA_HOST=0.0.0.0 ollama serve and enter that machine address below."}' }
        @{ Name = 'error message in script';          File = 'resources/app/main.js';     Text = 'function help(){return"Cannot reach Ollama. If it runs in WSL or Docker, set OLLAMA_HOST=0.0.0.0 and restart Ollama, then enter its address in Settings."}' }
        @{ Name = 'help text with the host flag';     File = 'resources/app/main.js';     Text = 'const HELP="Start llama.cpp yourself: llama-server -m model.gguf --host 0.0.0.0 --port 8080, then enter the address here.";' }
        @{ Name = 'help text with the port flag';     File = 'resources/app/main.js';     Text = 'const HELP="Run llama-server -m model.gguf --port 8080 and paste http://localhost:8080 below.";' }
        @{ Name = 'setting description in a manifest'; File = 'package.json';             Text = '{"contributes":{"configuration":{"properties":{"acme.ollamaUrl":{"default":"http://192.168.1.10:11434","description":"Address of your Ollama server. On that machine start Ollama with OLLAMA_HOST=0.0.0.0 so it accepts remote connections."}}}}}' }
        @{ Name = 'comment-help of a script';         File = 'Get-Thing.ps1';             Text = "function Get-Thing {`n<#`n.DESCRIPTION`n    Ollama (loopback + no auth by default; OLLAMA_HOST=0.0.0.0 exposes it to the LAN)`n#>`n}`n" }
        @{ Name = 'string resource in XML';           File = 'Strings.xml';               Text = '<data name="Hint" value="Use OLLAMA_HOST=0.0.0.0 on the server" />' }
        @{ Name = 'echo line in a batch file';        File = 'help.bat';                  Text = "@echo off`r`necho To expose Ollama run: set OLLAMA_HOST=0.0.0.0`r`n" }
        @{ Name = 'sentence literal in a native PE';  File = 'Client.dll';                Text = "If Ollama runs elsewhere, launch it with OLLAMA_HOST=0.0.0.0 first.`0Example: llama-server --host 0.0.0.0 --port 8080`0" }
    ) {
        $p = New-AiTree @{ $File = $Text }
        @(Get-AiFindings $p) | Should -BeNullOrEmpty
    }

    It 'does not read help text in a compiled assembly as a bind' {
        if (-not $script:AsmOk) { Set-ItResult -Skipped -Because 'this host cannot compile a test assembly'; return }
        $p = New-AiTree @{ 'AcmeChat.Core.dll' = $script:Asm['help'] }
        @(Get-AiFindings $p) | Should -BeNullOrEmpty
    }

    It 'still reads the same form as a bind when it is a command: <Name>' -ForEach @(
        @{ Name = 'conditional set in a batch file'; File = 'run.bat';      Text = "@echo off`r`nif defined EXPOSE set OLLAMA_HOST=0.0.0.0`r`nstart ollama.exe serve`r`n"; Expect = 'OLLAMA_HOST=0\.0\.0\.0 \(engine host variable\)' }
        @{ Name = 'assignment before the engine command'; File = 'compose.yaml'; Text = "services:`n  llm:`n    command: OLLAMA_HOST=0.0.0.0 ollama serve`n";              Expect = 'OLLAMA_HOST=0\.0\.0\.0 \(engine host variable\)' }
        @{ Name = 'template literal value in script'; File = 'resources/app/main.js'; Text = 'const child=spawn(ollamaPath,["serve"],{env:{...process.env,OLLAMA_HOST:`0.0.0.0:${port}`}});'; Expect = 'OLLAMA_HOST=0\.0\.0\.0 \(engine host variable; the ollama server binary is under the scan root\)' }
        @{ Name = 'command string passed to exec';   File = 'resources/app/main.js'; Text = 'exec("llama-server --host 0.0.0.0 --port 8080");';                             Expect = 'llama-server --host 0\.0\.0\.0 \(engine host flag; the llama\.cpp server binary is under the scan root\)' }
    ) {
        $p = New-AiTree @{ $File = $Text; 'bin/ollama.exe' = 'MZ stub'; 'bin/llama-server.exe' = 'MZ stub' }
        $f = @(Get-AiServer $p)
        $f.Count | Should -Be 1
        $f[0].RuleId   | Should -Be 'aiserver.bind-all-interfaces'
        $f[0].Evidence | Should -Match $Expect
    }

    # aiserver-high-unrelated-listener-fp (development ports)
    It 'does not let a product name tie a listener on a development port: <Name>' -ForEach @(
        @{ Name = 'llama.cpp named, URL bind on 3001';   File = 'AcmeNotes.Core.dll';    Text = "Backends: OpenAI, Ollama, llama.cpp`nSyncListener.Start(http://0.0.0.0:3001/sync)`n" }
        @{ Name = 'LM Studio named, URL bind on 1234';   File = 'AcmeNotes.Core.dll';    Text = "Backends: OpenAI, LM Studio`nDebugListener=http://0.0.0.0:1234/`n" }
        @{ Name = 'AnythingLLM named, URL bind on 3001'; File = 'AcmeNotes.Core.dll';    Text = "Integrations: Notion, AnythingLLM`nSyncListener.Start(http://0.0.0.0:3001/sync)`n" }
        @{ Name = 'provider list, listen on 3001';       File = 'resources/app/main.js'; Text = 'const PROVIDERS=[{id:"ollama",name:"Ollama"},{id:"llamacpp",name:"llama.cpp"}];const sync=http.createServer(f);sync.listen(3001,"0.0.0.0");' }
        @{ Name = 'provider list, listen with no host';  File = 'resources/app/main.js'; Text = 'const PROVIDERS=[{id:"ollama",name:"Ollama"},{id:"llamacpp",name:"llama.cpp"}];const sync=http.createServer(f);sync.listen(3001);' }
        @{ Name = 'provider list, OAuth callback on 1234'; File = 'resources/app/main.js'; Text = 'const PROVIDERS=["OpenAI","LM Studio"];const cb=require("http").createServer(onOAuthCallback);cb.listen(1234,"127.0.0.1");' }
        @{ Name = 'section name, host / port pair on 1234'; File = 'server.ini';         Text = "[lmstudio]`r`nhost = 0.0.0.0`r`nport = 1234`r`n" }
    ) {
        $p = New-AiTree @{ $File = $Text }
        @(Get-AiFindings $p) | Should -BeNullOrEmpty
    }

    It 'still ties a development port when the same file registers a model API route' {
        $p = New-AiTree @{ 'resources/app/server.js' = 'const n="AnythingLLM";app.post("/v1/chat/completions",h);app.listen(3001,"0.0.0.0");' }
        $f = @(Get-AiServer $p)
        $f.Count | Should -Be 1
        $f[0].RuleId   | Should -Be 'aiserver.bind-all-interfaces'
        $f[0].Evidence | Should -Match 'all-interfaces listen call \.listen\(3001, 0\.0\.0\.0\) on the AnythingLLM default port'
    }

    # aiserver-root-product-leak
    It 'does not turn a product name in a server file into that product''s server' {
        $p = New-AiTree @{
            'bin/llama-server.exe'  = 'MZ stub'
            'resources/app/main.js' = 'const REMOTE=["Ollama","LM Studio","AnythingLLM"];spawn(path.join(bin,"llama-server.exe"),["--host","127.0.0.1","--port",String(port)]);'
            'config/devtools.json'  = '{"hmr":{"host":"0.0.0.0","port":3001}}'
        }
        $f = @(Get-AiFindings $p)
        $f.Count | Should -Be 1
        $f[0].RuleId   | Should -Be 'aiserver.local-server'
        $f[0].Evidence | Should -Match 'engine server launch llama-server --host 127\.0\.0\.1'
        $f[0].Evidence | Should -Not -Match 'devtools|3001|AnythingLLM'
    }

    It 'ties a bare bind to a server that another file establishes on the same port' {
        $p = New-AiTree @{
            'resources/app.asar'   = 'app.post("/v1/chat/completions", h); app.listen(3001, "127.0.0.1");'
            'config/settings.json' = '{"server":{"host":"0.0.0.0","port":3001}}'
        }
        $f = @(Get-AiServer $p)
        $f.Count | Should -Be 1
        $f[0].RuleId   | Should -Be 'aiserver.bind-all-interfaces'
        $f[0].Evidence | Should -Match 'settings\.json: all-interfaces bind host=0\.0\.0\.0 port=3001 on a known inference port \(a server on that port is established elsewhere under the scan root\)'
    }

    # aiserver-commented-bind-high-fp
    It 'does not read a commented-out bind as active next to the server binary: <Name>' -ForEach @(
        @{ Name = 'batch @rem line';            File = 'run.bat';               Text = "@echo off`r`n@rem set OLLAMA_HOST=0.0.0.0`r`nstart `"`" `"%~dp0bin\ollama.exe`" serve`r`n" }
        @{ Name = 'batch rem after a command';  File = 'run.bat';               Text = "@echo off`r`nstart `"`" bin\ollama.exe serve & rem set OLLAMA_HOST=0.0.0.0`r`n" }
        @{ Name = 'JSON block comment';         File = 'config/settings.json';  Text = "{`n  /* to expose on the LAN:`n     `"OLLAMA_HOST`": `"0.0.0.0:11434`",`n  */`n  `"OLLAMA_HOST`": `"127.0.0.1:11434`"`n}`n" }
        @{ Name = 'JSON trailing comment';      File = 'config/settings.jsonc'; Text = "{`n  `"OLLAMA_HOST`": `"127.0.0.1`", // `"OLLAMA_HOST`": `"0.0.0.0`"`n}`n" }
        @{ Name = 'trailing # comment';         File = '.env';                  Text = "OLLAMA_HOST=127.0.0.1:11434 # OLLAMA_HOST=0.0.0.0:11434 to expose`n" }
        @{ Name = 'script trailing comment';    File = 'run.ps1';               Text = "`$env:OLLAMA_HOST = `"127.0.0.1`" # `$env:OLLAMA_HOST = `"0.0.0.0`"`r`n" }
    ) {
        $p = New-AiTree @{ 'bin/ollama.exe' = 'MZ stub'; $File = $Text }
        $f = @(Get-AiFindings $p)
        $f.Count | Should -Be 1
        $f[0].RuleId   | Should -Be 'aiserver.local-server'
        $f[0].Evidence | Should -Not -Match 'OLLAMA_HOST=0\.0\.0\.0'
    }

    It 'keeps an active bind that shares a file with comment markers: <Name>' -ForEach @(
        @{ Name = 'note after the value';        File = '.env';     Text = "OLLAMA_HOST=0.0.0.0 # expose on the LAN`n" }
        @{ Name = 'glob and URL in JSON strings'; File = 'app.json'; Text = '{"files":"src/*.js","docs":"http://example.com/#/x","note":"see // docs","env":{"OLLAMA_HOST":"0.0.0.0"},"end":"*/"}' }
    ) {
        $p = New-AiTree @{ $File = $Text; 'bin/ollama.exe' = 'MZ stub' }
        (@(Get-AiServer $p | ForEach-Object { $_.RuleId }) -join ',') | Should -Be 'aiserver.bind-all-interfaces'
    }

    # aiserver-streamed-adjacent-literals-high-fp
    It 'does not join two adjacent literals across a line break of the string extractor' {
        # What a streamed view of "OLLAMA_HOST\0" "0.0.0.0\0" looks like: runs joined by a line break.
        $binds = & (Get-Module TCPK) {
            $acc = New-TcpkAiSignalSet
            Add-TcpkAiSignals -Text "Run a model`nOLLAMA_HOST`n0.0.0.0`n127.0.0.1`n" -Acc $acc -Style 'pe'
            $acc.Binds.Count
        }
        $binds | Should -Be 0
    }

    It 'gives the same answer for adjacent literals in a file above the streaming threshold' {
        $tail = [Text.Encoding]::ASCII.GetBytes("acme-agent`0OLLAMA_HOST`0" + "0.0.0.0`0" + "127.0.0.1`0")
        $small = New-Object byte[] (1MB)
        $large = New-Object byte[] (17MB)
        $small[0] = 0x4D; $small[1] = 0x5A; $large[0] = 0x4D; $large[1] = 0x5A
        [Array]::Copy($tail, 0, $small, $small.Length - $tail.Length, $tail.Length)
        [Array]::Copy($tail, 0, $large, $large.Length - $tail.Length, $tail.Length)
        $a = New-AiTree @{ 'acme-agent.exe' = $small }
        $b = New-AiTree @{ 'acme-agent.exe' = $large }
        @(Get-AiFindings $a) | Should -BeNullOrEmpty
        @(Get-AiFindings $b) | Should -BeNullOrEmpty
    }

    It 'accepts the bare name-value form only after setx' {
        $yes = New-AiTree @{ 'install.cmd' = 'setx OLLAMA_HOST 0.0.0.0 /M' }
        $no  = New-AiTree @{ 'notes.cfg'   = "OLLAMA_HOST 0.0.0.0`r`n" }
        (@(Get-AiRules $yes) -join ',') | Should -Be 'aiserver.bind-all-interfaces'
        @(Get-AiFindings $no) | Should -BeNullOrEmpty
    }

    # aiserver-compiled-dotnet-server-fn
    It 'finds a model API server in a compiled assembly' {
        if (-not $script:AsmOk) { Set-ItResult -Skipped -Because 'this host cannot compile a test assembly'; return }
        $p = New-AiTree @{ 'Acme.LocalAi.Server.dll' = $script:Asm['server'] }
        $f = @(Get-AiFindings $p)
        $f.Count | Should -Be 1
        $f[0].RuleId   | Should -Be 'aiserver.local-server'
        $f[0].Severity | Should -Be 'MEDIUM'
        $f[0].Evidence | Should -Match 'route-mapping member MapGet, MapPost with model API routes /v1/chat/completions, /v1/completions, /v1/embeddings as string literals'
        # The bind is on a port no inference product uses: shown, not rated, and the
        # Description does not claim that no all-interfaces bind exists.
        $f[0].Evidence    | Should -Match 'all-interfaces address text seen but not rated: http://0\.0\.0\.0:8080'
        $f[0].Description | Should -Match 'could not be tied to the inference listener'
        $f[0].Description | Should -Not -Match 'assumes a loopback bind'
    }

    It 'does not call a compiled client that holds the same route literals a server' {
        if (-not $script:AsmOk) { Set-ItResult -Skipped -Because 'this host cannot compile a test assembly'; return }
        $p = New-AiTree @{ 'Acme.Chat.dll' = $script:Asm['client'] }
        @(Get-AiFindings $p) | Should -BeNullOrEmpty
    }

    # aiserver-compiled-dotnet-env-fn
    It 'finds the host variable set by a compiled launcher that names the engine executable' {
        if (-not $script:AsmOk) { Set-ItResult -Skipped -Because 'this host cannot compile a test assembly'; return }
        $p = New-AiTree @{ 'Acme.Launcher.dll' = $script:Asm['launcher'] }
        $f = @(Get-AiFindings $p)
        $f.Count | Should -Be 1
        $f[0].RuleId   | Should -Be 'aiserver.bind-all-interfaces'
        $f[0].Evidence | Should -Match 'Acme\.Launcher\.dll: all-interfaces bind OLLAMA_HOST=0\.0\.0\.0 \(engine host variable; name and value are adjacent string literals'
    }

    It 'needs the engine binary under the root when the compiled launcher does not name it' {
        if (-not $script:AsmOk) { Set-ItResult -Skipped -Because 'this host cannot compile a test assembly'; return }
        $alone = New-AiTree @{ 'Acme.Launcher.dll' = $script:Asm['launcher-noexe'] }
        $with  = New-AiTree @{ 'Acme.Launcher.dll' = $script:Asm['launcher-noexe']; 'bin/ollama.exe' = 'MZ stub' }
        @(Get-AiFindings $alone) | Should -BeNullOrEmpty
        $f = @(Get-AiServer $with)
        $f.Count | Should -Be 1
        $f[0].RuleId   | Should -Be 'aiserver.bind-all-interfaces'
        $f[0].Evidence | Should -Match 'Acme\.Launcher\.dll: all-interfaces bind OLLAMA_HOST=0\.0\.0\.0 \(engine host variable; the ollama server binary is under the scan root\)'
        $f[0].Evidence | Should -Match 'ollama\.exe: inference server binary by file name'
    }

    It 'does not read a compiled comparison against the address as an assignment' {
        if (-not $script:AsmOk) { Set-ItResult -Skipped -Because 'this host cannot compile a test assembly'; return }
        $p = New-AiTree @{ 'Acme.Probe.dll' = $script:Asm['reader']; 'bin/ollama.exe' = 'MZ stub' }
        $f = @(Get-AiServer $p)
        $f.Count | Should -Be 1
        $f[0].RuleId   | Should -Be 'aiserver.local-server'
        $f[0].Evidence | Should -Not -Match 'OLLAMA_HOST'
    }

    # aiserver-listen-identifier-port-fn
    It 'reads the listen call of the route-registering code when the port is not a literal: <Name>' -ForEach @(
        @{ Name = 'constant';                Call = 'app.listen(PORT,"0.0.0.0");';                         Expect = 'all-interfaces listen call \.listen\(PORT, 0\.0\.0\.0\) next to the model API route registration' }
        @{ Name = 'environment expression';  Call = 'app.listen(process.env.PORT || 1337, "::");';         Expect = 'all-interfaces listen call \.listen\(<port expression>, ::\) next to the model API route registration' }
        @{ Name = 'options object';          Call = 'app.listen({port:1234,host:"0.0.0.0"});';             Expect = 'all-interfaces listen call \.listen\(1234, 0\.0\.0\.0\) on a known inference port' }
    ) {
        $p = New-AiTree @{ 'resources/app/server.js' = 'const express=require("express");const app=express();const PORT=process.env.PORT||1337;app.post("/v1/chat/completions",h);' + $Call }
        $f = @(Get-AiFindings $p)
        $f.Count | Should -Be 1
        $f[0].RuleId   | Should -Be 'aiserver.bind-all-interfaces'
        $f[0].Severity | Should -Be 'HIGH'
        $f[0].Evidence | Should -Match $Expect
    }

    It 'does not rate a listen call with a non-literal port outside route-registering code' {
        # No route registration in the file: nothing says this listener serves a model API.
        $p = New-AiTree @{ 'resources/app/main.js' = 'const PROVIDERS=["Ollama","llama.cpp"];sync.listen(PORT,"0.0.0.0");' }
        @(Get-AiFindings $p) | Should -BeNullOrEmpty
    }

    It 'does not take an argument of a later call for the address of a listen call' {
        $p = New-AiTree @{ 'resources/app/server.js' = 'app.post("/v1/chat/completions",h);app.listen(PORT)||warn(a, "0.0.0.0");history.listen(cb);' }
        $f = @(Get-AiServer $p)
        $f.Count | Should -Be 1
        $f[0].RuleId   | Should -Be 'aiserver.local-server'
        $f[0].Evidence | Should -Match 'listen call \.listen\(PORT\) next to the model API route registration, no host argument'
        $f[0].Evidence | Should -Not -Match 'listen\(cb\)'
    }

    # aiserver-medium-description-contradicts-evidence
    It 'does not claim a loopback bind when the listen call passes no address: <Name>' -ForEach @(
        @{ Name = 'known port';      Call = 'server.listen(1234);';              Expect = 'listen call \.listen\(1234\) on a known inference port, no host argument \(a Node listener with no host accepts connections on every interface\)' }
        @{ Name = 'other port';      Call = 'server.listen(8080, () => up());';  Expect = 'listen call \.listen\(8080\) next to the model API route registration, no host argument' }
        @{ Name = 'named port';      Call = 'server.listen(PORT);';              Expect = 'listen call \.listen\(PORT\) next to the model API route registration, no host argument' }
    ) {
        $p = New-AiTree @{ 'resources/app/main.js' = 'app.post("/v1/chat/completions", h); ' + $Call }
        $f = @(Get-AiServer $p)
        $f.Count | Should -Be 1
        $f[0].RuleId      | Should -Be 'aiserver.local-server'
        $f[0].Evidence    | Should -Match $Expect
        $f[0].Description | Should -Match 'passes no address, so the runtime default decides'
        $f[0].Description | Should -Not -Match 'assumes a loopback bind|loopback-class'
        $f[0].ObsValue    | Should -Be '"listen-without-address"'
    }

    It 'states the loopback assumption only when the Evidence shows no other bind' {
        $loop = New-AiTree @{ 'resources/app/main.js' = 'app.post("/v1/chat/completions", h); server.listen(8080, "127.0.0.1");' }
        $expr = New-AiTree @{ 'resources/app/main.js' = 'app.post("/v1/chat/completions", h); server.listen(1234, bindAddress);' }
        $a = @(Get-AiServer $loop)
        $b = @(Get-AiServer $expr)
        $a.Count | Should -Be 1
        $a[0].Evidence    | Should -Match 'listen call \.listen\(8080, 127\.0\.0\.1\) next to the model API route registration'
        $a[0].Description | Should -Match 'assumes a loopback bind'
        # A second argument that is a name may be an address: nothing is claimed about it.
        $b.Count | Should -Be 1
        $b[0].Evidence    | Should -Match 'listen call \.listen\(1234, \.\.\.\) on a known inference port \(the address argument is not a literal\)'
        $b[0].Evidence    | Should -Not -Match 'no host argument'
    }

    # aiserver-server-binary-name-generic
    It 'takes a file name as the server binary only for the engine''s own names: <Name>' -ForEach @(
        @{ Name = 'local-ai-notes.exe';                 Expect = 0 }
        @{ Name = 'local-ai-assistant-setup.exe';       Expect = 0 }
        @{ Name = 'local-ai.exe';                       Expect = 1 }
        @{ Name = 'local-ai-windows-amd64.exe';         Expect = 1 }
        @{ Name = 'local-ai-v2.24.0-windows-amd64.exe'; Expect = 1 }
        @{ Name = 'koboldcpp_cu12.exe';                 Expect = 1 }
    ) {
        $p = New-AiTree @{ $Name = 'MZ stub' }
        @(Get-AiServer $p).Count | Should -Be $Expect
    }

    # aiserver-xml-config-not-read
    It 'reads the host variable from a service wrapper .xml next to the server binary' {
        $xml = "<service>`r`n  <id>acme-llm</id>`r`n  <executable>%BASE%\bin\ollama.exe</executable>`r`n  <arguments>serve</arguments>`r`n  <env name=`"OLLAMA_HOST`" value=`"0.0.0.0`" />`r`n</service>`r`n"
        $p = New-AiTree @{ 'acme-llm-service.xml' = $xml; 'bin/ollama.exe' = 'MZ stub' }
        $f = @(Get-AiServer $p)
        $f.Count | Should -Be 1
        $f[0].RuleId   | Should -Be 'aiserver.bind-all-interfaces'
        $f[0].Evidence | Should -Match 'acme-llm-service\.xml: all-interfaces bind OLLAMA_HOST=0\.0\.0\.0 \(engine host variable\)'

        $off = New-AiTree @{ 'acme-llm-service.xml' = ($xml -replace '<env [^>]+>', '<!-- <env name="OLLAMA_HOST" value="0.0.0.0" /> -->'); 'bin/ollama.exe' = 'MZ stub' }
        (@(Get-AiRules $off) -join ',') | Should -Be 'aiserver.local-server'
    }

    # aiserver-client-info-dev-url
    It 'does not report a development URL next to a provider name as an inference endpoint: <Name>' -ForEach @(
        @{ Name = 'AnythingLLM and 3001'; Text = 'const PROVIDERS=["OpenAI","AnythingLLM"];win.loadURL(isDev?"http://localhost:3001":"file://"+indexHtml);' }
        @{ Name = 'LM Studio and 1234';   Text = 'const PROVIDERS=["OpenAI","LM Studio"];const dev="http://localhost:1234";' }
        @{ Name = 'Jan and 1337';         Text = 'const about="jan.ai";const dev="http://127.0.0.1:1337/";' }
    ) {
        $p = New-AiTree @{ 'resources/app/main.js' = $Text }
        @(Get-AiFindings $p) | Should -BeNullOrEmpty
    }

    It 'still reports a client endpoint that carries a model API route, or is on the single-product port' {
        $route = New-AiTree @{ 'resources/app/main.js' = 'const PROVIDERS=["LM Studio"];const u="http://localhost:1234/v1/chat/completions";' }
        $port  = New-AiTree @{ 'resources/app/main.js' = 'const PROVIDERS=["Ollama"];const u="http://localhost:11434";' }
        $a = @(Get-AiFindings $route)
        $b = @(Get-AiFindings $port)
        $a.Count | Should -Be 1
        $a[0].RuleId   | Should -Be 'aiserver.local-llm-client'
        $a[0].Evidence | Should -Match 'http://localhost:1234/v1/chat/completions \(model API route on the LM Studio default port\)'
        $b.Count | Should -Be 1
        $b[0].RuleId   | Should -Be 'aiserver.local-llm-client'
        $b[0].Evidence | Should -Match 'http://localhost:11434 \(Ollama default port\)'
    }

    # aiserver-config-comment-regex-quadratic
    It 'strips block comments in one pass, whatever the number of unclosed openers' {
        $sb = New-Object System.Text.StringBuilder
        [void]$sb.Append("{`n")
        for ($i = 0; $i -lt 12000; $i++) { [void]$sb.Append(" `"mail.template.$i`": `"<#if user.name??>Hello<#else>Hi</#if> <!-- order $i <#list items as it>x</#list>`",`n") }
        [void]$sb.Append("}`n")
        $text = $sb.ToString()
        $text.Length | Should -BeGreaterThan 1000000
        $sw = [Diagnostics.Stopwatch]::StartNew()
        $out = & (Get-Module TCPK) { param($t) Get-TcpkAiConfigText -Text $t } $text
        $sw.Stop()
        $out.Length | Should -Be $text.Length
        $sw.Elapsed.TotalSeconds | Should -BeLessThan 10
    }

    It 'applies each block comment style to the file type that has it' {
        $r = & (Get-Module TCPK) {
            @{
                Ps1  = (Get-TcpkAiConfigText -Text "a<# OLLAMA_HOST=0.0.0.0 #>b" -Name 'run.ps1')
                Xml  = (Get-TcpkAiConfigText -Text "a<!-- OLLAMA_HOST=0.0.0.0 -->b" -Name 'svc.xml')
                Json = (Get-TcpkAiConfigText -Text "a/* OLLAMA_HOST=0.0.0.0 */b" -Name 'app.json')
                # A PowerShell block marker in a JSON template string is not a comment.
                Tmpl = (Get-TcpkAiConfigText -Text '{"t":"<#if x>","e":"OLLAMA_HOST=0.0.0.0","u":"#>"}' -Name 'templates.json')
                Rem  = (Get-TcpkAiConfigText -Text "@rem set OLLAMA_HOST=0.0.0.0`r`nrem`r`nremote=1`r`n" -Name 'run.bat')
            }
        }
        $r.Ps1  | Should -Not -Match 'OLLAMA_HOST'
        $r.Xml  | Should -Not -Match 'OLLAMA_HOST'
        $r.Json | Should -Not -Match 'OLLAMA_HOST'
        $r.Tmpl | Should -Match 'OLLAMA_HOST=0\.0\.0\.0'
        $r.Rem  | Should -Not -Match 'OLLAMA_HOST'
        $r.Rem  | Should -Match 'remote=1'
    }

    # aiserver-copy-stray-llm-config-change
    It 'leaves the module data folder untouched' {
        $moduleRoot = Split-Path (Split-Path $PSCommandPath -Parent) -Parent
        $cfg = Join-Path (Join-Path $moduleRoot 'Data') 'llm-config.json'
        $before = $null
        if (Test-Path -LiteralPath $cfg) { $before = [IO.File]::ReadAllBytes($cfg) }
        $p = New-AiTree @{ '.env' = 'OLLAMA_HOST=0.0.0.0:11434'; 'bin/ollama.exe' = 'MZ stub' }
        @(Get-AiFindings $p).Count | Should -Be 1
        $after = $null
        if (Test-Path -LiteralPath $cfg) { $after = [IO.File]::ReadAllBytes($cfg) }
        ($null -eq $after) | Should -Be ($null -eq $before)
        if ($null -ne $before) { [Convert]::ToBase64String($after) | Should -Be ([Convert]::ToBase64String($before)) }
    }
}

Describe 'Test-TcpkAiInferenceServer third-review regressions' {

    # aiserver-bind-snippet-literal-high-fp
    It 'does not read a copyable snippet in a help screen as a bind: <Name>' -ForEach @(
        @{ Name = 'JSX code element';  File = 'resources/app/renderer.js'; Text = 'const OLLAMA="http://localhost:11434";function H(){return (0,e.jsx)("code",{children:"OLLAMA_HOST=0.0.0.0"})}' }
        @{ Name = 'clipboard text';    File = 'resources/app/renderer.js'; Text = 'function C(){navigator.clipboard.writeText("OLLAMA_HOST=0.0.0.0")}' }
        @{ Name = 'JSON locale entry'; File = 'locales/en.json';           Text = '{"ollama.remote.step2.code":"OLLAMA_HOST=0.0.0.0","title":"Connect to Ollama"}' }
        @{ Name = 'YAML locale entry'; File = 'locales/en.yaml';           Text = "ollama.remote.step2.code: `"OLLAMA_HOST=0.0.0.0`"`ntitle: Connect to Ollama`n" }
        @{ Name = 'script variable';   File = 'help.ps1';                  Text = "`$snippet = `"OLLAMA_HOST=0.0.0.0`"`nWrite-Host `$snippet`n" }
        @{ Name = 'JSX command line';  File = 'resources/app/renderer.js'; Text = 'function H(){return (0,e.jsx)("pre",{children:"llama-server -m model.gguf --host 0.0.0.0 --port 8080"})}' }
        @{ Name = 'compiled literal';  File = 'Acme.Help.dll';             Text = "Run this on the server:`0OLLAMA_HOST=0.0.0.0`0Then restart Ollama.`0" }
    ) {
        @(Get-AiServer (New-AiTree @{ $File = $Text })) | Should -BeNullOrEmpty
        # Next to the server binaries the server is reported, and the snippet does not rate it.
        $f = @(Get-AiServer (New-AiTree @{ $File = $Text; 'bin/ollama.exe' = 'MZ stub'; 'bin/llama-server.exe' = 'MZ stub' }))
        $f.Count | Should -Be 1
        $f[0].RuleId | Should -Be 'aiserver.local-server'
    }

    # aiserver-11434-text-mention-high-fp
    It 'does not read an address in a message as a bind: <Name>' -ForEach @(
        @{ Name = 'sentence ending at the address'; Text = 'const OLLAMA="http://localhost:11434";const msg="On the other computer Ollama must listen on 0.0.0.0:11434.";' }
        @{ Name = 'label before the address';       Text = 'const OLLAMA="http://localhost:11434";const msg="Remote Ollama address to bind: 0.0.0.0:11434";' }
        @{ Name = 'URL in a log line';              Text = 'const OLLAMA="http://localhost:11434";log("[ollama] expected the remote server at http://0.0.0.0:11434/");' }
    ) {
        @(Get-AiServer (New-AiTree @{ 'resources/app/main.js' = $Text })) | Should -BeNullOrEmpty
        $f = @(Get-AiServer (New-AiTree @{ 'resources/app/main.js' = $Text; 'bin/ollama.exe' = 'MZ stub' }))
        $f.Count | Should -Be 1
        $f[0].RuleId | Should -Be 'aiserver.local-server'
    }

    It 'still rates a real setting in a launcher or configuration file: <Name>' -ForEach @(
        @{ Name = 'compose environment list'; File = 'compose.yaml'; Text = "services:`n  llm:`n    environment:`n      - `"OLLAMA_HOST=0.0.0.0`"`n" }
        @{ Name = 'service unit environment'; File = 'ollama.conf';  Text = "[Service]`nEnvironment=`"OLLAMA_HOST=0.0.0.0`"`n" }
        @{ Name = 'quoted batch assignment';  File = 'run.bat';      Text = "@echo off`r`nset `"OLLAMA_HOST=0.0.0.0`"`r`nstart ollama.exe serve`r`n" }
    ) {
        $p = New-AiTree @{ $File = $Text }
        (@(Get-AiRules $p) -join ',') | Should -Be 'aiserver.bind-all-interfaces'
    }

    It 'rates structured code only next to that engine''s own server binary' {
        $js = 'process.env["OLLAMA_HOST"] = "0.0.0.0:11434"; spawn(ollamaPath, ["serve"]);'
        @(Get-AiServer (New-AiTree @{ 'resources/app/main.js' = $js })) | Should -BeNullOrEmpty
        # Another engine's binary does not make an Ollama setting count.
        $other = @(Get-AiServer (New-AiTree @{ 'resources/app/main.js' = $js; 'bin/llama-server.exe' = 'MZ stub' }))
        $other.Count | Should -Be 1
        $other[0].RuleId | Should -Be 'aiserver.local-server'
        $own = @(Get-AiServer (New-AiTree @{ 'resources/app/main.js' = $js; 'bin/ollama.exe' = 'MZ stub' }))
        $own.Count | Should -Be 1
        $own[0].RuleId | Should -Be 'aiserver.bind-all-interfaces'
    }

    It 'takes a command string as a launch only when it is handed to a process-start call' {
        $exec = New-AiTree @{ 'resources/app/main.js' = 'exec("llama-server --host 0.0.0.0 --port 8080");'; 'bin/llama-server.exe' = 'MZ stub' }
        $text = New-AiTree @{ 'resources/app/main.js' = 'show("llama-server --host 0.0.0.0 --port 8080");'; 'bin/llama-server.exe' = 'MZ stub' }
        (@(Get-AiServer $exec))[0].RuleId | Should -Be 'aiserver.bind-all-interfaces'
        (@(Get-AiServer $text))[0].RuleId | Should -Be 'aiserver.local-server'
    }
}
