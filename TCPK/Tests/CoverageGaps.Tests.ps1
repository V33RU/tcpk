#requires -Version 5.1
# Coverage-gap features (v1.3.0): single-file bundle extraction, UI data-leak
# surface, browser token store, Tauri config audit, gRPC/SignalR channels.
# Deterministic, offline -- no SDK, no network, no real user profile touched.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
    $script:work = Join-Path ([IO.Path]::GetTempPath()) ("tcpk-gaps-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:work -Force | Out-Null
}

AfterAll {
    if ($script:work -and (Test-Path -LiteralPath $script:work)) {
        Remove-Item -LiteralPath $script:work -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Describe 'Single-file bundle extraction' {
    BeforeAll {
        # Build a synthetic .NET single-file apphost (bundle major v6) with two
        # embedded assemblies: one stored, one Deflate-compressed.
        $sig = [byte[]](0x8b,0x12,0x02,0xb9,0x6a,0x61,0x20,0x38,0x72,0x7b,0x93,0x02,0x14,0xd7,0xa0,0x32)
        $file1 = [Text.Encoding]::UTF8.GetBytes("MZ fake assembly one AKIAIOSFODNN7EXAMPLE end")
        $file2raw = [Text.Encoding]::UTF8.GetBytes("MZ fake assembly two -- secret marker UNIQUEBUNDLESECRET42 end")
        $cms = New-Object System.IO.MemoryStream
        $ds = New-Object System.IO.Compression.DeflateStream($cms, [System.IO.Compression.CompressionMode]::Compress, $true)
        $ds.Write($file2raw, 0, $file2raw.Length); $ds.Dispose()
        $file2c = $cms.ToArray(); $cms.Dispose()

        $ms = New-Object System.IO.MemoryStream
        $bw = New-Object System.IO.BinaryWriter($ms, [Text.Encoding]::UTF8)
        $bw.Write([byte[]](New-Object byte[] 128))      # fake PE prefix
        $off1 = $ms.Position; $bw.Write([byte[]]$file1)
        $off2 = $ms.Position; $bw.Write([byte[]]$file2c)
        $headerOffset = $ms.Position
        $bw.Write([int]6); $bw.Write([int]0); $bw.Write([int]2)   # major, minor, count
        $bw.Write([string]"bundle-id")
        $bw.Write([long]0); $bw.Write([long]0)                    # deps off/size
        $bw.Write([long]0); $bw.Write([long]0)                    # rtcfg off/size
        $bw.Write([long]0)                                        # flags
        # entry 1: stored
        $bw.Write([long]$off1); $bw.Write([long]$file1.Length); $bw.Write([long]0); $bw.Write([byte]1); $bw.Write([string]"One.dll")
        # entry 2: compressed (compressedSize != 0)
        $bw.Write([long]$off2); $bw.Write([long]$file2raw.Length); $bw.Write([long]$file2c.Length); $bw.Write([byte]1); $bw.Write([string]"sub\Two.dll")
        # trailer: headerOffset then signature
        $bw.Write([long]$headerOffset); $bw.Write([byte[]]$sig)
        $bw.Flush()
        $bytes = $ms.ToArray(); $bw.Dispose(); $ms.Dispose()

        $script:sfExe = Join-Path $script:work 'App.exe'
        [IO.File]::WriteAllBytes($script:sfExe, $bytes)
        $script:sfHeaderOffset = $headerOffset
    }

    It 'detects a single-file apphost and returns its header offset' {
        $off = & (Get-Module TCPK) { param($p) Test-TcpkSingleFileExe -Path $p } $script:sfExe
        $off | Should -Be $script:sfHeaderOffset
    }

    It 'does NOT flag an ordinary file as single-file' {
        $plain = Join-Path $script:work 'plain.exe'
        [IO.File]::WriteAllBytes($plain, [Text.Encoding]::UTF8.GetBytes("just some bytes, no bundle here"))
        $off = & (Get-Module TCPK) { param($p) Test-TcpkSingleFileExe -Path $p } $plain
        $off | Should -BeNullOrEmpty
    }

    It 'extracts both embedded assemblies (stored + Deflate) with correct content' {
        $out = Join-Path $script:work 'extracted'
        $res = & (Get-Module TCPK) { param($p,$o) Expand-TcpkSingleFileBundle -Path $p -OutDir $o } $script:sfExe $out
        @($res).Count | Should -Be 2
        $one = Join-Path $out 'One.dll'
        $two = Join-Path $out 'sub\Two.dll'
        (Test-Path $one) | Should -BeTrue
        (Test-Path $two) | Should -BeTrue
        ([IO.File]::ReadAllText($one)) | Should -Match 'AKIAIOSFODNN7EXAMPLE'
        ([IO.File]::ReadAllText($two)) | Should -Match 'UNIQUEBUNDLESECRET42'   # proves decompression
    }

    It 'Expand-TcpkSingleFile emits an expanded finding for the bundle' {
        $out = Join-Path $script:work 'extracted2'
        $f = @(Expand-TcpkSingleFile -Path $script:sfExe -OutDir $out)
        ($f | Where-Object { $_.RuleId -eq 'singlefile.expanded' }) | Should -Not -BeNullOrEmpty
    }
}

Describe 'UI data-leak surface' {
    It 'flags clipboard writes with no history exclusion, and missing screen-capture protection' {
        $dir = Join-Path $script:work 'ui'; New-Item -ItemType Directory -Path $dir -Force | Out-Null
        # a "binary" (bytes) that references clipboard write + password UI + WPF, but
        # neither a clipboard-exclusion marker nor SetWindowDisplayAffinity.
        $content = "PresentationFramework PasswordBox Clipboard SetDataObject some other code"
        [IO.File]::WriteAllBytes((Join-Path $dir 'MyApp.dll'), [Text.Encoding]::Unicode.GetBytes($content))
        $f = @(Test-TcpkUiLeakSurface -Path $dir)
        ($f | Where-Object { $_.RuleId -eq 'ui.clipboard-no-history-exclusion' }) | Should -Not -BeNullOrEmpty
        ($f | Where-Object { $_.RuleId -eq 'ui.no-screen-capture-protection' }) | Should -Not -BeNullOrEmpty
    }
    It 'stays quiet when protections are present' {
        $dir = Join-Path $script:work 'ui2'; New-Item -ItemType Directory -Path $dir -Force | Out-Null
        $content = "PresentationFramework PasswordBox SetDataObject ExcludeClipboardContentFromMonitorProcessing SetWindowDisplayAffinity"
        [IO.File]::WriteAllBytes((Join-Path $dir 'Safe.dll'), [Text.Encoding]::Unicode.GetBytes($content))
        $f = @(Test-TcpkUiLeakSurface -Path $dir)
        $f.Count | Should -Be 0
    }
}

Describe 'Tauri config audit' {
    It 'flags missing CSP, allowlist.all, shell access, and unsigned updater (v1)' {
        $dir = Join-Path $script:work 'tauri'; New-Item -ItemType Directory -Path $dir -Force | Out-Null
        $conf = @{
            tauri = @{
                security  = @{}                       # no csp
                allowlist = @{ all = $true; shell = @{ open = $true } }
                updater   = @{ active = $true; pubkey = ''; endpoints = @('http://updates.example.com/x') }
            }
        } | ConvertTo-Json -Depth 6
        Set-Content -LiteralPath (Join-Path $dir 'tauri.conf.json') -Value $conf -Encoding UTF8
        $f = @(Test-TcpkTauriConfig -Path $dir)
        $ids = $f.RuleId
        $ids | Should -Contain 'tauri.no-csp'
        $ids | Should -Contain 'tauri.allowlist-all'
        $ids | Should -Contain 'tauri.shell-access'
        $ids | Should -Contain 'tauri.updater-no-pubkey'
        $ids | Should -Contain 'tauri.updater-insecure-endpoint'
    }
}

Describe 'gRPC / SignalR channels' {
    It 'flags insecure gRPC credentials in first-party code' {
        $dir = Join-Path $script:work 'rpc'; New-Item -ItemType Directory -Path $dir -Force | Out-Null
        [IO.File]::WriteAllBytes((Join-Path $dir 'Client.dll'), [Text.Encoding]::Unicode.GetBytes("ChannelCredentials Insecure GrpcChannel ForAddress"))
        $f = @(Test-TcpkRpcChannels -Path $dir)
        ($f | Where-Object { $_.RuleId -eq 'rpc.grpc-insecure-credentials' }) | Should -Not -BeNullOrEmpty
    }
    It 'flags a cleartext SignalR hub URL in shipped JS' {
        $dir = Join-Path $script:work 'rpc2'; New-Item -ItemType Directory -Path $dir -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $dir 'app.js') -Value 'const c = new signalR.HubConnectionBuilder().withUrl("http://hub.example.com/chat").build();' -Encoding UTF8
        $f = @(Test-TcpkRpcChannels -Path $dir)
        ($f | Where-Object { $_.RuleId -eq 'rpc.signalr-cleartext-hub' }) | Should -Not -BeNullOrEmpty
    }
}

Describe 'Browser token store' {
    It 'finds a Chromium store and classifies a DPAPI-only key' -Skip:($IsWindows -eq $false) {
        # Browser token-store classification (DPAPI os_crypt key) is a Windows-only path.
        $fakeAppData = Join-Path $script:work 'appdata'
        $profile = Join-Path $fakeAppData 'MyChatApp\User Data\Default'
        $netDir  = Join-Path $profile 'Network'
        New-Item -ItemType Directory -Path $netDir -Force | Out-Null
        # a non-empty cookie store
        [IO.File]::WriteAllBytes((Join-Path $netDir 'Cookies'), (New-Object byte[] 4096))
        # Local State at the User Data root with a DPAPI-only os_crypt key
        $userData = Split-Path -Parent $profile
        $ls = @{ os_crypt = @{ encrypted_key = 'RFBBUEktZmFrZQ==' } } | ConvertTo-Json
        Set-Content -LiteralPath (Join-Path $userData 'Local State') -Value $ls -Encoding UTF8

        $oldAppData = $env:APPDATA; $oldLocal = $env:LOCALAPPDATA
        try {
            $env:APPDATA = $fakeAppData
            $env:LOCALAPPDATA = $fakeAppData
            $f = @(Test-TcpkBrowserTokenStore -NameLike @('MyChatApp'))
        } finally {
            $env:APPDATA = $oldAppData; $env:LOCALAPPDATA = $oldLocal
        }
        ($f | Where-Object { $_.RuleId -eq 'browser.cred-store' }) | Should -Not -BeNullOrEmpty
        ($f | Where-Object { $_.RuleId -eq 'browser.cookie-key-dpapi' }) | Should -Not -BeNullOrEmpty
    }

    It 'requires name terms (no terms -> no survey)' {
        $f = @(Test-TcpkBrowserTokenStore -NameLike @())
        $f.Count | Should -Be 0
    }
}
