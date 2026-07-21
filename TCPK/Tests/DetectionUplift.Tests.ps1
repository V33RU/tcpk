#requires -Version 5.1
# v2.6.0 detection-uplift regression guards:
#   - new modern-provider secret rules (recall across static/memory/env)
#   - injection sink-map additions: base DbCommand/IDbCommand (Dapper/EF-raw/DbProviderFactory)
#     + HttpMessageInvoker (SSRF through the abstraction), now taint-verifiable
#   - reflection.dynamic-load routed into the deterministic IL verifier (reflection-load sink)
#   - IL taint-source regex broadened to desktop input channels (file dialog / clipboard /
#     drag-drop / deserialized results)

$secretCases = @(
    @{ rule = 'openai-api-key';         sample = ('sk-' + ('a' * 20) + 'T3BlbkFJ' + ('b' * 20)) }
    @{ rule = 'anthropic-api-key';      sample = ('sk-ant-api03-' + ('a' * 40)) }
    @{ rule = 'gitlab-pat';             sample = ('glpat-' + ('a' * 24)) }
    @{ rule = 'sendgrid-api-key';       sample = ('SG.' + ('a' * 22) + '.' + ('b' * 43)) }
    @{ rule = 'npm-access-token';       sample = ('npm_' + ('a' * 36)) }
    @{ rule = 'digitalocean-pat';       sample = ('dop_v1_' + ('a' * 64)) }
    @{ rule = 'basic-auth-in-url';      sample = 'cfg: ftp://svcacct:Wint3rPass2024@10.44.12.9/data' }
    @{ rule = 'http-basic-auth-header'; sample = 'Authorization: Basic YWRtaW46c3VwZXJzZWNyZXQxMjM=' }
)

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
}

Describe 'New secret provider rules each detect a real positive' {
    It 'detects <rule>' -ForEach $secretCases {
        $dir = Join-Path ([IO.Path]::GetTempPath()) ("tcpk-du-" + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        try {
            Set-Content -LiteralPath (Join-Path $dir 'sample.txt') -Value $sample -Encoding UTF8
            $found = @(Test-TcpkSecrets -Path $dir | ForEach-Object { "$($_.RuleId)" })
            $found | Should -Contain "secrets.$rule"
        } finally { [IO.Directory]::Delete($dir, $true) }
    }
}

Describe 'IL sink map + taint-source additions' {
    It 'sql-command-construction includes the base DbCommand / IDbCommand types' {
        InModuleScope TCPK {
            $sql = @((Get-TcpkCallsiteSinkMap)['sql-command-construction'].Sinks | ForEach-Object { $_.T })
            $sql | Should -Contain 'System.Data.Common.DbCommand'
            $sql | Should -Contain 'System.Data.IDbCommand'
        }
    }
    It 'ssrf-request-build includes HttpMessageInvoker' {
        InModuleScope TCPK {
            $s = @((Get-TcpkCallsiteSinkMap)['ssrf-request-build'].Sinks | ForEach-Object { $_.T })
            $s | Should -Contain 'System.Net.Http.HttpMessageInvoker'
        }
    }
    It 'exposes a reflection-load injection sink family' {
        InModuleScope TCPK {
            $r = (Get-TcpkCallsiteSinkMap)['reflection-load']
            $r | Should -Not -BeNullOrEmpty
            $r.Inj | Should -BeTrue
            @($r.Sinks | ForEach-Object { $_.M }) | Should -Contain 'LoadFrom'
        }
    }
    It 'taint-source regex recognizes desktop input channels' {
        InModuleScope TCPK {
            $rx = $script:TcpkIlSourceApiRx
            'System.Windows.Forms.OpenFileDialog::get_FileName' | Should -Match $rx
            'System.Windows.Forms.Clipboard::GetText' | Should -Match $rx
            'Acme.BinaryFormatter::Deserialize' | Should -Match $rx
        }
    }
}

Describe 'reflection.dynamic-load is routed through the IL verifier' {
    It 'IL-processes a reflection finding instead of passing it through' {
        $cecilOk = $false
        try { $cecilOk = & (Get-Module TCPK) { Test-TcpkCecilAvailable } } catch {}
        if (-not $cecilOk) { Set-ItResult -Skipped -Because 'Mono.Cecil bridge not available'; return }
        $dll = Get-ChildItem (Join-Path (Split-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) -Parent) 'tools') -Recurse -Filter 'Mono.Cecil.dll' -ErrorAction SilentlyContinue |
               Select-Object -First 1 -ExpandProperty FullName
        if (-not $dll) { Set-ItResult -Skipped -Because 'Mono.Cecil.dll not found'; return }
        $find = [pscustomobject]@{ RuleId = 'reflection.dynamic-load'; Severity = 'MEDIUM'; Confidence = 'Inferred'; Title = 't'; File = $dll; Description = 'BASE'; Module = 'static' }
        $out = @($find | Confirm-TcpkCallsiteUsage)
        $out[0].Description | Should -Not -Be 'BASE'
    }
}

Describe 'Electron insecure-by-default (old runtime + omitted hardening key)' {
    BeforeAll {
        function New-TcpkElFixture([string]$eVer, [string]$mainJs) {
            $dir = Join-Path ([IO.Path]::GetTempPath()) ('tcpk-elt-' + [guid]::NewGuid().ToString('N'))
            New-Item -ItemType Directory -Path (Join-Path $dir 'resources') -Force | Out-Null
            Set-Content -LiteralPath (Join-Path $dir 'resources\app.asar') -Value 'ASARSTUB' -Encoding ASCII
            Set-Content -LiteralPath (Join-Path $dir 'App.exe') -Value ("MZ..Chromium..Electron/$eVer..Chrome/79.0.3945.130..") -Encoding ASCII
            Set-Content -LiteralPath (Join-Path $dir 'main.js') -Value $mainJs -Encoding UTF8
            return $dir
        }
        $script:mainNoKeys = "const { BrowserWindow } = require('electron'); new BrowserWindow({ webPreferences: { preload: 'p.js' } });"
    }
    It 'flags nodeIntegration/contextIsolation/sandbox on Electron 4 when the keys are omitted' {
        $dir = New-TcpkElFixture '4.2.0' $script:mainNoKeys
        try {
            $rids = @(Test-TcpkElectron -Path $dir | ForEach-Object { "$($_.RuleId)" })
            $rids | Should -Contain 'electron.insecure-default-nodeIntegration'
            $rids | Should -Contain 'electron.insecure-default-contextIsolation'
            $rids | Should -Contain 'electron.insecure-default-sandbox'
        } finally { [IO.Directory]::Delete($dir, $true) }
    }
    It 'does NOT flag on a modern Electron (above all default floors)' {
        $dir = New-TcpkElFixture '25.0.0' $script:mainNoKeys
        try {
            $rids = @(Test-TcpkElectron -Path $dir | ForEach-Object { "$($_.RuleId)" })
            @($rids -match 'insecure-default').Count | Should -Be 0
        } finally { [IO.Directory]::Delete($dir, $true) }
    }
}

Describe 'KEV enrichment' {
    It 'Get-TcpkKevSet returns a HashSet, not an unrolled Object[] (guards the return-comma)' {
        InModuleScope TCPK {
            $script:TcpkKevCache = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
            (Get-TcpkKevSet).GetType().Name | Should -Match 'HashSet'
        }
    }
    It 'matches a KEV CVE case-insensitively and rejects a non-KEV CVE' {
        InModuleScope TCPK {
            $script:TcpkKevCache = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
            [void]$script:TcpkKevCache.Add('CVE-2021-44228')
            $kev = Get-TcpkKevSet
            $kev.Contains('cve-2021-44228') | Should -BeTrue
            $kev.Contains('CVE-2019-00001') | Should -BeFalse
        }
    }
}
