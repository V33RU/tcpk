#requires -Version 5.1
# Electron/Chromium/Node bundled-runtime detection + the electron.outdated-runtime finding
# (v1.6.x). The embedded Chromium version is the biggest CVE surface in an Electron app and is
# NOT in any deps.json -- it is a string in the main exe. TCPK extracts it, flags an outdated
# bundle offline (vs Data/runtime-baseline.json), and online queries OSV electron@<version>.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
    $script:work = Join-Path ([IO.Path]::GetTempPath()) ("tcpk-eltver-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:work -Force | Out-Null

    function New-FakeElectron {
        param([string]$Dir, [string]$ExeBody)
        New-Item -ItemType Directory -Path $Dir -Force | Out-Null
        [IO.File]::WriteAllText((Join-Path $Dir 'app.asar'), 'dummy asar without any js config flags')
        [IO.File]::WriteAllText((Join-Path $Dir 'Acme Desktop.exe'), $ExeBody)
    }
    # outdated: Chromium 146 vs baseline 149 -> 3 majors behind
    $script:old = Join-Path $script:work 'old'
    New-FakeElectron -Dir $script:old -ExeBody 'MZ stub .. Chrome/146.0.7680.179 .. Electron/41.2.0 .. node.js/v24.14.0 .. end'
    # current: matches the baseline Chromium major -> no outdated finding
    $script:cur = Join-Path $script:work 'cur'
    New-FakeElectron -Dir $script:cur -ExeBody 'MZ stub .. Chrome/149.0.7827.156 .. Electron/42.4.1 .. node.js/v24.14.1 .. end'
}
AfterAll {
    if ($script:work -and (Test-Path -LiteralPath $script:work)) { [IO.Directory]::Delete($script:work, $true) }
}

Describe 'Get-TcpkRuntimeVersions (extract bundled Electron/Chromium/Node)' {
    It 'extracts the three versions from the main exe' {
        $rv = & (Get-Module TCPK) { param($d) Get-TcpkRuntimeVersions -Path $d } $script:old
        $rv          | Should -Not -BeNullOrEmpty
        $rv.Electron | Should -Be '41.2.0'
        $rv.Chromium | Should -Be '146.0.7680.179'
        $rv.Node     | Should -Be '24.14.0'
    }
    It 'returns null for a non-Electron dir (no asar / pak / v8 marker)' {
        $plain = Join-Path $script:work 'plain'; New-Item -ItemType Directory -Path $plain -Force | Out-Null
        [IO.File]::WriteAllText((Join-Path $plain 'tool.exe'), 'Chrome/146.0.7680.179 Electron/41.2.0')
        $rv = & (Get-Module TCPK) { param($d) Get-TcpkRuntimeVersions -Path $d } $plain
        $rv | Should -BeNullOrEmpty
    }
}

Describe 'Test-TcpkElectron: outdated-runtime finding' {
    It 'records the runtime version and flags an outdated Chromium (3 majors behind) as MEDIUM' {
        $f   = @(Test-TcpkElectron -Path $script:old)
        $ver = $f | Where-Object RuleId -eq 'electron.runtime-version'
        $ver           | Should -Not -BeNullOrEmpty
        $ver.Severity  | Should -Be 'INFO'
        $out = $f | Where-Object RuleId -eq 'electron.outdated-runtime'
        $out            | Should -Not -BeNullOrEmpty
        $out.Severity   | Should -Be 'MEDIUM'
        $out.Confidence | Should -Be 'Inferred'
        $out.Evidence   | Should -Match 'Chromium=146\.0\.7680\.179'
    }
    It 'does NOT flag a current runtime as outdated' {
        $f = @(Test-TcpkElectron -Path $script:cur)
        ($f | Where-Object RuleId -eq 'electron.runtime-version') | Should -Not -BeNullOrEmpty
        ($f | Where-Object RuleId -eq 'electron.outdated-runtime') | Should -BeNullOrEmpty
    }
}

Describe 'CVSS: outdated-runtime is not mis-scored as net-rce' {
    It 'electron.sandbox keeps the net-rce archetype; electron.outdated-runtime falls to per-finding' {
        $r = & (Get-Module TCPK) {
            $a = New-TcpkFinding -Module static -RuleId 'electron.sandbox' -Severity MEDIUM -Title 's'
            $b = New-TcpkFinding -Module static -RuleId 'electron.outdated-runtime' -Severity MEDIUM -Title 'o'
            [pscustomobject]@{ Sandbox = (Get-TcpkCvssVector $a); Outdated = (Get-TcpkCvssVector $b) }
        }
        $r.Sandbox.Source  | Should -Match 'archetype:net-rce'
        $r.Outdated.Source | Should -Be 'per-finding'
    }
}
