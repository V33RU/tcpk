#requires -Version 5.1
# A42 Test-TcpkElectronFuses -- parses the @electron/fuses wire from the app binary. Unlike the
# electronjs.* leads, fuse state is a Confirmed binary fact. Fixtures embed the sentinel + a
# crafted fuse wire at runtime (binary control bytes can't be a committed text fixture).

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
    $script:work = Join-Path ([IO.Path]::GetTempPath()) ("tcpk-fuses-" + [guid]::NewGuid().ToString('N'))
    function New-FuseApp {
        param($Dir, $Wire)
        New-Item -ItemType Directory -Path $Dir -Force | Out-Null
        [IO.File]::WriteAllText((Join-Path $Dir 'app.asar'), 'asar marker')   # electron gate
        $pre  = [Text.Encoding]::ASCII.GetBytes("MZ" + ([string]::new('A', 256)) + "dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX")
        $body = [byte[]]@(1, $Wire.Length) + [Text.Encoding]::ASCII.GetBytes($Wire)
        [IO.File]::WriteAllBytes((Join-Path $Dir 'TheApp.exe'), [byte[]]($pre + $body))
    }
    $script:vuln  = Join-Path $script:work 'vuln';  New-FuseApp $script:vuln  '101100011'   # run-as-node on, cookie off, inspect on, asar-integrity off
    $script:clean = Join-Path $script:work 'clean'; New-FuseApp $script:clean '010011000'   # all secure
    $script:plain = Join-Path $script:work 'plain'; New-Item -ItemType Directory -Path $script:plain -Force | Out-Null
    [IO.File]::WriteAllBytes((Join-Path $script:plain 'rand.exe'), [Text.Encoding]::ASCII.GetBytes("MZ no fuses here"))

    $script:v = @(Test-TcpkElectronFuses -Path $script:vuln)
    $script:c = @(Test-TcpkElectronFuses -Path $script:clean)
    $script:n = @(Test-TcpkElectronFuses -Path $script:plain)
}
AfterAll { if ($script:work -and (Test-Path -LiteralPath $script:work)) { [IO.Directory]::Delete($script:work, $true) } }

Describe 'Electron fuses (insecure binary)' {
    It 'parses the wire and reports the posture as a Confirmed fact' {
        $p = @($script:v | Where-Object RuleId -eq 'fuses.posture')
        @($p).Count       | Should -BeGreaterThan 0
        $p[0].Confidence  | Should -Be 'Confirmed'
        $p[0].Evidence    | Should -Match '101100011'
    }
    It 'flags cookie-encryption-disabled (MEDIUM) and the node/asar hardening gaps' {
        @($script:v | Where-Object RuleId -eq 'fuses.cookie-encryption-disabled')[0].Severity | Should -Be 'MEDIUM'
        @($script:v | Where-Object RuleId -eq 'fuses.run-as-node-enabled').Count     | Should -BeGreaterThan 0
        @($script:v | Where-Object RuleId -eq 'fuses.node-inspect-enabled').Count    | Should -BeGreaterThan 0
        @($script:v | Where-Object RuleId -eq 'fuses.asar-integrity-disabled').Count | Should -BeGreaterThan 0
    }
}

Describe 'Electron fuses (hardened binary)' {
    It 'reports posture but no insecure-fuse findings when fuses are secure' {
        @($script:c | Where-Object RuleId -eq 'fuses.posture').Count | Should -BeGreaterThan 0
        @($script:c | Where-Object { $_.RuleId -like 'fuses.*' -and $_.RuleId -ne 'fuses.posture' }).Count | Should -Be 0
    }
}

Describe 'Electron fuses (gate / no wire)' {
    It 'reports nothing on a non-Electron directory' {
        @($script:n | Where-Object { $_.RuleId -like 'fuses.*' }).Count | Should -Be 0
    }
}
