#requires -Version 5.1
# Pester 5: Test-TcpkLoopbackExempt (C35). The vendor-owned half of the AppContainer
# network-isolation bypass class -- the package registering a loopback exemption, which
# turns off the isolation that stops a sandboxed app reaching 127.0.0.1. The nine Project
# Zero AppContainer bugs are Windows enforcement bugs; this flags the app removing the
# boundary itself.

BeforeAll {
    Import-Module (Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1') -Force
    $script:root = Join-Path ([IO.Path]::GetTempPath()) ('tcpk-lbe-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:root | Out-Null
    function New-Pkg([hashtable]$Files) {
        $p = Join-Path $script:root ([guid]::NewGuid().ToString('N').Substring(0,8))
        New-Item -ItemType Directory -Path $p -Force | Out-Null
        foreach ($name in $Files.Keys) { Set-Content -LiteralPath (Join-Path $p $name) -Value $Files[$name] -Encoding UTF8 }
        return $p
    }
    function Rules($p) { return @(Test-TcpkLoopbackExempt -Path $p | Select-Object -ExpandProperty RuleId) }
}
AfterAll { if ($script:root -and (Test-Path $script:root)) { Remove-Item $script:root -Recurse -Force -ErrorAction SilentlyContinue } }

Describe 'Test-TcpkLoopbackExempt' {

    It 'flags a CheckNetIsolation LoopbackExempt call in an installer script' {
        $p = New-Pkg @{ 'install.bat' = 'CheckNetIsolation LoopbackExempt -a -n:Contoso_8wekyb3d8bbwe' }
        Rules $p | Should -Contain 'appcontainer.loopback-exempt'
    }

    It 'flags the Start-Process form where exe and verb are not adjacent' {
        $p = New-Pkg @{ 'setup.ps1' = 'Start-Process CheckNetIsolation -ArgumentList "LoopbackExempt -a -n:$pkg"' }
        Rules $p | Should -Contain 'appcontainer.loopback-exempt'
    }

    It 'does NOT fire on prose that merely mentions loopback' {
        # "loopback exempt" with a space is documentation, not the CheckNetIsolation verb.
        $p = New-Pkg @{ 'readme.txt' = 'This app may request a loopback exempt rule for debugging.' }
        Rules $p | Should -Not -Contain 'appcontainer.loopback-exempt'
    }

    It 'stays silent on a package with no exemption' {
        $p = New-Pkg @{ 'app.config' = '<configuration><appSettings/></configuration>' }
        @(Test-TcpkLoopbackExempt -Path $p) | Should -BeNullOrEmpty
    }

    It 'reports each file once, not once per shape' {
        $p = New-Pkg @{ 'both.ps1' = "CheckNetIsolation LoopbackExempt -a`r`nNetworkIsolationSetAppContainerConfig" }
        @(Test-TcpkLoopbackExempt -Path $p | Where-Object { $_.RuleId -eq 'appcontainer.loopback-exempt' }).Count | Should -Be 1
    }

    It 'is exported and runs in the audit' {
        Get-Command Test-TcpkLoopbackExempt -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
        $a = [IO.File]::ReadAllText((Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'Public\Invoke-TcpkAudit.ps1'))
        $a | Should -Match "_RunCheck 'Test-TcpkLoopbackExempt'"
    }
}
