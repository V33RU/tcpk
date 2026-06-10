#requires -Version 5.1
# The LLM judge must be able to LOCATE the method behind a generic callsites.* finding.
# Those rules name the weakness (command-execution), not a method, so a name match never
# lands -- the method is found by the sink API it INVOKES (Get-TcpkMethodIl -CallsApi,
# driven by the shared Get-TcpkCallsiteSinkApiRegex). Skips if Mono.Cecil is absent.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
    $script:cecil = $false
    try { $script:cecil = & (Get-Module TCPK) { Test-TcpkCecilAvailable } } catch { }

    $script:work = Join-Path ([IO.Path]::GetTempPath()) ("tcpk-mloc-" + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $script:work -Force | Out-Null
    if ($script:cecil) {
        # method whose NAME says nothing about the weakness, but invokes Process.Start
        $src = "using System; using System.Diagnostics; public class Worker { public void HandleRequest(string p){ Process.Start(p); } }"
        $script:dll = Join-Path $script:work 'Worker.dll'
        Add-Type -TypeDefinition $src -OutputAssembly $script:dll -OutputType Library -ReferencedAssemblies 'System'
    }
}

AfterAll {
    if ($script:work -and (Test-Path -LiteralPath $script:work)) {
        try { [System.IO.Directory]::Delete($script:work, $true) } catch {}
    }
}

Describe 'Get-TcpkCallsiteSinkApiRegex (shared sink-API regex)' {
    It 'builds a regex over the command-execution sink names' {
        $rx = & (Get-Module TCPK) { Get-TcpkCallsiteSinkApiRegex 'command-execution' }
        $rx | Should -Match 'Process'
        'System.Diagnostics.Process::Start' | Should -Match $rx
    }
    It 'returns null for an unknown suffix' {
        $rx = & (Get-Module TCPK) { Get-TcpkCallsiteSinkApiRegex 'not-a-real-rule' }
        $rx | Should -BeNullOrEmpty
    }
    It 'stays in sync with the shared sink map (same families)' {
        $keys = & (Get-Module TCPK) { (Get-TcpkCallsiteSinkMap).Keys }
        @($keys) -contains 'command-execution' | Should -BeTrue
    }
}

Describe 'Get-TcpkMethodIl -CallsApi (locate by invoked sink)' {
    BeforeEach { if (-not $script:cecil) { Set-ItResult -Skipped -Because 'Mono.Cecil (ILSpy) not available' } }

    It 'does NOT find the method by the rule suffix alone (the old miss)' {
        $m = & (Get-Module TCPK) { param($d) Get-TcpkMethodIl -DllPath $d -SymbolHint 'command-execution' -MaxMethods 2 } $script:dll
        $m | Should -BeNullOrEmpty
    }
    It 'DOES find the method by the sink API it invokes' {
        $rx = & (Get-Module TCPK) { Get-TcpkCallsiteSinkApiRegex 'command-execution' }
        $m = & (Get-Module TCPK) { param($d,$r) Get-TcpkMethodIl -DllPath $d -SymbolHint 'command-execution' -CallsApi $r -MaxMethods 2 } $script:dll $rx
        @($m).Count | Should -BeGreaterThan 0
        $m[0].Method | Should -Be 'HandleRequest'
    }
}
