#requires -Version 5.1
# v1.8.2 live progress: Write-TcpkProgress must never throw (a progress failure must not abort
# a scan) and must forward the heartbeat to a registered host hook (the web-panel / GUI contract).

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
}

Describe 'Write-TcpkProgress' {
    It 'does not throw when Total is 0 (no divide-by-zero)' {
        { & (Get-Module TCPK) { Write-TcpkProgress -Activity 'x' -Status 'y' -Current 0 -Total 0 } } | Should -Not -Throw
    }
    It 'forwards the heartbeat to a registered host hook' {
        $got = & (Get-Module TCPK) {
            $script:got = $null
            $script:TcpkProgressHook = { param($a, $s, $c, $t) $script:got = "$a|$s|$c|$t" }
            try { Write-TcpkProgress -Activity 'Secrets scan' -Status 'f.txt [1/3]' -Current 1 -Total 3 }
            finally { $script:TcpkProgressHook = $null }
            $script:got
        }
        $got | Should -Be 'Secrets scan|f.txt [1/3]|1|3'
    }
}
