#requires -Version 5.1
# Pester 5: the pcap -> replay-request bridge. Only the PURE decode (ConvertFrom-TcpkHexString)
# is deterministic off Windows and tested here. The live tshark extraction
# (Get-TcpkHttpRequestsFromPcap / Get-TcpkJwtFromPcap) is exercised against a real capture on
# the operator's Windows box, where Wireshark/tshark is the shipping dependency.

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force
}

Describe 'ConvertFrom-TcpkHexString' {
    It 'decodes contiguous hex to bytes' {
        InModuleScope TCPK {
            $b = ConvertFrom-TcpkHexString '7b22726f6c65223a2275227d'
            [Text.Encoding]::UTF8.GetString($b) | Should -Be '{"role":"u"}'
        }
    }
    It 'decodes colon-separated hex identically' {
        InModuleScope TCPK {
            $b = ConvertFrom-TcpkHexString '48:65:6c:6c:6f'
            [Text.Encoding]::UTF8.GetString($b) | Should -Be 'Hello'
        }
    }
    It 'returns empty for odd-length or empty input (never throws)' {
        InModuleScope TCPK {
            (ConvertFrom-TcpkHexString 'abc').Length | Should -Be 0
            (ConvertFrom-TcpkHexString '').Length | Should -Be 0
        }
    }
}
