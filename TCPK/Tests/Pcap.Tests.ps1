#requires -Version 5.1
# Pester 5: the pcap (packet-capture) analysis engine. The pure helpers and the
# graceful-degradation paths run everywhere. The findings-extraction test needs tshark
# (Wireshark) and self-skips if it is not installed, so this suite never fails for lack of
# an external tool. The test capture is embedded as base64 -- no fixture file, no text2pcap.

# Detect tshark at DISCOVERY time so the -Skip condition below can see it (a BeforeAll variable
# is not set until run time, after -Skip is already evaluated). Path + the Windows install dirs.
BeforeDiscovery {
    $script:hasTshark = [bool](Get-Command tshark -ErrorAction SilentlyContinue) `
        -or (Test-Path 'C:\Program Files\Wireshark\tshark.exe' -ErrorAction SilentlyContinue) `
        -or (Test-Path 'C:\Program Files (x86)\Wireshark\tshark.exe' -ErrorAction SilentlyContinue)
}

BeforeAll {
    $psd1 = Join-Path (Split-Path (Split-Path $PSCommandPath -Parent) -Parent) 'TCPK.psd1'
    Import-Module $psd1 -Force

    # a tiny pcapng: one HTTP GET carrying 'Authorization: Basic YWRtaW46c2VjcmV0' (admin:secret)
    $b64 = 'Cg0NCsQAAABNPCsaAQAAAP//////////AQAiAEdlbmVyYXRlZCBmcm9tIGlucHV0IGZpbGUgcmVxLmhleC4AAAIAPAAxMXRoIEdlbiBJbnRlbChSKSBDb3JlKFRNKSBpNy0xMTg1MEggQCAyLjUwR0h6ICh3aXRoIFNTRTQuMikDABYATGludXggNy4wLjAtMjgtZ2VuZXJpYwAABAAbAFRleHQycGNhcCAoV2lyZXNoYXJrKSA0LjYuNgAAAAAAxAAAAAEAAAA4AAAAAQAAAAAABAACABIARmFrZSBJRiwgdGV4dDJwY2FwAAAJAAEACQAAAAAAAAA4AAAABgAAAOAAAAAAAAAAB7/GGOhpX+m9AAAAvQAAACBSRUNWACBTRU5EAAgARQAArxI0AAD/BpIPCgEBAQoCAgKr4ABQAAAAAAAAAABQACAAjeEAAEdFVCAvYWRtaW4vY29uZmlnIEhUVFAvMS4xDQpIb3N0OiBwYW5lbC5jcmVzdHJvbi5sb2NhbA0KQXV0aG9yaXphdGlvbjogQmFzaWMgWVdSdGFXNDZjMlZqY21WMA0KVXNlci1BZ2VudDogQ3Jlc3Ryb25WaXJ0dWFsUGFuZWwvMS4wDQoNCgAAAOAAAAA='
    $script:pcap = Join-Path ([IO.Path]::GetTempPath()) ("tcpk-pcaptest-" + [guid]::NewGuid().ToString('N') + '.pcapng')
    [IO.File]::WriteAllBytes($script:pcap, [Convert]::FromBase64String($b64))
}

AfterAll { if ($script:pcap -and (Test-Path $script:pcap)) { Remove-Item $script:pcap -Force -ErrorAction SilentlyContinue } }

Describe 'pcap engine - pure helpers (run everywhere)' {
    It 'decodes HTTP Basic auth to the username, password redacted' {
        & (Get-Module TCPK) { ConvertFrom-TcpkBasicAuth 'Basic YWRtaW46c2VjcmV0' } | Should -Be 'admin'
    }
    It 'returns null for a non-Basic authorization' {
        & (Get-Module TCPK) { ConvertFrom-TcpkBasicAuth 'Bearer abc.def' } | Should -BeNullOrEmpty
    }
    It 'flags obsolete TLS versions and passes 1.2 / 1.3' {
        & (Get-Module TCPK) { (Get-TcpkTlsVersionInfo '0x0301').Weak } | Should -BeTrue    # TLS 1.0
        & (Get-Module TCPK) { (Get-TcpkTlsVersionInfo '0x0300').Weak } | Should -BeTrue    # SSL 3.0
        & (Get-Module TCPK) { (Get-TcpkTlsVersionInfo '0x0303').Weak } | Should -BeFalse   # TLS 1.2
        & (Get-Module TCPK) { (Get-TcpkTlsVersionInfo '0x0304').Weak } | Should -BeFalse   # TLS 1.3
    }
    It 'Get-TcpkTshark does not throw on any platform (no C: drive validation)' {
        { & (Get-Module TCPK) { Get-TcpkTshark } } | Should -Not -Throw
    }
}

Describe 'Invoke-TcpkPcapReview - contract and graceful degradation' {
    It 'throws a clear error for a missing capture file' {
        { Invoke-TcpkPcapReview -Path (Join-Path ([IO.Path]::GetTempPath()) 'tcpk-no-such.pcap') } | Should -Throw
    }
    It 'returns a Skipped finding (not a throw) when tshark is unavailable' {
        InModuleScope TCPK -Parameters @{ p = $script:pcap } {
            param($p)
            Mock Get-TcpkTshark { $null }
            $f = Invoke-TcpkPcapReview -Path $p
            @($f).Count | Should -Be 1
            $f.RuleId     | Should -Be 'pcap.tshark-missing'
            $f.Confidence | Should -Be 'Skipped'
        }
    }
}

Describe 'Invoke-TcpkPcapReview - findings from a real capture' {
    It 'flags the cleartext HTTP Basic credentials' -Skip:(-not $script:hasTshark) {
        $f = @(Invoke-TcpkPcapReview -Path $script:pcap)
        $basic = $f | Where-Object { $_.RuleId -eq 'pcap.http-basic-cleartext' }
        $basic | Should -Not -BeNullOrEmpty
        "$($basic.Severity)"   | Should -Be 'HIGH'
        "$($basic.Evidence)"   | Should -Match "admin"
        "$($basic.Confidence)" | Should -Be 'Confirmed (dynamic)'
    }
}
