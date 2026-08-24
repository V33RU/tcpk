function Test-TcpkDiscoveryProtocols {
<#
.SYNOPSIS
    A51. Local-network device-discovery protocols the client speaks.

.DESCRIPTION
    Companion apps discover devices on the LAN with mDNS, SSDP/UPnP, WS-Discovery, ONVIF probe
    messages, or a vendor UDP broadcast. That surface is worth naming because each protocol has
    its own failure mode: mDNS accepts responses from any host on the segment, SSDP has been
    used for reflection and takeover, WS-Discovery is XML over UDP with schema attacks, ONVIF
    accepts crafted probes without authentication.

    This cmdlet detects references, not live behaviour. Inferred throughout; a pcap of the
    client's first ten seconds proves what it actually sends.

.PARAMETER Path
    Install directory or single binary.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    # Each protocol: display name, .NET / string markers, native imports, why it matters.
    $protos = @(
        @{ Kind = 'mdns';        Sev = 'MEDIUM'
           Needles = @('_tcp.local','_udp.local','MulticastDnsResponder','Zeroconf','Bonjour','DNSSDResolveServiceInstance','dns-sd')
           Why = 'mDNS resolves .local names by trusting whatever responds first on the segment. A LAN attacker can be that responder.' }
        @{ Kind = 'ssdp-upnp';   Sev = 'MEDIUM'
           Needles = @('239.255.255.250','ssdp:discover','M-SEARCH','urn:schemas-upnp-org','UPnP/','urn:dial-multiscreen')
           Why = 'SSDP has a 20-year record of amplification, reflection and device-takeover primitives. The client speaks it before it authenticates.' }
        @{ Kind = 'ws-discovery'; Sev = 'MEDIUM'
           Needles = @('urn:schemas-xmlsoap-org:ws/2005/04/discovery','WS-Discovery','soap:Envelope','http://schemas.xmlsoap.org/ws/2005/04/discovery')
           Why = 'WS-Discovery is XML over UDP multicast. XML external entity and schema-confusion bugs both apply, and there is no authentication on the probe response.' }
        @{ Kind = 'onvif';       Sev = 'MEDIUM'
           Needles = @('http://www.onvif.org/ver10','onvif','NetworkVideoTransmitter','tds:Device','tt:PTZ')
           Why = 'ONVIF discovery accepts crafted probes without authentication. Subsequent SOAP calls often have wsse:UsernameToken with a fixed nonce.' }
        @{ Kind = 'llmnr-netbios'; Sev = 'LOW'
           Needles = @('LLMNR','NetBIOS','__MSBROWSE__','WNet','WNetEnumResource')
           Why = 'LLMNR and NetBIOS name resolution are the classic AD LAN spoofing surface (Responder/Inveigh). A client relying on them for device names accepts LAN-attacker-supplied endpoints.' }
        @{ Kind = 'vendor-broadcast'; Sev = 'INFO'
           Needles = @('UdpClient.Send','SocketFlags.Broadcast','SO_BROADCAST','sendto.*255.255.255.255')
           Why = 'A raw UDP broadcast is often a vendor discovery protocol. Reverse-engineer the framing; there is usually no authentication.' }
    )

    if (-not (Test-Path -LiteralPath $Path)) { return }
    $items = @()
    if ((Get-Item -LiteralPath $Path).PSIsContainer) {
        try { $items = @(Get-TcpkPeFiles -Path $Path) } catch { return }
    } else {
        try { $items = @([IO.FileInfo]::new((Resolve-Path -LiteralPath $Path).Path)) } catch { return }
    }

    foreach ($pe in $items) {
        if (Test-TcpkIsFrameworkFile $pe.Name) { continue }
        $text = Read-TcpkAllText -Path $pe.FullName
        if (-not $text) { continue }

        foreach ($p in $protos) {
            $hits = New-Object 'System.Collections.Generic.List[string]'
            foreach ($n in $p.Needles) {
                if ([regex]::IsMatch($text, [regex]::Escape($n))) { $hits.Add($n) }
            }
            if ($hits.Count -eq 0) { continue }

            New-TcpkFinding -Module 'discovery' -RuleId "discovery.$($p.Kind)" `
                -Severity $p.Sev -Confidence 'Inferred' `
                -Title "$($pe.Name) speaks $($p.Kind) for device discovery" `
                -File $pe.FullName -Evidence (($hits | Select-Object -First 5) -join ', ') `
                -Description ("The binary contains references consistent with the $($p.Kind) discovery " +
                    "protocol. " + $p.Why + " A LAN capture of the client's start-up proves the wire behaviour.") `
                -Fix 'No fix required. This is scope: a tester on the same segment can respond to discovery and see how the client validates the responder.'
        }
    }
}
