function Get-TcpkPcapZigbeeFindings {
<#
.SYNOPSIS
    Analyse a Zigbee / IEEE 802.15.4 packet capture for security findings.

.DESCRIPTION
    Dissects a .pcap/.pcapng file via tshark and surfaces Zigbee-specific
    security issues:
      - Unencrypted NWK frames (AES-CCM* disabled)       pcap.zigbee-unencrypted  HIGH
      - Transport Key broadcast in the air                pcap.zigbee-transport-key  CRITICAL
      - IEEE 802.15.4 MAC frames without security         (counted in summary)
      - Zigbee frame inventory                            pcap.zigbee-summary  INFO

    Returns an empty array if the capture contains no Zigbee/802.15.4 frames.
    Requires tshark with Zigbee dissector support (standard Wireshark install).

    Capture sources: RZUSBSTICK, ApiMote, Sniffle, Ubertooth (with 802.15.4 firmware),
    or any libpcap-capable 802.15.4 sniffer with LINKTYPE_IEEE802_15_4 link type.

.PARAMETER Path
    A .pcap or .pcapng file to analyse.

.PARAMETER TsharkPath
    Explicit path to tshark.

.OUTPUTS
    [TcpkFinding] with confidence 'Confirmed (dynamic)'.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [string]$TsharkPath
    )
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "Capture file not found: $Path" }
    $tshark = Get-TcpkTshark -Override $TsharkPath
    if (-not $tshark) {
        return (New-TcpkFinding -Module 'network' -RuleId 'pcap.tshark-missing' -Severity 'INFO' `
            -Confidence 'Skipped' -Title 'tshark not found -- Zigbee analysis skipped' `
            -Evidence 'tshark not installed or not in PATH' `
            -Description 'Install Wireshark (which includes tshark) to enable Zigbee pcap analysis.' -Fix '')
    }
    $pcap = (Resolve-Path -LiteralPath $Path).Path
    Get-TcpkZigbeePcapFindings -Tshark $tshark -Pcap $pcap
}
