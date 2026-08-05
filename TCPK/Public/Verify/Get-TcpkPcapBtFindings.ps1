function Get-TcpkPcapBtFindings {
<#
.SYNOPSIS
    Analyse a Bluetooth / BLE packet capture for security findings.

.DESCRIPTION
    Dissects a .pcap/.pcapng file via tshark and surfaces Bluetooth-specific
    security issues:
      - BLE JustWorks pairing (no MITM protection)       pcap.bt-justworks  HIGH
      - GATT Write operations in cleartext                pcap.bt-gatt-cleartext  HIGH
      - GATT Read responses in cleartext                  pcap.bt-gatt-read-cleartext  MEDIUM
      - BLE advertisement data / device fingerprinting    pcap.bt-adv  INFO
      - HCI trace presence (link-key and pairing state)   pcap.bt-hci  INFO

    Returns an empty array if the capture contains no Bluetooth frames.
    Requires tshark with Bluetooth dissector support (standard Wireshark install).

    Capture sources: Wireshark Bluetooth interface, HCI snoop log (btsnoop),
    Ubertooth One (via ubertooth-btle | wireshark), or Sniffle.

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
            -Confidence 'Skipped' -Title 'tshark not found -- Bluetooth analysis skipped' `
            -Evidence 'tshark not installed or not in PATH' `
            -Description 'Install Wireshark (which includes tshark) to enable Bluetooth pcap analysis.' -Fix '')
    }
    $pcap = (Resolve-Path -LiteralPath $Path).Path
    Get-TcpkBtPcapFindings -Tshark $tshark -Pcap $pcap
}
