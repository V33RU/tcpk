function Get-TcpkPcapConversations {
<#
.SYNOPSIS
    Extract per-conversation statistics from a packet capture.

.DESCRIPTION
    Reads a .pcap/.pcapng via tshark and returns one row per unique
    (src IP:port, dst IP:port, protocol) conversation, with packet count
    and byte total. Sorted by bytes descending.

.PARAMETER Path
    A .pcap or .pcapng file to analyse.

.PARAMETER TsharkPath
    Explicit path to tshark (overrides auto-discovery).

.PARAMETER KeylogFile
    SSLKEYLOGFILE path -- decrypts TLS so dissected protocols are visible.

.PARAMETER RsaKeyFile
    Server RSA private key -- decrypts RSA-kx TLS sessions.

.PARAMETER Max
    Maximum frames to read (default 5000; raise for very large captures).

.OUTPUTS
    [ordered] rows: Date, Time, SrcIP, SrcPort, SrcMAC, DstIP, DstPort, DstMAC,
                    Protocol, Packets, Bytes, FirstInfo
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [string]$TsharkPath,
        [string]$KeylogFile,
        [string]$RsaKeyFile,
        [int]$Max = 5000
    )
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "Capture file not found: $Path" }
    $tshark = Get-TcpkTshark -Override $TsharkPath
    if (-not $tshark) {
        Write-Warning 'tshark not found -- install Wireshark to enable conversation stats.'
        return
    }
    $pcap = (Resolve-Path -LiteralPath $Path).Path
    $klog = ''; if ($KeylogFile -and (Test-Path -LiteralPath $KeylogFile)) { $klog = (Resolve-Path -LiteralPath $KeylogFile).Path }
    $rkey = ''; if ($RsaKeyFile -and (Test-Path -LiteralPath $RsaKeyFile)) { $rkey = (Resolve-Path -LiteralPath $RsaKeyFile).Path }
    Get-TcpkConvStats -Tshark $tshark -Pcap $pcap -KeylogFile $klog -RsaKeyFile $rkey -Max $Max
}
