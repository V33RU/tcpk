function Get-TcpkPcapTlsTree {
<#
.SYNOPSIS
    Extract TLS handshake tree (ClientHello + ServerHello per server) from a capture.

.DESCRIPTION
    Reads ClientHello (type 1) and ServerHello (type 2) frames via tshark and
    builds a tree keyed by "server_ip:port". Each node contains:
      ClientHellos - per-client: SNI, offered cipher list, supported TLS versions
      ServerHellos - per-session: negotiated version, selected cipher, key exchange group
    ServerHellos whose selected cipher is weak are flagged (WeakCipher property).

.PARAMETER Path
    A .pcap or .pcapng file to analyse.

.PARAMETER TsharkPath
    Explicit path to tshark.

.PARAMETER KeylogFile
    SSLKEYLOGFILE for TLS decryption (needed to see application data; handshake
    metadata is always visible even without keys).

.PARAMETER RsaKeyFile
    Server RSA private key for RSA-kx TLS decryption.

.OUTPUTS
    [ordered hashtable] keyed by "ip:port". Values are ordered dicts with
    keys ClientHellos and ServerHellos (each a List of pscustomobjects).
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [string]$TsharkPath,
        [string]$KeylogFile,
        [string]$RsaKeyFile
    )
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "Capture file not found: $Path" }
    $tshark = Get-TcpkTshark -Override $TsharkPath
    if (-not $tshark) {
        Write-Warning 'tshark not found -- install Wireshark to enable TLS tree analysis.'
        return
    }
    $pcap = (Resolve-Path -LiteralPath $Path).Path
    $klog = ''; if ($KeylogFile -and (Test-Path -LiteralPath $KeylogFile)) { $klog = (Resolve-Path -LiteralPath $KeylogFile).Path }
    $rkey = ''; if ($RsaKeyFile -and (Test-Path -LiteralPath $RsaKeyFile)) { $rkey = (Resolve-Path -LiteralPath $RsaKeyFile).Path }
    Get-TcpkTlsSessionTree -Tshark $tshark -Pcap $pcap -KeylogFile $klog -RsaKeyFile $rkey
}
