function Search-TcpkPcapString {
<#
.SYNOPSIS
    Search for a string or regex pattern across all frames in a capture.

.DESCRIPTION
    Uses tshark's "frame matches" display filter to find every frame that contains
    the given pattern anywhere in its dissected content. Case-insensitive by default.
    Returns one row per matching frame with frame number, time, src/dst, protocol,
    and the info summary line.

    Useful for finding which packets carry a specific token, hostname, parameter name,
    error string, or any other known payload fragment.

.PARAMETER Path
    A .pcap or .pcapng file to search.

.PARAMETER Pattern
    The string to search for. By default this is treated as a literal string (special
    regex characters are escaped). Pass -Regex to use it as a PCRE regex.

.PARAMETER Regex
    If set, $Pattern is used as a raw PCRE regex (case-insensitive via (?i) wrapper).

.PARAMETER Protocol
    Restrict the search to frames of a specific dissector:
    http, dns, tls, smtp, ftp, btle, zbee_nwk, etc. Default: All.

.PARAMETER Max
    Maximum matching frames to return (default 500).

.PARAMETER TsharkPath
    Explicit path to tshark.

.PARAMETER KeylogFile
    SSLKEYLOGFILE for TLS decryption -- enables searching decrypted HTTPS content.

.PARAMETER RsaKeyFile
    RSA private key for RSA-kx TLS decryption.

.OUTPUTS
    [pscustomobject] rows: frame.number, frame.time_relative, ip.src, ip.dst,
                           _ws.col.Protocol, _ws.col.Info
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Pattern,
        [switch]$Regex,
        [string]$Protocol,
        [int]$Max = 500,
        [string]$TsharkPath,
        [string]$KeylogFile,
        [string]$RsaKeyFile
    )
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "Capture file not found: $Path" }
    $tshark = Get-TcpkTshark -Override $TsharkPath
    if (-not $tshark) { throw 'tshark not found -- install Wireshark.' }
    $pcap = (Resolve-Path -LiteralPath $Path).Path
    $klog = ''; if ($KeylogFile -and (Test-Path -LiteralPath $KeylogFile)) { $klog = (Resolve-Path -LiteralPath $KeylogFile).Path }
    $rkey = ''; if ($RsaKeyFile -and (Test-Path -LiteralPath $RsaKeyFile)) { $rkey = (Resolve-Path -LiteralPath $RsaKeyFile).Path }
    Invoke-TcpkPcapStringSearch -Tshark $tshark -Pcap $pcap -Pattern $Pattern `
        -Protocol $Protocol -Regex:$Regex -Max $Max -KeylogFile $klog -RsaKeyFile $rkey
}
