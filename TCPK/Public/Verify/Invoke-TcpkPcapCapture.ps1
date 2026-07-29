function Invoke-TcpkPcapCapture {
<#
.SYNOPSIS
    Capture live traffic on an interface (via the operator's dumpcap), then analyse it for
    security issues. LIVE capture needs a capture driver (npcap on Windows) and elevation -- it
    is the operator's dumpcap doing the privileged work; TCPK ships no driver.

.DESCRIPTION
    Runs dumpcap for -Seconds on -Interface into a temp .pcapng, then runs the same analysis as
    Invoke-TcpkPcapReview over it (optionally decrypting TLS with -KeylogFile). Returns the
    pcap.* findings. Use Get-TcpkCaptureInterface to list interfaces first.

.PARAMETER Interface
    Interface name (from Get-TcpkCaptureInterface), e.g. 'Ethernet' or 'eth0'.

.PARAMETER Seconds
    Capture duration in seconds (default 20). Blocks for the duration.

.PARAMETER Filter
    Optional capture (BPF) filter, e.g. 'host 10.0.0.5 and port 443'.

.PARAMETER KeylogFile
    Optional TLS key log (SSLKEYLOGFILE) to decrypt TLS so HTTPS is analysed too.

.PARAMETER Keep
    Keep the captured .pcapng (its path goes to the verbose stream). Default: delete it after analysis.

.OUTPUTS
    [TcpkFinding] -- pcap.* findings from the captured traffic.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Interface,
        [int]$Seconds = 20,
        [string]$Filter,
        [string]$KeylogFile,
        [string]$RsaKeyFile,
        [switch]$Keep
    )
    $pcap = Invoke-TcpkPcapCaptureFile -Interface $Interface -Seconds $Seconds -Filter $Filter
    Write-Verbose "captured to $pcap"
    try {
        Invoke-TcpkPcapReview -Path $pcap -KeylogFile $KeylogFile -RsaKeyFile $RsaKeyFile
    } finally {
        if (-not $Keep -and (Test-Path -LiteralPath $pcap)) {
            Remove-Item -LiteralPath $pcap -Force -ErrorAction SilentlyContinue
        }
    }
}
