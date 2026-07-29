function Invoke-TcpkPcapReview {
<#
.SYNOPSIS
    Analyse a packet capture (.pcap / .pcapng) for security issues, via the operator's
    installed Wireshark (tshark). Read-only: it dissects a capture you already made; it does
    not capture live and needs no admin.

.DESCRIPTION
    TCPK does not reimplement a packet sniffer. Capturing all traffic needs a kernel driver
    (npcap), which is what Wireshark installs -- so TCPK orchestrates the installed tshark to
    DISSECT a capture, then surfaces the security-relevant slice as findings:
      - HTTP Basic credentials sent in cleartext        (pcap.http-basic-cleartext, HIGH)
      - cleartext HTTP transport, per host              (pcap.cleartext-http, MEDIUM)
      - obsolete TLS negotiated (SSL3 / TLS1.0 / 1.1)   (pcap.weak-tls)
      - FTP credentials in cleartext                    (pcap.ftp-cleartext-cred, HIGH)
      - DNS query inventory                             (pcap.dns-queries, INFO)
      - endpoint inventory (host:port contacted)        (pcap.endpoints, INFO)

    Findings observed on the wire are 'Confirmed (dynamic)'. Requires tshark; if it is not
    installed the review returns a single 'Skipped' finding telling you to install Wireshark.

    This is the complement to Invoke-TcpkIntercept: interception sees HTTP flows through a proxy,
    this sees everything on the wire (all protocols, and metadata even for un-decryptable TLS).

.PARAMETER Path
    A .pcap or .pcapng capture file to analyse.

.PARAMETER TsharkPath
    Explicit path to tshark (overrides PATH / Wireshark install-dir discovery).

.OUTPUTS
    [TcpkFinding] -- pcap.* findings.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [string]$TsharkPath,
        [string]$KeylogFile,  # a TLS key log (SSLKEYLOGFILE) to DECRYPT TLS so HTTPS is analysed too
        [string]$RsaKeyFile   # a server RSA private key to DECRYPT RSA-key-exchange TLS (not ECDHE / 1.3)
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Capture file not found: $Path"
    }
    $pcap = (Resolve-Path -LiteralPath $Path).Path
    $klog = ''
    if ($KeylogFile) {
        if (Test-Path -LiteralPath $KeylogFile -PathType Leaf) { $klog = (Resolve-Path -LiteralPath $KeylogFile).Path }
        else { throw "Keylog file not found: $KeylogFile" }
    }
    $rkey = ''
    if ($RsaKeyFile) {
        if (Test-Path -LiteralPath $RsaKeyFile -PathType Leaf) { $rkey = (Resolve-Path -LiteralPath $RsaKeyFile).Path }
        else { throw "RSA key file not found: $RsaKeyFile" }
    }

    $tshark = Get-TcpkTshark -Override $TsharkPath
    if (-not $tshark) {
        return (New-TcpkFinding -Module 'network' -RuleId 'pcap.tshark-missing' -Severity 'INFO' `
            -Confidence 'Skipped' -Title 'tshark (Wireshark) not found -- pcap analysis skipped' `
            -File $pcap `
            -Description 'Install Wireshark (which includes tshark) to enable capture analysis. TCPK does not bundle it.' `
            -Fix 'Install Wireshark, or pass -TsharkPath to the tshark executable.')
    }

    $findings = @(Get-TcpkPcapFindings -Tshark $tshark -Pcap $pcap -KeylogFile $klog -RsaKeyFile $rkey)
    foreach ($f in $findings) { if (-not $f.File) { $f.File = $pcap } }
    if (-not $findings.Count) {
        return (New-TcpkFinding -Module 'network' -RuleId 'pcap.clean' -Severity 'INFO' `
            -Confidence 'Confirmed (dynamic)' -Title 'No cleartext credentials, weak TLS, or plaintext protocols observed' `
            -File $pcap -Description 'The capture was analysed and none of the checked issues were present.')
    }
    $findings
}
