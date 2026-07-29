# Packet-capture (pcap/pcapng) analysis. TCPK does NOT capture packets and does NOT ship a
# capture driver: capturing all traffic needs a kernel driver (npcap), which is what Wireshark
# installs. TCPK orchestrates the operator's installed Wireshark CLI (tshark) to DISSECT a
# capture the operator already made, then surfaces the security-relevant slice as findings.
# Same pattern as the mitmproxy interception path (Get-TcpkMitmdump); here the tool is tshark.
#
# Everything here reads a capture FILE. It never captures live and never needs admin.

# Locate tshark: explicit override, repo tools\wireshark\, the Windows Wireshark install dirs
# (Wireshark does NOT add itself to PATH), then PATH. Returns the path or $null.
function Get-TcpkTshark {
    param([string]$Override)
    $cands = @()
    if ($Override) { $cands += $Override }
    $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent   # repo root (parent of TCPK\)
    $cands += (Join-Path $repo 'tools/wireshark/tshark')
    $cands += (Join-Path $repo 'tools/wireshark/tshark.exe')
    # standard Windows install locations (built as plain strings, not Join-Path, so it never
    # tries to validate a non-existent 'C:' drive on a non-Windows box)
    foreach ($pf in @($env:ProgramFiles, ${env:ProgramFiles(x86)}, 'C:\Program Files', 'C:\Program Files (x86)')) {
        if ($pf) { $cands += ($pf.TrimEnd('\', '/') + '\Wireshark\tshark.exe') }
    }
    foreach ($c in $cands) {
        try { if ($c -and (Test-Path -LiteralPath $c -ErrorAction SilentlyContinue)) { return (Resolve-Path -LiteralPath $c).Path } } catch { }
    }
    $cmd = Get-Command 'tshark' -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    return $null
}

# Run one tshark field query over a capture and return rows as ordered dictionaries keyed by the
# requested field names. Deterministic (-n = no name resolution). Fully guarded: a tshark error,
# a bad capture, or empty output yields an empty array, never a throw. $Max caps rows returned.
function Invoke-TcpkTsharkQuery {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Tshark,
        [Parameter(Mandatory)][string]$Pcap,
        [string]$Filter,
        [Parameter(Mandatory)][string[]]$Fields,
        [int]$Max = 0
    )
    $sep = "`t"
    $a = @('-r', $Pcap, '-n')
    if ($Filter) { $a += @('-Y', $Filter) }
    $a += @('-T', 'fields', '-E', "separator=$sep", '-E', 'occurrence=f')
    foreach ($f in $Fields) { $a += @('-e', $f) }
    $lines = @()
    try { $lines = & $Tshark @a 2>$null } catch { return @() }
    if (-not $lines) { return @() }
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($ln in @($lines)) {
        if ($null -eq $ln -or "$ln" -eq '') { continue }
        $parts = "$ln" -split $sep, $Fields.Count
        $o = [ordered]@{}
        for ($i = 0; $i -lt $Fields.Count; $i++) {
            $o[$Fields[$i]] = if ($i -lt $parts.Count) { $parts[$i] } else { '' }
        }
        $rows.Add([pscustomobject]$o)
        if ($Max -gt 0 -and $rows.Count -ge $Max) { break }
    }
    return $rows.ToArray()
}

# Map a tls.handshake.version value (as tshark prints it) to a friendly name + weak flag.
function Get-TcpkTlsVersionInfo {
    param([string]$Raw)
    $v = "$Raw".Trim().ToLower()
    switch ($v) {
        '0x0300' { return @{ Name = 'SSL 3.0'; Weak = $true;  Sev = 'HIGH' } }
        '0x0301' { return @{ Name = 'TLS 1.0'; Weak = $true;  Sev = 'HIGH' } }
        '0x0302' { return @{ Name = 'TLS 1.1'; Weak = $true;  Sev = 'MEDIUM' } }
        '0x0303' { return @{ Name = 'TLS 1.2'; Weak = $false; Sev = 'INFO' } }
        '0x0304' { return @{ Name = 'TLS 1.3'; Weak = $false; Sev = 'INFO' } }
        default  { return @{ Name = $Raw;      Weak = $false; Sev = 'INFO' } }
    }
}

# Decode an HTTP Basic authorization value to 'user' (password redacted). Returns $null if not Basic.
function ConvertFrom-TcpkBasicAuth {
    param([string]$Header)
    $h = "$Header".Trim()
    if ($h -notmatch '^(?i)basic\s+(.+)$') { return $null }
    $b64 = $Matches[1].Trim()
    try {
        $txt = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b64))
        $user = ($txt -split ':', 2)[0]
        return $user
    } catch { return $null }
}

# The analysis: run the finding queries and emit [TcpkFinding]s. Observed-on-the-wire evidence,
# so Confidence is 'Confirmed (dynamic)'. Every query is independently guarded, so one failing
# dissector never sinks the rest.
function Get-TcpkPcapFindings {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Tshark, [Parameter(Mandatory)][string]$Pcap)
    $out = New-Object System.Collections.Generic.List[object]

    # 1. HTTP Basic credentials in cleartext (highest value)
    foreach ($r in (Invoke-TcpkTsharkQuery -Tshark $Tshark -Pcap $Pcap -Filter 'http.authorization' `
                        -Fields @('ip.dst', 'http.host', 'http.request.uri', 'http.authorization'))) {
        $user = ConvertFrom-TcpkBasicAuth $r.'http.authorization'
        if (-not $user) { continue }
        $host_ = if ($r.'http.host') { $r.'http.host' } else { $r.'ip.dst' }
        $out.Add((New-TcpkFinding -Module 'network' -RuleId 'pcap.http-basic-cleartext' -Severity 'HIGH' `
            -Confidence 'Confirmed (dynamic)' -Cwe @('CWE-319', 'CWE-522') `
            -Title "HTTP Basic credentials sent in cleartext to $host_" `
            -Evidence "user '$user' (password redacted) -> http://$host_$($r.'http.request.uri')" `
            -Description 'HTTP Basic auth was observed on the wire over plaintext HTTP. The credentials are recoverable by anyone on the path.' `
            -Fix 'Use HTTPS and a token-based scheme; never send Basic auth over plaintext HTTP.'))
    }

    # 2. Cleartext HTTP transport (one finding per host)
    $httpHosts = @{}
    foreach ($r in (Invoke-TcpkTsharkQuery -Tshark $Tshark -Pcap $Pcap -Filter 'http.request' `
                        -Fields @('ip.dst', 'tcp.dstport', 'http.host'))) {
        $h = if ($r.'http.host') { $r.'http.host' } else { $r.'ip.dst' }
        if ($h) { $httpHosts[$h] = "$($r.'ip.dst'):$($r.'tcp.dstport')" }
    }
    foreach ($h in $httpHosts.Keys) {
        $out.Add((New-TcpkFinding -Module 'network' -RuleId 'pcap.cleartext-http' -Severity 'MEDIUM' `
            -Confidence 'Confirmed (dynamic)' -Cwe @('CWE-319') `
            -Title "Cleartext HTTP traffic to $h" `
            -Evidence "$h ($($httpHosts[$h])) served over plaintext HTTP" `
            -Description 'The client exchanged HTTP over plaintext. Anything sent (tokens, data) is visible on the path.' `
            -Fix 'Serve the endpoint over HTTPS and redirect HTTP to HTTPS.'))
    }

    # 3. Weak / obsolete TLS negotiated (from the ServerHello)
    $tlsSeen = @{}
    foreach ($r in (Invoke-TcpkTsharkQuery -Tshark $Tshark -Pcap $Pcap -Filter 'tls.handshake.type == 2' `
                        -Fields @('ip.src', 'tls.handshake.version'))) {
        $info = Get-TcpkTlsVersionInfo $r.'tls.handshake.version'
        if (-not $info.Weak) { continue }
        $key = "$($r.'ip.src')|$($info.Name)"
        if ($tlsSeen.ContainsKey($key)) { continue }
        $tlsSeen[$key] = $true
        $out.Add((New-TcpkFinding -Module 'network' -RuleId 'pcap.weak-tls' -Severity $info.Sev `
            -Confidence 'Confirmed (dynamic)' -Cwe @('CWE-326', 'CWE-327') `
            -Title "Obsolete TLS negotiated ($($info.Name)) with $($r.'ip.src')" `
            -Evidence "server $($r.'ip.src') negotiated $($info.Name)" `
            -Description 'The server accepted an obsolete TLS version. These versions have known weaknesses and are deprecated.' `
            -Fix 'Require TLS 1.2 or 1.3 and disable SSL 3.0 / TLS 1.0 / 1.1 on the server.'))
    }

    # 4. FTP credentials in cleartext
    $ftp = Invoke-TcpkTsharkQuery -Tshark $Tshark -Pcap $Pcap `
                -Filter 'ftp.request.command == "USER" || ftp.request.command == "PASS"' `
                -Fields @('ip.dst', 'ftp.request.command', 'ftp.request.arg')
    $ftpHosts = @($ftp | ForEach-Object { $_.'ip.dst' } | Where-Object { $_ } | Sort-Object -Unique)
    foreach ($h in $ftpHosts) {
        $u = @($ftp | Where-Object { $_.'ip.dst' -eq $h -and $_.'ftp.request.command' -eq 'USER' } | ForEach-Object { $_.'ftp.request.arg' } | Select-Object -First 1)
        $out.Add((New-TcpkFinding -Module 'network' -RuleId 'pcap.ftp-cleartext-cred' -Severity 'HIGH' `
            -Confidence 'Confirmed (dynamic)' -Cwe @('CWE-319') `
            -Title "FTP credentials sent in cleartext to $h" `
            -Evidence "user '$u' (password redacted) over plaintext FTP to $h" `
            -Description 'FTP USER/PASS were observed on the wire in cleartext.' `
            -Fix 'Use FTPS or SFTP; never send FTP credentials over plaintext.'))
    }

    # 5. DNS query inventory (INFO -- host discovery / telemetry)
    $dns = @(Invoke-TcpkTsharkQuery -Tshark $Tshark -Pcap $Pcap -Filter 'dns.flags.response == 0' -Fields @('dns.qry.name') |
                ForEach-Object { $_.'dns.qry.name' } | Where-Object { $_ } | Sort-Object -Unique)
    if ($dns.Count) {
        $list = ($dns | Select-Object -First 40) -join ', '
        $out.Add((New-TcpkFinding -Module 'network' -RuleId 'pcap.dns-queries' -Severity 'INFO' `
            -Confidence 'Confirmed (dynamic)' `
            -Title "$($dns.Count) DNS name(s) queried by the target" `
            -Evidence $list `
            -Description 'Domains the client resolved. Review for unexpected backends, telemetry, or exfiltration hosts.'))
    }

    # 6. Endpoint inventory (INFO)
    $eps = @{}
    foreach ($r in (Invoke-TcpkTsharkQuery -Tshark $Tshark -Pcap $Pcap `
                        -Fields @('ip.dst', 'tcp.dstport', 'udp.dstport', '_ws.col.Protocol'))) {
        $port = if ($r.'tcp.dstport') { $r.'tcp.dstport' } else { $r.'udp.dstport' }
        if (-not $r.'ip.dst') { continue }
        $eps["$($r.'ip.dst'):$port"] = $r.'_ws.col.Protocol'
    }
    if ($eps.Count) {
        $list = (@($eps.Keys | Sort-Object) | Select-Object -First 40) -join ', '
        $out.Add((New-TcpkFinding -Module 'network' -RuleId 'pcap.endpoints' -Severity 'INFO' `
            -Confidence 'Confirmed (dynamic)' `
            -Title "$($eps.Count) endpoint(s) contacted by the target" `
            -Evidence $list `
            -Description 'Host:port pairs the client contacted. Review for unexpected or hardcoded backends.'))
    }

    return $out.ToArray()
}

# Packet list for the UI: bounded (default 2000 rows) so a huge capture never floods the browser.
function Get-TcpkPcapPackets {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Tshark, [Parameter(Mandatory)][string]$Pcap, [int]$Max = 2000)
    $rows = Invoke-TcpkTsharkQuery -Tshark $Tshark -Pcap $Pcap -Max $Max `
                -Fields @('frame.number', 'frame.time_relative', 'ip.src', 'ipv6.src', 'ip.dst', 'ipv6.dst', '_ws.col.Protocol', 'frame.len', '_ws.col.Info')
    foreach ($r in $rows) {
        [ordered]@{
            no    = $r.'frame.number'
            time  = $r.'frame.time_relative'
            src   = if ($r.'ip.src') { $r.'ip.src' } else { $r.'ipv6.src' }
            dst   = if ($r.'ip.dst') { $r.'ip.dst' } else { $r.'ipv6.dst' }
            proto = $r.'_ws.col.Protocol'
            len   = $r.'frame.len'
            info  = $r.'_ws.col.Info'
        }
    }
}
