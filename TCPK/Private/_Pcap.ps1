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
        [int]$Max = 0,
        [string]$KeylogFile,  # TLS session-key log (SSLKEYLOGFILE) -> decrypt TLS so HTTPS dissects
        [string]$RsaKeyFile,  # server RSA private key -> decrypt RSA-key-exchange TLS (not ECDHE / 1.3)
        [string]$Occurrence = 'f',  # tshark -E occurrence: f=first (default, back-compat), a=all, l=last
        [string]$Aggregator         # tshark -E aggregator: joins multi-occurrence values in one field
    )
    $sep = "`t"
    $a = @('-r', $Pcap, '-n')
    if ($KeylogFile -and (Test-Path -LiteralPath $KeylogFile)) { $a += @('-o', "tls.keylog_file:$KeylogFile") }
    if ($RsaKeyFile -and (Test-Path -LiteralPath $RsaKeyFile)) { $a += @('-o', ('uat:rsa_keys:"' + $RsaKeyFile + '",""')) }
    if ($Filter) { $a += @('-Y', $Filter) }
    $a += @('-T', 'fields', '-E', "separator=$sep", '-E', "occurrence=$Occurrence")
    if ($Aggregator) { $a += @('-E', "aggregator=$Aggregator") }
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

# --------------------------------------------------- pcap -> replay-request bridge ----
# Decode a tshark hex string (http.file_data etc., contiguous or colon-separated) to bytes.
# Odd-length or empty input -> empty array (never throws).
function ConvertFrom-TcpkHexString {
    [CmdletBinding()] param([AllowEmptyString()][string]$Hex)
    if ([string]::IsNullOrEmpty($Hex)) { return , ([byte[]]@()) }
    $clean = ($Hex -replace '[^0-9a-fA-F]', '')
    if ($clean.Length -eq 0 -or ($clean.Length % 2) -ne 0) { return , ([byte[]]@()) }
    $bytes = New-Object byte[] ($clean.Length / 2)
    for ($i = 0; $i -lt $bytes.Length; $i++) { $bytes[$i] = [Convert]::ToByte($clean.Substring($i * 2, 2), 16) }
    return , $bytes
}

# Reconstruct HTTP requests from a capture as replay-request specs. TLS keys decrypt first.
# tshark gives method/host/uri/all-header-lines (aggregated)/body-hex/dstport per request.
function Get-TcpkHttpRequestsFromPcap {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Tshark, [Parameter(Mandatory)][string]$Pcap, [string]$KeylogFile, [string]$RsaKeyFile, [int]$Max = 0)
    $us = [char]0x1F
    $rows = Invoke-TcpkTsharkQuery -Tshark $Tshark -Pcap $Pcap -Filter 'http.request' `
        -Fields @('http.request.method', 'http.host', 'http.request.uri', 'http.request.line', 'http.file_data', 'tcp.dstport') `
        -Occurrence 'a' -Aggregator "$us" -KeylogFile $KeylogFile -RsaKeyFile $RsaKeyFile -Max $Max
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($r in @($rows)) {
        $method = "$($r.'http.request.method')"; if (-not $method) { continue }
        # multi-request TCP streams can aggregate; take the first value of single-valued fields
        $method = ($method -split $us)[0]
        $hostH = (("$($r.'http.host')") -split $us)[0]
        $uri = (("$($r.'http.request.uri')") -split $us)[0]
        if (-not $uri) { $uri = '/' }
        $port = (("$($r.'tcp.dstport')") -split $us)[0]
        $scheme = if ($port -eq '443' -or $KeylogFile -or $RsaKeyFile) { 'https' } else { 'http' }
        if (-not $hostH) { $hostH = 'unknown.host' }
        $url = "${scheme}://${hostH}${uri}"
        $headerLines = @()
        foreach ($hl in ("$($r.'http.request.line')" -split $us)) { $t = "$hl".TrimEnd("`r", "`n"); if ($t) { $headerLines += $t } }
        $spec = New-TcpkRequestSpec -Method $method -Url $url -Header $headerLines
        $bodyHex = (("$($r.'http.file_data')") -split $us)[0]
        if ($bodyHex) { $spec.Body = ConvertFrom-TcpkHexString $bodyHex; $spec.ContentType = if ($spec.Headers.Contains('Content-Type')) { "$($spec.Headers['Content-Type'])" } else { $spec.ContentType } }
        $out.Add($spec)
    }
    return $out.ToArray()
}

# One request spec from a capture (by index) for the replay/IDOR engines.
function ConvertFrom-TcpkPcapRequest {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Tshark, [Parameter(Mandatory)][string]$Pcap, [string]$KeylogFile, [string]$RsaKeyFile, [int]$Index = 0)
    $reqs = @(Get-TcpkHttpRequestsFromPcap -Tshark $Tshark -Pcap $Pcap -KeylogFile $KeylogFile -RsaKeyFile $RsaKeyFile)
    if ($reqs.Count -eq 0) { throw "no HTTP requests found in $Pcap (need cleartext HTTP, or TLS keys to decrypt HTTPS)." }
    if ($Index -lt 0 -or $Index -ge $reqs.Count) { throw "request index $Index out of range (capture has $($reqs.Count) request(s))." }
    return $reqs[$Index]
}

# Pull the first Bearer JWT (and where it rode) from a capture for the JWT toolkit.
function Get-TcpkJwtFromPcap {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Pcap, [Parameter(Mandatory)][string]$Tshark, [string]$KeylogFile, [string]$RsaKeyFile)
    $rxJwt = 'eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*'
    foreach ($r in @(Invoke-TcpkTsharkQuery -Tshark $Tshark -Pcap $Pcap -Filter 'http.authorization' -Fields @('http.authorization') -KeylogFile $KeylogFile -RsaKeyFile $RsaKeyFile)) {
        if ("$($r.'http.authorization')" -match "Bearer\s+($rxJwt)") { return [pscustomobject]@{ Token = $Matches[1]; Location = 'header' } }
    }
    $us = [char]0x1F
    foreach ($r in @(Invoke-TcpkTsharkQuery -Tshark $Tshark -Pcap $Pcap -Filter 'http.request' -Fields @('http.request.line') -Occurrence 'a' -Aggregator "$us" -KeylogFile $KeylogFile -RsaKeyFile $RsaKeyFile)) {
        foreach ($line in ("$($r.'http.request.line')" -split $us)) {
            if ($line -match "([A-Za-z0-9_\-]+)=($rxJwt)" -and $line -imatch '^\s*Cookie\s*:') { return [pscustomobject]@{ Token = $Matches[2]; Location = 'cookie:' + $Matches[1] } }
            if ($line -match "($rxJwt)") {
                $tok = $Matches[1]
                if ($line -imatch '^\s*([A-Za-z0-9\-]+)\s*:' -and $Matches[1] -inotmatch '^Authorization$') { return [pscustomobject]@{ Token = $tok; Location = 'rawheader:' + $Matches[1] } }
                return [pscustomobject]@{ Token = $tok; Location = 'header' }
            }
        }
    }
    return $null
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
    param([Parameter(Mandatory)][string]$Tshark, [Parameter(Mandatory)][string]$Pcap, [string]$KeylogFile, [string]$RsaKeyFile)
    $out = New-Object System.Collections.Generic.List[object]
    $q = @{ Tshark = $Tshark; Pcap = $Pcap }
    if ($KeylogFile) { $q.KeylogFile = $KeylogFile }
    if ($RsaKeyFile) { $q.RsaKeyFile = $RsaKeyFile }

    # 1. HTTP Basic credentials in cleartext (highest value; dedup by host+user)
    $seenBasic = @{}
    foreach ($r in (Invoke-TcpkTsharkQuery @q -Filter 'http.authorization' `
                        -Fields @('ip.dst', 'http.host', 'http.request.uri', 'http.authorization'))) {
        $user = ConvertFrom-TcpkBasicAuth $r.'http.authorization'
        if (-not $user) { continue }
        $host_ = if ($r.'http.host') { $r.'http.host' } else { $r.'ip.dst' }
        if ($seenBasic.ContainsKey("$host_|$user")) { continue }
        $seenBasic["$host_|$user"] = $true
        $out.Add((New-TcpkFinding -Module 'network' -RuleId 'pcap.http-basic-cleartext' -Severity 'HIGH' `
            -Confidence 'Confirmed (dynamic)' -Cwe @('CWE-319', 'CWE-522') `
            -Title "HTTP Basic credentials sent in cleartext to $host_" `
            -Evidence "user '$user' (password redacted) -> http://$host_$($r.'http.request.uri')" `
            -Description 'HTTP Basic auth was observed on the wire over plaintext HTTP. The credentials are recoverable by anyone on the path.' `
            -Fix 'Use HTTPS and a token-based scheme; never send Basic auth over plaintext HTTP.'))
    }

    # 2. Cleartext HTTP transport (one finding per host)
    $httpHosts = @{}
    foreach ($r in (Invoke-TcpkTsharkQuery @q -Filter 'http.request' `
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
    foreach ($r in (Invoke-TcpkTsharkQuery @q -Filter 'tls.handshake.type == 2' `
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
    $ftp = Invoke-TcpkTsharkQuery @q `
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
    $dns = @(Invoke-TcpkTsharkQuery @q -Filter 'dns.flags.response == 0' -Fields @('dns.qry.name') |
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
    foreach ($r in (Invoke-TcpkTsharkQuery @q `
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
    param([Parameter(Mandatory)][string]$Tshark, [Parameter(Mandatory)][string]$Pcap, [int]$Max = 2000, [string]$KeylogFile, [string]$RsaKeyFile)
    $q = @{ Tshark = $Tshark; Pcap = $Pcap }
    if ($KeylogFile) { $q.KeylogFile = $KeylogFile }
    if ($RsaKeyFile) { $q.RsaKeyFile = $RsaKeyFile }
    $rows = Invoke-TcpkTsharkQuery @q -Max $Max `
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

# --- LIVE CAPTURE (drives the operator's dumpcap; needs a capture driver + elevation) ---------
# TCPK does not capture itself. Live capture needs a kernel driver (npcap on Windows), which
# Wireshark installs. These orchestrate the operator's dumpcap: their tool, their driver, their
# privileges. Off Windows dumpcap needs CAP_NET_RAW; if it cannot capture, the runner throws a
# clear error rather than pretending.

# Locate dumpcap (mirrors Get-TcpkTshark). Windows paths are plain strings (no C: drive validation).
function Get-TcpkDumpcap {
    param([string]$Override)
    $cands = @()
    if ($Override) { $cands += $Override }
    $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $cands += (Join-Path $repo 'tools/wireshark/dumpcap')
    $cands += (Join-Path $repo 'tools/wireshark/dumpcap.exe')
    foreach ($pf in @($env:ProgramFiles, ${env:ProgramFiles(x86)}, 'C:\Program Files', 'C:\Program Files (x86)')) {
        if ($pf) { $cands += ($pf.TrimEnd('\', '/') + '\Wireshark\dumpcap.exe') }
    }
    foreach ($c in $cands) {
        try { if ($c -and (Test-Path -LiteralPath $c -ErrorAction SilentlyContinue)) { return (Resolve-Path -LiteralPath $c).Path } } catch { }
    }
    $cmd = Get-Command 'dumpcap' -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    return $null
}

# List capture interfaces via 'tshark -D'. Returns [{ Id; Name; Desc }]. Empty if tshark absent.
function Get-TcpkCaptureInterfaces {
    param([string]$TsharkPath)
    $tshark = if ($TsharkPath) { $TsharkPath } else { Get-TcpkTshark }
    if (-not $tshark) { return @() }
    $lines = @()
    try { $lines = & $tshark -D 2>$null } catch { return @() }
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($ln in @($lines)) {
        if ("$ln" -match '^\s*(\d+)\.\s+(\S+)(?:\s+\((.+)\))?\s*$') {
            $out.Add([pscustomobject][ordered]@{ Id = $Matches[1]; Name = $Matches[2]; Desc = "$($Matches[3])" })
        }
    }
    return $out.ToArray()
}

# Capture $Seconds on $Interface into a pcapng and return the file path. Blocks for the duration.
function Invoke-TcpkPcapCaptureFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Interface,
        [int]$Seconds = 20,
        [string]$Filter,        # capture (BPF) filter, e.g. 'host 10.0.0.5 and port 443'
        [string]$OutFile,
        [string]$DumpcapPath
    )
    $dumpcap = Get-TcpkDumpcap -Override $DumpcapPath
    if (-not $dumpcap) { throw "dumpcap not found -- install Wireshark (it includes dumpcap)." }
    if ($Seconds -lt 1) { $Seconds = 1 }
    if (-not $OutFile) { $OutFile = Join-Path ([IO.Path]::GetTempPath()) ('tcpk-cap-' + [guid]::NewGuid().ToString('N') + '.pcapng') }
    $a = @('-i', $Interface, '-a', "duration:$Seconds", '-w', $OutFile, '-q')
    if ($Filter) { $a += @('-f', $Filter) }
    try { & $dumpcap @a 2>&1 | Out-Null } catch { throw "dumpcap failed: $($_.Exception.Message)" }
    if (-not (Test-Path -LiteralPath $OutFile)) {
        throw "capture produced no file -- dumpcap needs a capture driver (npcap on Windows) and elevation."
    }
    return (Resolve-Path -LiteralPath $OutFile).Path
}
