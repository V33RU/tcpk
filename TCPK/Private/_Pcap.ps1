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

    # 7. TLS cipher suite weakness (from ServerHello -- what was actually negotiated)
    $cipherSeen = @{}
    foreach ($r in (Invoke-TcpkTsharkQuery @q -Filter 'tls.handshake.type == 2' `
                        -Fields @('ip.src', 'tls.handshake.ciphersuite'))) {
        $srv    = "$($r.'ip.src')"
        $cipher = "$($r.'tls.handshake.ciphersuite')".Trim()
        if (-not $cipher -or $cipherSeen.ContainsKey("$srv|$cipher")) { continue }
        $cipherSeen["$srv|$cipher"] = $true
        $weak = Test-TcpkCipherWeak $cipher
        if (-not $weak) { continue }
        $out.Add((New-TcpkFinding -Module 'network' -RuleId 'pcap.weak-cipher' -Severity $weak.Severity `
            -Confidence 'Confirmed (dynamic)' -Cwe @('CWE-326', 'CWE-327') `
            -Title "Weak TLS cipher negotiated with $srv -- $cipher" `
            -Evidence "server $srv selected $cipher ($($weak.Reason))" `
            -Description "The server negotiated a weak or broken cipher suite. Traffic in this TLS session is at elevated risk of decryption or forgery." `
            -Fix "Remove $cipher from the server's cipher list. Permit only AES-GCM and ChaCha20-Poly1305 suites."))
    }

    # 8. Credential or secret in HTTP URL query parameters
    $secretRx = '(?i)[?&](token|api[_-]?key|apikey|access[_-]?token|password|passwd|pwd|secret|auth|client[_-]?secret|refresh[_-]?token)=[^&\s]{1,}'
    $secretSeen = @{}
    foreach ($r in (Invoke-TcpkTsharkQuery @q -Filter 'http.request' `
                        -Fields @('ip.dst', 'http.host', 'http.request.uri'))) {
        $uri = "$($r.'http.request.uri')"
        if ($uri -notmatch $secretRx) { continue }
        $host_ = if ($r.'http.host') { $r.'http.host' } else { $r.'ip.dst' }
        $paramKey = ($Matches[1] + '').ToLower()
        $key = "$host_|$paramKey"
        if ($secretSeen.ContainsKey($key)) { continue }
        $secretSeen[$key] = $true
        $truncated = $Matches[0] -replace '(=[^&]{4})[^&]*', '$1...'
        $out.Add((New-TcpkFinding -Module 'network' -RuleId 'pcap.secret-in-url' -Severity 'HIGH' `
            -Confidence 'Confirmed (dynamic)' -Cwe @('CWE-598', 'CWE-319') `
            -Title "Credential or token in HTTP URL params sent to $host_" `
            -Evidence "param $truncated in request to $host_" `
            -Description "A sensitive parameter ($paramKey) was observed in the HTTP URL query string. URL params are logged by servers, proxies, load balancers, and browser history -- they are not a safe location for secrets." `
            -Fix 'Move tokens and credentials to Authorization or custom request headers, or a POST body. Never embed them in the URL.'))
    }

    # 9. Cookie security flags (Secure / HttpOnly absent, or cookie set over cleartext HTTP)
    $cookieSeen = @{}
    foreach ($r in (Invoke-TcpkTsharkQuery @q -Filter 'http.set_cookie' `
                        -Fields @('ip.src', 'tcp.srcport', 'http.set_cookie'))) {
        $cookie   = "$($r.'http.set_cookie')"
        $isHttps  = ($r.'tcp.srcport' -eq '443')
        $name_    = if ($cookie -match '^([^=;]+)') { $Matches[1].Trim() } else { '?' }
        $missSecure   = $cookie -notmatch '(?i)\bSecure\b'
        $missHttpOnly = $cookie -notmatch '(?i)\bHttpOnly\b'
        if ($isHttps -and -not $missSecure -and -not $missHttpOnly) { continue }
        $key = "$($r.'ip.src')|$name_"
        if ($cookieSeen.ContainsKey($key)) { continue }
        $cookieSeen[$key] = $true
        $flags = @()
        if (-not $isHttps) { $flags += 'set over cleartext HTTP' }
        if ($missSecure)   { $flags += 'Secure flag missing' }
        if ($missHttpOnly) { $flags += 'HttpOnly flag missing' }
        $out.Add((New-TcpkFinding -Module 'network' -RuleId 'pcap.insecure-cookie' -Severity 'MEDIUM' `
            -Confidence 'Confirmed (dynamic)' -Cwe @('CWE-614', 'CWE-1004') `
            -Title "Insecure cookie '$name_' from $($r.'ip.src') ($($flags -join ', '))" `
            -Evidence "Set-Cookie: $($cookie.Substring(0, [math]::Min(100, $cookie.Length)))..." `
            -Description "Cookie '$name_' is set without adequate security flags. Missing Secure allows transmission over HTTP; missing HttpOnly allows JavaScript access (XSS pivot)." `
            -Fix "Add Secure;HttpOnly to all session cookies. Add SameSite=Strict for sensitive sessions."))
    }

    # 10. SMTP cleartext authentication (AUTH LOGIN / AUTH PLAIN observed in cleartext)
    $smtpSeen = @{}
    foreach ($r in (Invoke-TcpkTsharkQuery @q -Filter 'smtp.req.command == "AUTH"' `
                        -Fields @('ip.dst', 'smtp.req.parameter'))) {
        $param = "$($r.'smtp.req.parameter')".ToUpper().Trim()
        if ($param -notmatch '^(LOGIN|PLAIN|CRAM-MD5)') { continue }
        $h = "$($r.'ip.dst')"
        if ($smtpSeen.ContainsKey($h)) { continue }
        $smtpSeen[$h] = $true
        $out.Add((New-TcpkFinding -Module 'network' -RuleId 'pcap.smtp-cleartext-auth' -Severity 'HIGH' `
            -Confidence 'Confirmed (dynamic)' -Cwe @('CWE-319', 'CWE-522') `
            -Title "SMTP AUTH credentials transmitted in cleartext to $h" `
            -Evidence "SMTP AUTH $param to $h without TLS" `
            -Description "SMTP AUTH $param credentials were observed on the wire without an enclosing TLS layer. Any path observer can recover them." `
            -Fix 'Require STARTTLS (port 587) or implicit TLS (port 465) before any AUTH command. Reject AUTH on unencrypted connections.'))
    }

    # 11. Telnet cleartext session (TCP 23) -- all keystrokes and credentials visible
    $telnetSeen = @{}
    foreach ($r in @(Invoke-TcpkTsharkQuery @q -Filter 'tcp.dstport == 23' `
                        -Fields @('ip.dst','ip.src') -Max 5)) {
        $h = "$($r.'ip.dst')"
        if (-not $h -or $telnetSeen.ContainsKey($h)) { continue }
        $telnetSeen[$h] = $true
        $out.Add((New-TcpkFinding -Module 'network' -RuleId 'pcap.telnet-cleartext' -Severity 'CRITICAL' `
            -Confidence 'Confirmed (dynamic)' -Cwe @('CWE-319','CWE-522') `
            -Title "Telnet session to $h -- all keystrokes and credentials in cleartext" `
            -Evidence "TCP port 23 connection from $($r.'ip.src') to $h" `
            -Description 'Telnet is fully plaintext. Every keystroke, command, and response including credentials is visible to any on-path observer.' `
            -Fix 'Replace Telnet with SSH. Disable the Telnet service on all devices.'))
    }

    # 12. MQTT cleartext broker traffic (TCP 1883 -- no TLS)
    $mqttSeen = @{}
    foreach ($r in @(Invoke-TcpkTsharkQuery @q -Filter 'tcp.dstport == 1883' `
                        -Fields @('ip.dst','ip.src') -Max 5)) {
        $h = "$($r.'ip.dst')"
        if (-not $h -or $mqttSeen.ContainsKey($h)) { continue }
        $mqttSeen[$h] = $true
        $out.Add((New-TcpkFinding -Module 'network' -RuleId 'pcap.mqtt-cleartext' -Severity 'HIGH' `
            -Confidence 'Confirmed (dynamic)' -Cwe @('CWE-319') `
            -Title "MQTT cleartext broker traffic to $h (TCP 1883 -- no TLS)" `
            -Evidence "TCP port 1883 from $($r.'ip.src') to $h" `
            -Description 'MQTT over TCP 1883 (no TLS) exposes all publish/subscribe messages, topic names, and CONNECT credentials (username/password) to passive observers.' `
            -Fix 'Use MQTT over TLS (port 8883). Enforce TLS 1.2+ on the broker. Use client certificate authentication.'))
    }

    # 13. HTTP POST with credentials in form body (password= / passwd= / pwd= in POST frame)
    $fCredSeen = @{}
    foreach ($r in @(Invoke-TcpkTsharkQuery @q `
                        -Filter '(http.request.method == "POST") and (frame matches "(?i)(password=|passwd=|pwd=|pass=)")' `
                        -Fields @('ip.dst','http.host','http.request.uri') -Max 20)) {
        $host_ = if ($r.'http.host') { $r.'http.host' } else { $r.'ip.dst' }
        $u     = "$($r.'http.request.uri')"
        $key   = "$host_|$u"
        if ($fCredSeen.ContainsKey($key)) { continue }
        $fCredSeen[$key] = $true
        $out.Add((New-TcpkFinding -Module 'network' -RuleId 'pcap.form-cred-cleartext' -Severity 'CRITICAL' `
            -Confidence 'Confirmed (dynamic)' -Cwe @('CWE-319','CWE-522') `
            -Title "Form credential POST in cleartext to $host_" `
            -Evidence "POST $u to $host_ -- body contains password or credential field" `
            -Description 'A login form POST containing a password field was observed over plaintext HTTP. The credentials are recoverable by any on-path observer.' `
            -Fix 'Serve the login endpoint over HTTPS exclusively. Redirect all HTTP traffic to HTTPS at the load balancer.'))
    }

    # 14. LDAP cleartext bind (TCP 389 -- credentials exposed without TLS)
    $ldapSeen = @{}
    foreach ($r in @(Invoke-TcpkTsharkQuery @q -Filter 'tcp.dstport == 389' `
                        -Fields @('ip.dst','ip.src') -Max 5)) {
        $h = "$($r.'ip.dst')"
        if (-not $h -or $ldapSeen.ContainsKey($h)) { continue }
        $ldapSeen[$h] = $true
        $out.Add((New-TcpkFinding -Module 'network' -RuleId 'pcap.ldap-cleartext' -Severity 'HIGH' `
            -Confidence 'Confirmed (dynamic)' -Cwe @('CWE-319','CWE-522') `
            -Title "LDAP cleartext connection to $h (TCP 389 -- no TLS)" `
            -Evidence "LDAP port 389 from $($r.'ip.src') to $h -- Distinguished Name and password transmitted in cleartext" `
            -Description 'LDAP Simple Bind over TCP 389 transmits the DN and password in cleartext. Any observer between the client and LDAP server can recover Active Directory or LDAP credentials.' `
            -Fix 'Use LDAPS (TCP 636) or LDAP with StartTLS. Require signing and sealing on all LDAP connections (AD: set domain controller LDAP signing policy to Required).'))
    }

    # 15. SNMP v1 / v2c community string exposed in cleartext (UDP 161)
    $snmpSeen = @{}
    foreach ($r in @(Invoke-TcpkTsharkQuery @q -Filter 'snmp' `
                        -Fields @('ip.dst','snmp.community','snmp.version') -Max 20)) {
        $comm = "$($r.'snmp.community')"; $h = "$($r.'ip.dst')"
        if (-not $comm -or -not $h) { continue }
        $key = "$h|$comm"
        if ($snmpSeen.ContainsKey($key)) { continue }
        $snmpSeen[$key] = $true
        $sev = if ($comm -imatch '^(public|private|community|default|admin)$') { 'CRITICAL' } else { 'HIGH' }
        $ver = "$($r.'snmp.version')"
        $out.Add((New-TcpkFinding -Module 'network' -RuleId 'pcap.snmp-community' -Severity $sev `
            -Confidence 'Confirmed (dynamic)' -Cwe @('CWE-319','CWE-260') `
            -Title "SNMP community string in cleartext to $h (community='$comm')" `
            -Evidence "SNMP v$ver community='$comm' to $h over UDP 161" `
            -Description "SNMP v1/v2c authenticates via community string sent in cleartext UDP. An observer can capture the string and query or (if write community) modify MIB objects on the device." `
            -Fix 'Migrate to SNMPv3 with authPriv (auth=SHA-256, priv=AES-256). Disable SNMPv1 and SNMPv2c. Change community strings from all defaults.'))
    }

    # 16. DNS exfiltration pattern -- abnormally long subdomain labels (>40 chars)
    $dnsExfil = @{}
    foreach ($r in @(Invoke-TcpkTsharkQuery @q -Filter 'dns.flags.response == 0' `
                        -Fields @('ip.dst','dns.qry.name') -Max 2000)) {
        $name = "$($r.'dns.qry.name')"
        if (-not $name) { continue }
        $labels    = $name -split '\.'
        $longLabel = @($labels | Where-Object { $_.Length -gt 40 } | Select-Object -First 1)
        if ($longLabel.Count -eq 0) { continue }
        $tld = if ($labels.Count -ge 2) { ($labels[-2] + '.' + $labels[-1]) } else { $name }
        if ($dnsExfil.ContainsKey($tld)) { continue }
        $dnsExfil[$tld] = $true
        $sample = $longLabel[0]
        $out.Add((New-TcpkFinding -Module 'network' -RuleId 'pcap.dns-exfil' -Severity 'HIGH' `
            -Confidence 'Confirmed (dynamic)' -Cwe @('CWE-201') `
            -Title "DNS exfiltration pattern -- abnormally long subdomain label to $tld ($($sample.Length) chars)" `
            -Evidence "label: ${sample}....$tld" `
            -Description 'DNS queries with subdomain labels exceeding 40 chars are a signature of DNS-based data exfiltration. Data is base32/base64/hex-encoded into labels to bypass firewall restrictions using the DNS channel.' `
            -Fix 'Block outbound DNS except to approved resolvers. Deploy DNS inspection and response policy zones. Investigate the process and domain generating these queries.'))
    }

    # 17. NTLM / Negotiate authentication over cleartext HTTP (hash capture / relay risk)
    $ntlmSeen = @{}
    foreach ($r in @(Invoke-TcpkTsharkQuery @q -Filter 'http.authorization' `
                        -Fields @('ip.dst','tcp.dstport','http.host','http.authorization') -Max 30)) {
        $auth  = "$($r.'http.authorization')"
        $dport = "$($r.'tcp.dstport')"
        if ($dport -eq '443' -or $auth -notmatch '(?i)^(NTLM|Negotiate)\s+') { continue }
        $h = if ($r.'http.host') { $r.'http.host' } else { $r.'ip.dst' }
        if ($ntlmSeen.ContainsKey($h)) { continue }
        $ntlmSeen[$h] = $true
        $scheme = ($auth -split '\s+')[0]
        $out.Add((New-TcpkFinding -Module 'network' -RuleId 'pcap.ntlm-http' -Severity 'HIGH' `
            -Confidence 'Confirmed (dynamic)' -Cwe @('CWE-319','CWE-522') `
            -Title "NTLM/Negotiate authentication over cleartext HTTP to $h" `
            -Evidence "Authorization: $scheme ... over TCP $dport to $h" `
            -Description 'NTLM challenge-response was observed over plaintext HTTP. An attacker can capture NTLM hashes for offline cracking or perform relay attacks (NTLM relay / Pass-the-Hash) even though the password is not sent in full cleartext.' `
            -Fix 'Use Kerberos or token-based authentication. If NTLM is unavoidable, enforce HTTPS. Disable NTLMv1 via LmCompatibilityLevel >= 3.'))
    }

    # 18. Sensitive HTTP path access (.env, .git, /admin, /config, credentials, etc.)
    $sensPathSeen = @{}
    $sensRx = '(?i)/(\.env|\.git|admin|manager|phpmyadmin|config\.php|backup|api[_\-]?key|passwd|credentials|secret|private)'
    foreach ($r in @(Invoke-TcpkTsharkQuery @q `
                        -Filter "frame matches `"$sensRx`"" `
                        -Fields @('ip.dst','http.host','http.request.uri') -Max 50)) {
        $uri = "$($r.'http.request.uri')"
        if (-not $uri -or $uri -notmatch $sensRx) { continue }
        $host_ = if ($r.'http.host') { $r.'http.host' } else { $r.'ip.dst' }
        $key = "$host_|$($Matches[0])"
        if ($sensPathSeen.ContainsKey($key)) { continue }
        $sensPathSeen[$key] = $true
        $out.Add((New-TcpkFinding -Module 'network' -RuleId 'pcap.sensitive-path' -Severity 'HIGH' `
            -Confidence 'Confirmed (dynamic)' -Cwe @('CWE-538','CWE-200') `
            -Title "Sensitive path request: $uri on $host_" `
            -Evidence "Request to $host_$uri" `
            -Description 'A request to a sensitive or potentially exposed path was observed. These paths often expose configuration data, credentials, admin interfaces, or source control repositories.' `
            -Fix 'Block access to admin and configuration paths at the web server or WAF layer. Apply deny-by-default for /admin, /.*  and configuration paths from the internet.'))
    }

    # 19. JWT Bearer token transmitted over cleartext HTTP (full token captured on wire)
    $jwtHttpSeen = @{}
    $rxJwtPfx = 'eyJ[A-Za-z0-9_\-]{20,}'
    foreach ($r in @(Invoke-TcpkTsharkQuery @q -Filter 'http.authorization' `
                        -Fields @('ip.dst','tcp.dstport','http.host','http.authorization') -Max 20)) {
        $auth  = "$($r.'http.authorization')"
        $dport = "$($r.'tcp.dstport')"
        if ($dport -eq '443' -or $auth -notmatch "(?i)Bearer\s+($rxJwtPfx)") { continue }
        $h = if ($r.'http.host') { $r.'http.host' } else { $r.'ip.dst' }
        if ($jwtHttpSeen.ContainsKey($h)) { continue }
        $jwtHttpSeen[$h] = $true
        $tok = $Matches[1].Substring(0, [Math]::Min(40, $Matches[1].Length)) + '...'
        $out.Add((New-TcpkFinding -Module 'network' -RuleId 'pcap.jwt-cleartext' -Severity 'CRITICAL' `
            -Confidence 'Confirmed (dynamic)' -Cwe @('CWE-319','CWE-345') `
            -Title "JWT Bearer token transmitted in cleartext HTTP to $h" `
            -Evidence "Authorization: Bearer $tok over TCP $dport to $h" `
            -Description 'A JWT Bearer token was observed in a cleartext HTTP Authorization header. The full token is recoverable by any on-path observer. Possession allows impersonation until expiry.' `
            -Fix 'Serve ALL API endpoints exclusively over HTTPS. Reject requests on port 80. Rotate the captured token immediately and investigate for unauthorized use.'))
    }

    # 20. ARP spoofing indicator -- same IP claimed by multiple MAC addresses
    $arpIpMacs = @{}
    foreach ($r in @(Invoke-TcpkTsharkQuery @q -Filter 'arp.opcode == 2' `
                        -Fields @('arp.src.proto_ipv4','arp.src.hw_mac') -Max 2000)) {
        $ip = "$($r.'arp.src.proto_ipv4')"; $mac = "$($r.'arp.src.hw_mac')"
        if (-not $ip -or -not $mac) { continue }
        if (-not $arpIpMacs.ContainsKey($ip)) {
            $arpIpMacs[$ip] = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        }
        [void]$arpIpMacs[$ip].Add($mac)
    }
    foreach ($ip in $arpIpMacs.Keys) {
        if ($arpIpMacs[$ip].Count -lt 2) { continue }
        $macs = (@($arpIpMacs[$ip]) | Select-Object -First 4) -join ', '
        $out.Add((New-TcpkFinding -Module 'network' -RuleId 'pcap.arp-spoof' -Severity 'CRITICAL' `
            -Confidence 'Confirmed (dynamic)' -Cwe @('CWE-290','CWE-345') `
            -Title "ARP spoofing detected -- IP $ip claimed by $($arpIpMacs[$ip].Count) different MACs" `
            -Evidence "IP $ip -> MACs: $macs" `
            -Description 'ARP replies from multiple distinct MAC addresses for the same IP were detected. This is the hallmark of ARP cache poisoning, used for MITM attacks, session hijacking, and DoS on LAN segments.' `
            -Fix 'Enable Dynamic ARP Inspection (DAI) on managed switches. Use static ARP entries for critical hosts. Deploy 802.1X port authentication. Investigate the duplicate MAC source immediately.'))
    }

    # 21. VNC cleartext remote desktop (TCP 5900-5910 -- no TLS tunnel)
    $vncSeen = @{}
    foreach ($r in @(Invoke-TcpkTsharkQuery @q `
                        -Filter 'tcp.dstport >= 5900 and tcp.dstport <= 5910' `
                        -Fields @('ip.dst','tcp.dstport','ip.src') -Max 5)) {
        $h = "$($r.'ip.dst')"
        if (-not $h -or $vncSeen.ContainsKey($h)) { continue }
        $vncSeen[$h] = $true
        $out.Add((New-TcpkFinding -Module 'network' -RuleId 'pcap.vnc-cleartext' -Severity 'HIGH' `
            -Confidence 'Confirmed (dynamic)' -Cwe @('CWE-319') `
            -Title "VNC cleartext session to $h (TCP $($r.'tcp.dstport'))" `
            -Evidence "TCP $($r.'tcp.dstport') from $($r.'ip.src') to $h -- VNC without TLS tunnel" `
            -Description 'VNC over TCP 5900-5910 without a TLS or SSH tunnel transmits screen content, keystrokes, and authentication in cleartext. An on-path observer has full graphical session visibility.' `
            -Fix 'Tunnel VNC over SSH (ssh -L 5900:localhost:5900) or use VNC over TLS. Never expose the VNC port directly on a network.'))
    }

    return $out.ToArray()
}

# ─── cipher weakness helper ──────────────────────────────────────────────────────
# Returns @{Severity; Reason} when the cipher name or hex/decimal code is known weak.
# tshark outputs human-readable names (TLS_RSA_WITH_RC4_128_SHA), hex codes (0x0005),
# or decimal (5) depending on version and whether the cipher is in its name table.
function Test-TcpkCipherWeak {
    param([string]$Name)
    $n = "$Name".Trim().ToLower()
    if (-not $n) { return $null }
    # Name-pattern checks (tshark usually outputs the IANA name string)
    if ($n -match 'null')                               { return @{Severity='CRITICAL'; Reason='NULL cipher -- no encryption'} }
    if ($n -match '_anon_')                             { return @{Severity='CRITICAL'; Reason='anonymous (no server auth) -- MITM trivial'} }
    if ($n -match 'export')                             { return @{Severity='HIGH';     Reason='export-grade (FREAK / Logjam)'} }
    if ($n -match 'rc4')                                { return @{Severity='HIGH';     Reason='RC4 is cryptographically broken'} }
    if ($n -match '3des')                               { return @{Severity='HIGH';     Reason='3DES Sweet32 (64-bit block collision)'} }
    if ($n -match '_des_cbc' -and $n -notmatch '3des') { return @{Severity='HIGH';     Reason='DES 56-bit -- brute-forceable'} }
    # Known-weak hex / decimal codes (fallback for tshark numeric output)
    switch ($n) {
        '0x0000' { return @{Severity='CRITICAL'; Reason='NULL cipher'} }
        '0x0001' { return @{Severity='CRITICAL'; Reason='NULL cipher'} }
        '0x0002' { return @{Severity='CRITICAL'; Reason='NULL cipher'} }
        '0x003b' { return @{Severity='CRITICAL'; Reason='NULL cipher'} }
        '0'      { return @{Severity='CRITICAL'; Reason='NULL cipher'} }
        '1'      { return @{Severity='CRITICAL'; Reason='NULL cipher'} }
        '2'      { return @{Severity='CRITICAL'; Reason='NULL cipher'} }
        '59'     { return @{Severity='CRITICAL'; Reason='NULL cipher'} }
        '0x0004' { return @{Severity='HIGH'; Reason='RC4'} }
        '0x0005' { return @{Severity='HIGH'; Reason='RC4'} }
        '4'      { return @{Severity='HIGH'; Reason='RC4'} }
        '5'      { return @{Severity='HIGH'; Reason='RC4'} }
        '0x000a' { return @{Severity='HIGH'; Reason='3DES Sweet32'} }
        '10'     { return @{Severity='HIGH'; Reason='3DES Sweet32'} }
        '0x0017' { return @{Severity='CRITICAL'; Reason='anonymous'} }
        '0x0018' { return @{Severity='CRITICAL'; Reason='anonymous'} }
        '0x001a' { return @{Severity='CRITICAL'; Reason='anonymous'} }
        '23'     { return @{Severity='CRITICAL'; Reason='anonymous'} }
        '24'     { return @{Severity='CRITICAL'; Reason='anonymous'} }
        '26'     { return @{Severity='CRITICAL'; Reason='anonymous'} }
        '0xc016' { return @{Severity='CRITICAL'; Reason='anonymous'} }
        '0xc017' { return @{Severity='CRITICAL'; Reason='anonymous'} }
        '0xc018' { return @{Severity='CRITICAL'; Reason='anonymous'} }
        '0xc019' { return @{Severity='CRITICAL'; Reason='anonymous'} }
    }
    return $null
}

# ─── TLS handshake tree (ClientHello + ServerHello per server:port) ───────────────
# Returns ordered dict keyed by "server_ip:port". Each value has:
#   ClientHellos - list of {Client, SNI, OfferedCiphers[], SupportedVersions[]}
#   ServerHellos - list of {NegotiatedVersion, SelectedCipher, KeyGroup, WeakCipher}
function Get-TcpkTlsSessionTree {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Tshark, [Parameter(Mandatory)][string]$Pcap,
          [string]$KeylogFile, [string]$RsaKeyFile)
    $q  = @{ Tshark=$Tshark; Pcap=$Pcap }
    if ($KeylogFile) { $q.KeylogFile=$KeylogFile }
    if ($RsaKeyFile) { $q.RsaKeyFile=$RsaKeyFile }
    $us = [char]0x1F

    $clientHellos = @(Invoke-TcpkTsharkQuery @q -Filter 'tls.handshake.type == 1' `
        -Fields @('ip.src','ip.dst','tcp.dstport',
                  'tls.handshake.extensions_server_name',
                  'tls.handshake.ciphersuite',
                  'tls.handshake.extensions.supported_versions.tls') `
        -Occurrence 'a' -Aggregator "$us")

    $serverHellos = @(Invoke-TcpkTsharkQuery @q -Filter 'tls.handshake.type == 2' `
        -Fields @('ip.src','ip.dst','tcp.srcport',
                  'tls.handshake.version',
                  'tls.handshake.ciphersuite',
                  'tls.handshake.extensions.key_share.selected_group') `
        -Occurrence 'a' -Aggregator "$us")

    $sessions = [ordered]@{}

    $ensureKey = {
        param($K, $SrvIP, $Port)
        if (-not $sessions.Contains($K)) {
            $sessions[$K] = [ordered]@{
                ServerIP     = $SrvIP
                Port         = $Port
                ClientHellos = [System.Collections.Generic.List[object]]::new()
                ServerHellos = [System.Collections.Generic.List[object]]::new()
            }
        }
    }

    foreach ($ch in $clientHellos) {
        $dport = (("$($ch.'tcp.dstport')") -split $us)[0]
        $key   = "$($ch.'ip.dst'):$dport"
        & $ensureKey $key $ch.'ip.dst' $dport
        $sni      = (("$($ch.'tls.handshake.extensions_server_name')") -split $us)[0]
        $ciphers  = @("$($ch.'tls.handshake.ciphersuite')" -split $us | Where-Object {$_} | ForEach-Object {$_.Trim()} | Select-Object -Unique)
        $versions = @("$($ch.'tls.handshake.extensions.supported_versions.tls')" -split $us | Where-Object {$_} | ForEach-Object {$_.Trim()} | Select-Object -Unique)
        $sessions[$key].ClientHellos.Add([pscustomobject]@{
            Client = "$($ch.'ip.src')"; SNI = $sni
            OfferedCiphers = $ciphers; SupportedVersions = $versions
        })
    }

    foreach ($sh in $serverHellos) {
        $sport  = (("$($sh.'tcp.srcport')") -split $us)[0]
        $key    = "$($sh.'ip.src'):$sport"
        & $ensureKey $key $sh.'ip.src' $sport
        $ver    = (("$($sh.'tls.handshake.version')") -split $us)[0]
        $cipher = (("$($sh.'tls.handshake.ciphersuite')") -split $us)[0]
        $kgrp   = (("$($sh.'tls.handshake.extensions.key_share.selected_group')") -split $us)[0]
        $weak   = if ($cipher) { Test-TcpkCipherWeak $cipher } else { $null }
        $sessions[$key].ServerHellos.Add([pscustomobject]@{
            NegotiatedVersion = $ver; SelectedCipher = $cipher
            KeyGroup = $kgrp; WeakCipher = $weak
        })
    }

    return $sessions
}

# ─── conversation statistics ───────────────────────────────────────────────────────
# Returns ordered dicts (sorted by bytes descending) with:
#   Date, Time, SrcIP, SrcPort, SrcMAC, DstIP, DstPort, DstMAC, Protocol, Packets, Bytes
function Get-TcpkConvStats {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Tshark, [Parameter(Mandatory)][string]$Pcap,
          [string]$KeylogFile, [string]$RsaKeyFile, [int]$Max = 5000)
    $q = @{ Tshark=$Tshark; Pcap=$Pcap }
    if ($KeylogFile) { $q.KeylogFile=$KeylogFile }
    if ($RsaKeyFile) { $q.RsaKeyFile=$RsaKeyFile }

    $rows = Invoke-TcpkTsharkQuery @q -Max $Max `
        -Fields @('ip.src','ip.dst','eth.src','eth.dst','_ws.col.Protocol','frame.len',
                  'tcp.srcport','tcp.dstport','udp.srcport','udp.dstport','frame.time_epoch')

    $convs = [ordered]@{}
    foreach ($r in @($rows)) {
        $sip = "$($r.'ip.src')"; $dip = "$($r.'ip.dst')"
        if (-not $sip -or -not $dip) { continue }
        $sport = if ($r.'tcp.srcport') { $r.'tcp.srcport' } elseif ($r.'udp.srcport') { $r.'udp.srcport' } else { '' }
        $dport = if ($r.'tcp.dstport') { $r.'tcp.dstport' } elseif ($r.'udp.dstport') { $r.'udp.dstport' } else { '' }
        $proto = "$($r.'_ws.col.Protocol')"
        $ck    = "${sip}:${sport}|${dip}:${dport}|${proto}"
        if (-not $convs.Contains($ck)) {
            $dateStr = ''; $timeStr = ''
            try {
                $epoch = [double]"$($r.'frame.time_epoch')"
                $dt = ([DateTime]'1970-01-01 00:00:00Z').ToUniversalTime().AddSeconds($epoch).ToLocalTime()
                $dateStr = $dt.ToString('yyyy-MM-dd')
                $timeStr = $dt.ToString('HH:mm:ss')
            } catch {}
            $convs[$ck] = [ordered]@{
                Date=$dateStr; Time=$timeStr
                SrcIP=$sip; SrcPort=$sport; SrcMAC="$($r.'eth.src')"
                DstIP=$dip; DstPort=$dport; DstMAC="$($r.'eth.dst')"
                Protocol=$proto; Packets=0; Bytes=0
            }
        }
        $convs[$ck].Packets++
        $len = 0; try { $len = [int]"$($r.'frame.len')" } catch {}
        $convs[$ck].Bytes += $len
    }
    return @($convs.Values | Sort-Object { -($_.Bytes) })
}

# ─── packet string / regex search ─────────────────────────────────────────────────
# Applies a tshark display filter "frame matches (?i)PATTERN" and returns matching rows.
# If -Regex is set, $Pattern is used as a literal PCRE regex; otherwise it is escaped.
# Protocol restricts to frames of that dissector (e.g. 'http', 'dns', 'btle').
function Invoke-TcpkPcapStringSearch {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Tshark, [Parameter(Mandatory)][string]$Pcap,
          [Parameter(Mandatory)][string]$Pattern,
          [string]$Protocol,
          [switch]$Regex,
          [int]$Max = 500,
          [string]$KeylogFile, [string]$RsaKeyFile)
    $q = @{ Tshark=$Tshark; Pcap=$Pcap }
    if ($KeylogFile) { $q.KeylogFile=$KeylogFile }
    if ($RsaKeyFile) { $q.RsaKeyFile=$RsaKeyFile }

    $escaped = if ($Regex) { $Pattern } else { [Regex]::Escape($Pattern) }
    $mf = "frame matches `"(?i)$escaped`""
    if ($Protocol -and $Protocol -ne 'All') { $mf = "$Protocol and ($mf)" }

    @(Invoke-TcpkTsharkQuery @q -Filter $mf -Max $Max `
        -Fields @('frame.number','frame.time_relative','ip.src','ip.dst','_ws.col.Protocol','_ws.col.Info'))
}

# ─── Bluetooth / BLE pcap analysis ────────────────────────────────────────────────
# Returns TcpkFindings. Empty array if no BT frames are present.
function Get-TcpkBtPcapFindings {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Tshark, [Parameter(Mandatory)][string]$Pcap)
    $out = New-Object System.Collections.Generic.List[object]
    $q   = @{ Tshark=$Tshark; Pcap=$Pcap }

    # Guard: detect any Bluetooth frames at all
    $probe = @(Invoke-TcpkTsharkQuery @q -Filter 'btle or btl2cap or bthci_cmd or bthci_evt' `
                  -Fields @('_ws.col.Protocol') -Max 1)
    if (-not $probe.Count) { return @() }

    # JustWorks (NoInputNoOutput) pairing -- no MITM protection
    $smps = @(Invoke-TcpkTsharkQuery @q -Filter 'btsmp.opcode == 0x01' `
                  -Fields @('ip.src','ip.dst','btsmp.io_capability','btsmp.auth_req'))
    foreach ($smp in $smps) {
        $io = "$($smp.'btsmp.io_capability')".Trim()
        if ($io -in '0x03','3','NoInputNoOutput') {
            $out.Add((New-TcpkFinding -Module 'network' -RuleId 'pcap.bt-justworks' -Severity 'HIGH' `
                -Confidence 'Confirmed (dynamic)' -Cwe @('CWE-287', 'CWE-330') `
                -Title 'BLE JustWorks pairing observed -- no MITM protection' `
                -Evidence "SMP Pairing Request io_capability=NoInputNoOutput (0x03) -> JustWorks selected" `
                -Description 'JustWorks pairing is used when the device has no input/output capability. It provides no MITM protection. An attacker present at pairing time can impersonate either peer.' `
                -Fix 'Use Passkey Entry or Numeric Comparison pairing. Enable Secure Connections (SC bit in auth_req). Require Passkey Entry for sensitive operations.'))
            break
        }
    }

    # Unencrypted GATT writes visible in cleartext
    $attWrites = @(Invoke-TcpkTsharkQuery @q `
                      -Filter 'btatt.opcode == 0x52 or btatt.opcode == 0x12' `
                      -Fields @('btatt.opcode','btatt.handle','btatt.value') -Max 5)
    if ($attWrites.Count) {
        $sample = "handle=0x$($attWrites[0].'btatt.handle') value=$($attWrites[0].'btatt.value')"
        $out.Add((New-TcpkFinding -Module 'network' -RuleId 'pcap.bt-gatt-cleartext' -Severity 'HIGH' `
            -Confidence 'Confirmed (dynamic)' -Cwe @('CWE-319') `
            -Title "GATT Write operations visible in cleartext ($($attWrites.Count) frame(s))" `
            -Evidence "sample: $sample" `
            -Description 'ATT/GATT Write frames are present in the capture without LE link-layer encryption. All GATT traffic (commands, responses, notifications) is exposed to any passive BLE observer.' `
            -Fix 'Require LE link encryption before allowing GATT attribute access. Set Encrypt Read / Encrypt Write attribute permissions on all sensitive characteristics.'))
    }

    # Unencrypted ATT reads (handle value reads visible)
    $attReads = @(Invoke-TcpkTsharkQuery @q `
                     -Filter 'btatt.opcode == 0x0b' `
                     -Fields @('btatt.handle','btatt.value') -Max 5)
    if ($attReads.Count -and -not $attWrites.Count) {
        $out.Add((New-TcpkFinding -Module 'network' -RuleId 'pcap.bt-gatt-read-cleartext' -Severity 'MEDIUM' `
            -Confidence 'Confirmed (dynamic)' -Cwe @('CWE-319') `
            -Title "GATT Read responses visible in cleartext ($($attReads.Count) frame(s))" `
            -Evidence "handle=0x$($attReads[0].'btatt.handle') value=$($attReads[0].'btatt.value')" `
            -Description 'ATT Read Response frames are visible without LE encryption. Characteristic values are exposed to passive observers.' `
            -Fix 'Require LE link encryption. Set Encrypt Read permission on sensitive characteristics.'))
    }

    # BLE advertisements leaking device info
    $advFrames = @(Invoke-TcpkTsharkQuery @q -Filter 'btle.advertising_header' `
                      -Fields @('btle.advertising_header.pdu_type') -Max 50)
    if ($advFrames.Count) {
        $pdus = @($advFrames | ForEach-Object { "$($_.'btle.advertising_header.pdu_type')" } | Where-Object {$_} | Sort-Object -Unique)
        $out.Add((New-TcpkFinding -Module 'network' -RuleId 'pcap.bt-adv' -Severity 'INFO' `
            -Confidence 'Confirmed (dynamic)' `
            -Title "BLE advertisement frames captured ($($advFrames.Count) frames, PDU types: $($pdus -join ', '))" `
            -Evidence "PDU types observed: $($pdus -join ', ')" `
            -Description 'BLE advertisement frames expose device identity (local name, service UUIDs, manufacturer data) to any passive RF observer. Sensitive fields are a tracking and fingerprinting risk.' `
            -Fix 'Rotate the BLE random address periodically (RPA). Do not include sensitive data in advertisement payloads.'))
    }

    # HCI-level capture (full Bluetooth classic / LE dual-mode trace)
    $hciCmds = @(Invoke-TcpkTsharkQuery @q -Filter 'bthci_cmd' `
                    -Fields @('bthci_cmd.opcode') -Max 10)
    if ($hciCmds.Count) {
        $opcodes = @($hciCmds | ForEach-Object { "$($_.'bthci_cmd.opcode')" } | Where-Object {$_} | Select-Object -Unique -First 6)
        $out.Add((New-TcpkFinding -Module 'network' -RuleId 'pcap.bt-hci' -Severity 'INFO' `
            -Confidence 'Confirmed (dynamic)' `
            -Title "Bluetooth HCI trace: $($hciCmds.Count)+ HCI command frames" `
            -Evidence "opcodes: $($opcodes -join ', ')" `
            -Description 'HCI-level capture includes all host-to-controller communication: link key negotiation, connection events, and encryption status. Useful for pairing analysis and encryption state tracing.' `
            -Fix ''))
    }

    return $out.ToArray()
}

# ─── Zigbee / IEEE 802.15.4 pcap analysis ─────────────────────────────────────────
# Returns TcpkFindings. Empty array if no Zigbee/802.15.4 frames are present.
function Get-TcpkZigbeePcapFindings {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Tshark, [Parameter(Mandatory)][string]$Pcap)
    $out = New-Object System.Collections.Generic.List[object]
    $q   = @{ Tshark=$Tshark; Pcap=$Pcap }

    # Guard: detect any Zigbee or IEEE 802.15.4 frames
    $probe = @(Invoke-TcpkTsharkQuery @q -Filter 'zbee_nwk or wpan' `
                  -Fields @('_ws.col.Protocol') -Max 1)
    if (-not $probe.Count) { return @() }

    # Total Zigbee NWK frame count
    $allZb = @(Invoke-TcpkTsharkQuery @q -Filter 'zbee_nwk' -Fields @('frame.number') -Max 2000)
    $total = $allZb.Count

    # Unencrypted Zigbee Network frames
    $unenc = @(Invoke-TcpkTsharkQuery @q `
                  -Filter 'zbee_nwk and !zbee_nwk.fcf.security' `
                  -Fields @('frame.number','zbee_nwk.src','zbee_nwk.dst') -Max 20)
    if ($unenc.Count) {
        $s = "frame $($unenc[0].'frame.number') src=$($unenc[0].'zbee_nwk.src') dst=$($unenc[0].'zbee_nwk.dst')"
        $out.Add((New-TcpkFinding -Module 'network' -RuleId 'pcap.zigbee-unencrypted' -Severity 'HIGH' `
            -Confidence 'Confirmed (dynamic)' -Cwe @('CWE-319') `
            -Title "Unencrypted Zigbee NWK frames: $($unenc.Count) observed" `
            -Evidence "sample: $s" `
            -Description 'Zigbee NWK frames with security bit clear are present. All payload data (commands, sensor readings, actuation) is visible to any 802.15.4 receiver in range of the network.' `
            -Fix 'Enable Zigbee network-layer security (AES-128 CCM*). All NWK frames must carry zbee_nwk.fcf.security=1.'))
    }

    # APS Transport Key in the air (network key broadcast -- CRITICAL)
    $tkeys = @(Invoke-TcpkTsharkQuery @q -Filter 'zbee_aps.cmd.id == 0x05' `
                  -Fields @('frame.number','zbee_nwk.src','zbee_nwk.dst') -Max 5)
    if ($tkeys.Count) {
        $out.Add((New-TcpkFinding -Module 'network' -RuleId 'pcap.zigbee-transport-key' -Severity 'CRITICAL' `
            -Confidence 'Confirmed (dynamic)' -Cwe @('CWE-321', 'CWE-319') `
            -Title 'Zigbee network key (Transport Key) broadcast captured -- entire network decryptable' `
            -Evidence "frame $($tkeys[0].'frame.number'): APS Transport Key from $($tkeys[0].'zbee_nwk.src') to $($tkeys[0].'zbee_nwk.dst')" `
            -Description "The Zigbee network key was distributed over the air via an APS Transport Key command. Any passive observer who captured this frame holds the network key and can decrypt all past and future Zigbee traffic in this network." `
            -Fix 'Pre-provision the network key out-of-band (not over the air). If OTA key distribution is required, use CBKE (Certificate-Based Key Establishment) per Zigbee PRO spec. Rotate the network key after any suspected capture.'))
    }

    # IEEE 802.15.4 frames without MAC-layer security
    $wpanUnsec = @(Invoke-TcpkTsharkQuery @q -Filter 'wpan and !wpan.fcf.security' `
                      -Fields @('frame.number') -Max 5)

    # Summary INFO finding (always emitted when Zigbee is present)
    $detail = "zbee_nwk=$total; unencrypted=$($unenc.Count); transport-key=$($tkeys.Count); wpan-unsecured=$($wpanUnsec.Count)"
    $out.Add((New-TcpkFinding -Module 'network' -RuleId 'pcap.zigbee-summary' -Severity 'INFO' `
        -Confidence 'Confirmed (dynamic)' `
        -Title "Zigbee / IEEE 802.15.4 traffic: $total NWK frames analysed" `
        -Evidence $detail `
        -Description 'Zigbee/IEEE 802.15.4 traffic was detected. See other Zigbee findings for security-relevant detections.' `
        -Fix ''))

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
