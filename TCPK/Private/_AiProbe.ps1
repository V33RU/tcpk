# Live-probe internals for Confirm-TcpkAiInferenceServer.
#
# Everything that opens a socket or reads the process table for that cmdlet is here, so the
# cmdlet itself holds only policy: what counts as proof, which severity, which attribution.
# Every function in this file returns a value and never throws.
#
# System.Net.Http auto-loads in PowerShell 7 but not in Windows PowerShell 5.1.
Add-Type -AssemblyName System.Net.Http -ErrorAction SilentlyContinue

# The complete request surface. Invoke-TcpkAiHttpGet refuses any other path, so the statement
# in the cmdlet help ("GET to these four paths only") is enforced where the socket is opened
# and does not depend on each caller getting it right.
$script:TcpkAiProbePaths    = @('/', '/api/version', '/api/tags', '/v1/models')
# Header values for the two cross-origin variants. '.invalid' is a reserved name that never
# resolves; it is only ever sent as a header value, never looked up or connected to.
$script:TcpkAiForeignOrigin = 'http://tcpk-probe.invalid'
$script:TcpkAiForeignHost   = 'tcpk-probe.invalid'
# Response-size cap. A model list is a few hundred bytes per model, so 1 MB is far above any
# real answer and still small enough to parse quickly on 5.1.
$script:TcpkAiMaxBodyBytes  = 1048576
# The exact text an Ollama server returns on GET /.
$script:TcpkAiOllamaBanner  = 'Ollama is running'
# Longest model name that is looked at. A longer one is masked without a single pattern
# being run on it, so the cost of masking does not depend on what the listener sends.
$script:TcpkAiMaxNameChars  = 256

# Default sweep list: the loopback ports local inference servers use out of the box
# (11434, 1234, 1337, 4891, 3001). A port number selects what to probe and nothing else:
# it is never used as evidence of which product is listening. Kept in a function so a
# test can point the sweep at its own listener.
function Get-TcpkAiDefaultEndpoint {
    [CmdletBinding()] param()
    return @('127.0.0.1:11434', '127.0.0.1:1234', '127.0.0.1:1337', '127.0.0.1:4891', '127.0.0.1:3001')
}

# Server-supplied text (model names, a version string, a header value) goes into Evidence
# only after this: a fixed safe alphabet and a length bound, so a hostile listener cannot
# place markup or control characters in a report.
function Get-TcpkAiSafeText {
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyString()][string]$Text, [int]$Max = 60)
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    # Cut first, then replace: the replacement is one character for one character, so the
    # result is the same and the pattern never runs over more than $Max characters.
    $t = $Text
    $cut = $false
    if ($Max -lt 1) { $Max = 1 }
    if ($t.Length -gt $Max) { $t = $t.Substring(0, $Max); $cut = $true }
    $t = [regex]::Replace($t, '[^A-Za-z0-9._:/@+_\-]', '?')
    if ($cut) { $t += '...' }
    return $t
}

# A model name for Evidence. A model list is not supposed to hold secrets, but its entries
# are whatever the listener chose to send, so a value shaped like a credential is masked
# instead of printed:
#   * anything longer than TcpkAiMaxNameChars, before any pattern sees it (the JWT pattern
#     in Get-TcpkRedact backtracks on a long run with no dot, so an unbounded name could
#     hold the probe for as long as the module-wide pattern timeout);
#   * a name holding '=' or '?' (key=value, a query string), or a ':' somewhere before an
#     '@' (user-info in a URL, user:password@host);
#   * a JWT or bearer value (Get-TcpkRedact), a known key prefix followed by a key-length
#     body (case-sensitive, as the keys are), or one unbroken run of 24 or more letters
#     and digits.
# Real model names are short words joined by '-', '.', ':' and '/', so they pass unchanged,
# including one that merely starts with "sk-" or "asia", and one with a revision after '@'.
function Get-TcpkAiSafeName {
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyString()][string]$Text, [int]$Max = 60)
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    $masked = '<masked>'
    if ($Text.Length -gt $script:TcpkAiMaxNameChars) { return $masked }
    try {
        if ($Text.IndexOfAny([char[]]@('=', '?')) -ge 0) { return $masked }
        $at = $Text.LastIndexOf([char]'@')
        if ($at -gt 0 -and $Text.Substring(0, $at).IndexOf([char]':') -ge 0) { return $masked }
        if ((Get-TcpkRedact -Text $Text) -cne $Text) { return $masked }
        $keyShapes = @(
            '(\A|[^A-Za-z0-9])sk-[A-Za-z0-9_\-]{20,}'
            '(\A|[^A-Za-z0-9])gh[pousr]_[A-Za-z0-9]{20,}'
            '(\A|[^A-Za-z0-9])github_pat_[A-Za-z0-9_]{20,}'
            '(\A|[^A-Za-z0-9])glpat-[A-Za-z0-9_\-]{20,}'
            '(\A|[^A-Za-z0-9])xox[abprs]-[A-Za-z0-9\-]{10,}'
            '(\A|[^A-Za-z0-9])(AKIA|ASIA)[0-9A-Z]{16}'
            '(\A|[^A-Za-z0-9])AIza[0-9A-Za-z_\-]{35}'
        )
        foreach ($shape in $keyShapes) {
            # The static Regex methods ignore case only when told to; none is passed here.
            if ([regex]::IsMatch($Text, $shape, [System.Text.RegularExpressions.RegexOptions]::None)) { return $masked }
        }
        if ([regex]::IsMatch($Text, '[A-Za-z0-9]{24,}')) { return $masked }
    } catch { return $masked }
    # Same bound as Get-TcpkAiSafeText, with an alphabet that fits real model ids: display
    # names hold spaces and parentheses, and a llama.cpp style server reports the model as
    # a Windows file path. A replaced character prints as '_' so it is not read as text
    # the server sent.
    $t = $Text
    $cut = $false
    if ($Max -lt 1) { $Max = 1 }
    if ($t.Length -gt $Max) { $t = $t.Substring(0, $Max); $cut = $true }
    $t = [regex]::Replace($t, '[^A-Za-z0-9._:/@+\- ()\\]', '_')
    if ($cut) { $t += '...' }
    return $t
}

# A redirect target for Evidence: scheme, host and path only. The query string and the
# fragment are dropped and user-info is removed, because any of them can carry a token; a
# long unbroken path segment is masked for the same reason.
function Get-TcpkAiSafeLocation {
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyString()][string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    try {
        # Only the first 120 characters are ever printed; nothing past this is looked at.
        $loc = $Text
        if ($loc.Length -gt 2048) { $loc = $loc.Substring(0, 2048) }
        $loc = $loc.Replace('\', '/')
        $loc = ($loc -split '[?#]')[0]
        # Authority = the text between the slashes after the scheme and the next '/'.
        # User-info is everything up to the LAST '@' in it (a password may itself hold
        # '@'). What is left must read as host or host:port; if it does not (a password
        # cut short by '?' or '#', for one), the whole authority is masked.
        $am = [regex]::Match($loc, '\A((?:[A-Za-z][A-Za-z0-9+.\-]*:)?/+)([^/]*)(.*)\z', [System.Text.RegularExpressions.RegexOptions]::Singleline)
        if ($am.Success -and $am.Groups[2].Value) {
            $auth = $am.Groups[2].Value
            $at = $auth.LastIndexOf([char]'@')
            if ($at -ge 0) { $auth = $auth.Substring($at + 1) }
            if (-not [regex]::IsMatch($auth, '\A(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9._\-]+)(:\d{1,5})?\z')) { $auth = '<masked>' }
            $loc = $am.Groups[1].Value + $auth + $am.Groups[3].Value
        }
        $loc = [regex]::Replace($loc, '[^\x21-\x7E]', '?')
        $loc = [regex]::Replace($loc, '[A-Za-z0-9_\-]{24,}', '<masked>')
        $loc = Get-TcpkRedact -Text $loc
        if ($loc.Length -gt 120) { $loc = $loc.Substring(0, 120) + '...' }
        return $loc
    } catch { return '' }
}

# First line of the innermost exception message, safe to print. A client error can quote
# bytes the listener sent (a malformed status line, for one), so the text is reduced to a
# plain alphabet and bounded like any other server-supplied value.
function Get-TcpkAiErrorText {
    [CmdletBinding()] param($Exception)
    $ex = $Exception
    try { while ($ex -and $ex.InnerException) { $ex = $ex.InnerException } } catch { }
    $msg = ''
    try { $msg = "$($ex.Message)" } catch { }
    if ($msg.Length -gt 2048) { $msg = $msg.Substring(0, 2048) }
    $msg = (($msg -split "[`r`n]+")[0]).Trim()
    $msg = [regex]::Replace($msg, "[^A-Za-z0-9 .,:;_/()'=+\-]", '?')
    if ($msg.Length -gt 160) { $msg = $msg.Substring(0, 160) + '...' }
    return $msg
}

# An -Endpoint value as a warning may print it: printable ASCII, bounded, and with
# everything up to the LAST '@' replaced, so a password typed into a URL is not echoed
# back, also when the password itself holds an '@' or a '/'. Only the scheme and the part
# after that '@' are shown.
function Get-TcpkAiEndpointLabel {
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyString()][string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    try {
        $t = $Text
        $prefix = ''
        $at = $t.LastIndexOf([char]'@')
        if ($at -ge 0) {
            $m = [regex]::Match($t, '\A\s*([A-Za-z][A-Za-z0-9+.\-]*://)')
            if ($m.Success -and $m.Length -le $at) { $prefix = $m.Groups[1].Value }
            $prefix += '<redacted>@'
            $t = $t.Substring($at + 1)
        }
        $cut = $false
        if ($t.Length -gt 120) { $t = $t.Substring(0, 120); $cut = $true }
        $t = [regex]::Replace($t, '[^\x20-\x7E]', '?')
        if ($cut) { $t += '...' }
        return ($prefix + $t)
    } catch { return '<endpoint>' }
}

# Parse one -Endpoint value. Accepted: host:port, [ipv6]:port, a bare port (loopback), and
# URL forms (the scheme and everything from the first '/', '?' or '#' are dropped).
# Returns { Ok; Host; Port; Reason; Note }. Reason says why a value was rejected so the
# caller can warn instead of returning nothing.
function ConvertTo-TcpkAiEndpoint {
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyString()][string]$Text)
    $r = [pscustomobject]@{ Ok = $false; Host = ''; Port = 0; Reason = ''; Note = '' }
    try {
        $s = "$Text".Trim()
        if (-not $s) { $r.Reason = 'the value is empty'; return $r }
        if ($s.Length -gt 512) { $r.Reason = 'the value is too long'; return $r }

        $m = [regex]::Match($s, '\A([A-Za-z][A-Za-z0-9+.\-]*)://')
        if ($m.Success) {
            $scheme = $m.Groups[1].Value.ToLowerInvariant()
            if ($scheme -ne 'http') { $r.Note = "the '$scheme' scheme was ignored, the probe speaks plain HTTP only" }
            $s = $s.Substring($m.Length)
        }
        # An '@' after the first '/' belongs to the path of a well-formed URL, so it is not
        # refused outright. It decides the wording only when the rest fails to parse: a
        # password that holds a '/' lands there.
        $userInfo = 'user-info (user@host) is not accepted'
        $hadAt = ($s.IndexOf([char]'@') -ge 0)
        $cut = $s.IndexOfAny([char[]]@('/', '?', '#'))
        if ($cut -ge 0) { $s = $s.Substring(0, $cut) }
        if (-not $s) { $r.Reason = 'no host or port is left after the scheme and path are removed'; return $r }
        if ($s.IndexOf([char]'@') -ge 0) { $r.Reason = $userInfo; return $r }

        $hostText = ''
        $portText = ''
        $m6 = [regex]::Match($s, '\A\[([0-9A-Za-z:.%]+)\]:([0-9]+)\z')
        $mh = [regex]::Match($s, '\A([^:\[\]]+):([0-9]+)\z')
        if ($m6.Success) {
            $inner = $m6.Groups[1].Value
            $ip6 = $null
            $ok6 = [System.Net.IPAddress]::TryParse($inner, [ref]$ip6)
            if (-not $ok6 -or $null -eq $ip6 -or $ip6.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
                $r.Reason = 'the bracketed value is not an IPv6 address'; return $r
            }
            $hostText = $inner
            $portText = $m6.Groups[2].Value
        } elseif ([regex]::IsMatch($s, '\A[0-9]+\z')) {
            $hostText = '127.0.0.1'
            $portText = $s
        } elseif ($mh.Success) {
            $hostText = $mh.Groups[1].Value.Trim()
            $portText = $mh.Groups[2].Value
        } elseif ($hadAt) {
            $r.Reason = $userInfo; return $r
        } elseif ($s.StartsWith('[')) {
            $r.Reason = 'an IPv6 literal needs the form [address]:port'; return $r
        } elseif (($s.Split([char]':')).Count -gt 2) {
            $r.Reason = 'an IPv6 literal must be bracketed: [address]:port'; return $r
        } elseif ($s.IndexOf([char]':') -lt 0) {
            $r.Reason = 'no port was given'; return $r
        } else {
            $r.Reason = 'the port is not a number'; return $r
        }

        if ($portText.Length -gt 5) { $r.Reason = 'the port is outside 1-65535'; return $r }
        $portNum = [int]$portText
        if ($portNum -lt 1 -or $portNum -gt 65535) { $r.Reason = 'the port is outside 1-65535'; return $r }

        if (-not $m6.Success) {
            $ip4 = $null
            $isLiteral = [System.Net.IPAddress]::TryParse($hostText, [ref]$ip4)
            if (-not $isLiteral -and -not [regex]::IsMatch($hostText, '\A[A-Za-z0-9_][A-Za-z0-9_.\-]{0,253}\z')) {
                $r.Reason = 'the host is neither an IP address nor a host name'; return $r
            }
        }

        $r.Ok = $true
        $r.Host = $hostText
        $r.Port = $portNum
        return $r
    } catch {
        $r.Ok = $false
        $r.Reason = 'the value could not be parsed'
        return $r
    }
}

# Host text -> the addresses to try, in resolver order. An IP literal is used as is (an
# IPv4-mapped IPv6 literal is mapped back to IPv4 so it is reached over IPv4). A name is
# resolved with a bounded wait. Returns @{ Ok; Addresses; Reason }.
function Resolve-TcpkAiAddress {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$HostName, [int]$TimeoutMs = 3000)
    $r = @{ Ok = $false; Addresses = @(); Reason = '' }
    try {
        $ip = $null
        if ([System.Net.IPAddress]::TryParse($HostName, [ref]$ip) -and $null -ne $ip) {
            if ($ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6 -and $ip.IsIPv4MappedToIPv6) { $ip = $ip.MapToIPv4() }
            $r.Ok = $true; $r.Addresses = @($ip)
            return $r
        }

        $task = [System.Net.Dns]::GetHostAddressesAsync($HostName)
        $done = $false
        try { $done = $task.Wait($TimeoutMs) } catch { $done = $true }
        if (-not $done) { $r.Reason = "the name did not resolve within $TimeoutMs ms"; return $r }
        if ($task.IsFaulted -or $task.IsCanceled) { $r.Reason = 'the name does not resolve'; return $r }

        $seen = @{}
        $list = New-Object 'System.Collections.Generic.List[System.Net.IPAddress]'
        foreach ($a in @($task.Result)) {
            if ($null -eq $a) { continue }
            $addr = $a
            if ($addr.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6 -and $addr.IsIPv4MappedToIPv6) { $addr = $addr.MapToIPv4() }
            if ($addr.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork -and
                $addr.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetworkV6) { continue }
            $key = $addr.ToString()
            if ($seen.ContainsKey($key)) { continue }
            $seen[$key] = $true
            $list.Add($addr)
            if ($list.Count -ge 4) { break }
        }
        if ($list.Count -eq 0) { $r.Reason = 'the name resolved to no usable address'; return $r }
        $r.Ok = $true
        $r.Addresses = $list.ToArray()
        return $r
    } catch {
        $r.Ok = $false
        $r.Reason = 'the name does not resolve'
        return $r
    }
}

# "127.0.0.1:11434" or "[::1]:11434". Used for the URL authority and for finding text.
function Get-TcpkAiHostPort {
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Net.IPAddress]$Address, [Parameter(Mandatory)][int]$Port)
    $a = $Address.ToString()
    if ($Address.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) { return ('[' + $a + ']:' + $Port) }
    return ($a + ':' + $Port)
}

# Bounded TCP connect to one address, with the socket created for that address family (the
# parameterless TcpClient is IPv4-only on .NET Framework). Returns @{ State; Detail } where
# State is connected | refused | timeout | error.
function Test-TcpkAiTcpConnect {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.Net.IPAddress]$Address,
        [Parameter(Mandatory)][int]$Port,
        [int]$TimeoutMs = 3000
    )
    $r = @{ State = 'error'; Detail = '' }
    $tcp = $null
    try {
        $tcp = [System.Net.Sockets.TcpClient]::new($Address.AddressFamily)
        $iar = $tcp.BeginConnect($Address, $Port, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne($TimeoutMs)) {
            $r.State = 'timeout'; $r.Detail = "no answer within $TimeoutMs ms"
            return $r
        }
        try {
            $tcp.EndConnect($iar)
            $r.State = 'connected'
        } catch {
            $code = ''
            $ex = $_.Exception
            while ($ex) {
                if ($ex -is [System.Net.Sockets.SocketException]) { $code = "$($ex.SocketErrorCode)"; break }
                $ex = $ex.InnerException
            }
            if ($code -eq 'ConnectionRefused') { $r.State = 'refused' }
            elseif ($code -eq 'TimedOut') { $r.State = 'timeout'; $r.Detail = 'the connection attempt timed out' }
            elseif ($code) { $r.State = 'error'; $r.Detail = "socket error $code" }
            else { $r.State = 'error'; $r.Detail = (Get-TcpkAiErrorText $_.Exception) }
        }
        return $r
    } catch {
        $r.State = 'error'
        $r.Detail = (Get-TcpkAiErrorText $_.Exception)
        return $r
    } finally {
        if ($tcp) { try { $tcp.Close() } catch { } }
    }
}

# $null when the response header is absent, its value (possibly '') when present.
function Get-TcpkAiHeader {
    [CmdletBinding()] param($Response, [string]$Name)
    try {
        $vals = $null
        if ($Response.Headers.TryGetValues($Name, [ref]$vals)) {
            return ((@($vals) | ForEach-Object { "$_" }) -join ', ')
        }
    } catch { }
    return $null
}

# The only place this feature sends an HTTP request.
#
#   * GET only, to one of the four allow-listed paths, on the address and port given.
#   * Redirects are never followed and no proxy is used (an http_proxy variable or a system
#     proxy would otherwise answer in the target's place).
#   * No credential, no cookie, and no automatic logon with the Windows account.
#   * -TimeoutMs bounds the whole exchange: connect, headers and body. The response is
#     buffered by the client, so the client's own timeout covers the body and the client
#     aborts the connection when it expires. Reading the body by hand after the headers
#     would keep the status code of a stalled response, but the time bound would then rest
#     on how the runtime closes a half-read response, and that could not be exercised on
#     Windows PowerShell 5.1 when this was written. So a stalled or oversize response
#     yields no status at all.
#   * The body is capped at -MaxBodyBytes by the client. A larger response is not read.
#
# Status is the status code of a response that arrived complete. Status 0 means no complete
# response: TimedOut, TooLarge or Error says why. Nothing is ever inferred from a partial one.
# Returns @{ Status; Body; TimedOut; TooLarge; ContentType; Location; Acao;
#            WwwAuthenticate; Error; Url }.
function Invoke-TcpkAiHttpGet {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.Net.IPAddress]$Address,
        [Parameter(Mandatory)][int]$Port,
        [Parameter(Mandatory)][string]$Path,
        [int]$TimeoutMs = 3000,
        [int]$MaxBodyBytes = 0,
        [string]$Origin = '',
        [string]$HostHeader = ''
    )
    if ($MaxBodyBytes -le 0) { $MaxBodyBytes = $script:TcpkAiMaxBodyBytes }
    $r = @{
        Status = 0; Body = ''; TimedOut = $false; TooLarge = $false
        ContentType = ''; Location = $null; Acao = $null; WwwAuthenticate = $false; Error = ''; Url = ''
    }
    if ($script:TcpkAiProbePaths -cnotcontains $Path) {
        $r.Error = 'path is not on the probe allow-list; nothing was sent'
        return $r
    }

    $handler = $null; $client = $null; $req = $null; $resp = $null
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $r.Url = 'http://' + (Get-TcpkAiHostPort -Address $Address -Port $Port) + $Path

        $handler = [System.Net.Http.HttpClientHandler]::new()
        $handler.AllowAutoRedirect = $false
        $handler.UseProxy = $false
        $handler.UseCookies = $false
        $handler.UseDefaultCredentials = $false
        $client = [System.Net.Http.HttpClient]::new($handler)
        $client.Timeout = [TimeSpan]::FromMilliseconds($TimeoutMs)
        $client.MaxResponseContentBufferSize = [long]$MaxBodyBytes

        $req = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Get, $r.Url)
        if ($Origin)     { [void]$req.Headers.TryAddWithoutValidation('Origin', $Origin) }
        if ($HostHeader) { $req.Headers.Host = $HostHeader }

        # Buffered send: the task completes only when the whole body is in memory, or fails.
        # The extra wait is a backstop for a client that does not honour its own timeout.
        $task = $client.SendAsync($req)
        $done = $false
        try { $done = $task.Wait($TimeoutMs + 1500) } catch { $done = $true }
        if (-not $done -or $task.IsCanceled) {
            $r.TimedOut = $true
            $r.Error = "no complete response within $TimeoutMs ms"
            return $r
        }
        if ($task.IsFaulted) {
            $canceled = $false; $tooLarge = $false
            $ex = $task.Exception
            $depth = 0
            while ($ex -and $depth -lt 10) {
                if ($ex -is [System.OperationCanceledException]) { $canceled = $true }
                if ($ex -is [System.Net.Http.HttpRequestException]) {
                    # The client ends its message with the configured limit on both runtimes.
                    # The number is matched, not the wording, so a localized message works,
                    # and only at the end, so a number quoted from the listener does not count.
                    if ([regex]::IsMatch("$($ex.Message)", ('(\A|[^0-9])' + $MaxBodyBytes + '[.\s]*\z'))) { $tooLarge = $true }
                    try { if ("$($ex.HttpRequestError)" -eq 'ConfigurationLimitExceeded') { $tooLarge = $true } } catch { }
                }
                $ex = $ex.InnerException
                $depth++
            }
            if ($tooLarge) {
                $r.TooLarge = $true
                $r.Error = "response larger than the $MaxBodyBytes-byte cap"
            } elseif ($canceled -or $sw.ElapsedMilliseconds -ge $TimeoutMs) {
                $r.TimedOut = $true
                $r.Error = "no complete response within $TimeoutMs ms"
            } else {
                $r.Error = (Get-TcpkAiErrorText $task.Exception)
                if (-not $r.Error) { $r.Error = 'the request failed' }
            }
            return $r
        }
        $resp = $task.Result
        if ($null -eq $resp) { $r.Error = 'the client returned no response'; return $r }

        # The body is already buffered, so this returns at once.
        $bytes = $null
        if ($resp.Content) {
            try { $bytes = $resp.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult() } catch { $bytes = $null }
        }
        if ($null -ne $bytes -and $bytes.Length -gt $MaxBodyBytes) {
            $r.TooLarge = $true
            $r.Error = "response larger than the $MaxBodyBytes-byte cap"
            return $r
        }

        try {
            if ($resp.Content -and $resp.Content.Headers -and $resp.Content.Headers.ContentType) {
                $r.ContentType = "$($resp.Content.Headers.ContentType.MediaType)"
            }
        } catch { }
        $r.Location = Get-TcpkAiHeader -Response $resp -Name 'Location'
        $r.Acao     = Get-TcpkAiHeader -Response $resp -Name 'Access-Control-Allow-Origin'
        $r.WwwAuthenticate = ($null -ne (Get-TcpkAiHeader -Response $resp -Name 'WWW-Authenticate'))

        if ($null -ne $bytes -and $bytes.Length -gt 0) {
            $r.Body = [System.Text.Encoding]::UTF8.GetString($bytes)
        }
        # Set last: a status is reported only for a response that was read to the end.
        $r.Status = [int]$resp.StatusCode
        return $r
    } catch {
        $r.Status = 0
        if ($sw.ElapsedMilliseconds -ge $TimeoutMs) { $r.TimedOut = $true }
        if (-not $r.Error) { $r.Error = (Get-TcpkAiErrorText $_.Exception) }
        if (-not $r.Error) { $r.Error = 'the request failed' }
        return $r
    } finally {
        # Disposing the client cancels a request that is still pending.
        if ($resp)    { try { $resp.Dispose() }    catch { } }
        if ($req)     { try { $req.Dispose() }     catch { } }
        if ($client)  { try { $client.Dispose() }  catch { } }
        if ($handler) { try { $handler.Dispose() } catch { } }
    }
}

# Body text -> a JSON OBJECT, or $null. Only an object can be a model list, so anything
# that does not start with '{' is rejected before the parser sees it. ConvertFrom-Json
# throws on both runtimes for malformed input and for keys that differ only by case; both
# are "not a model list" here.
function ConvertFrom-TcpkAiJson {
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyString()][string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $null }
    try {
        $t = $Text.Trim().TrimStart([char]0xFEFF).Trim()
        if ($t.Length -lt 2 -or $t[0] -ne [char]'{') { return $null }
        $o = ConvertFrom-Json -InputObject $t -ErrorAction Stop
        if ($o -is [System.Management.Automation.PSCustomObject]) { return $o }
    } catch { }
    return $null
}

# The record Get-TcpkAiModelList returns, in its "nothing was parsed" state.
#   Shape       'list' (array with model entries), 'empty-list' (the array is there but
#               empty, so the caller needs a second signal), 'none'
#   Total       entries in the array (Total, not Count: a key named Count would shadow the
#               hashtable's own Count property)
#   Names       up to five entry names, already safe to print
#   ListMarker  the body carries "object":"list"
#   ArrayKey    'models' or 'data', the array the route is expected to return
#   Accepted    set by Invoke-TcpkAiProbe: this body was counted as a model list
#   Why         what the body was, when it was not a list
function New-TcpkAiListInfo {
    [CmdletBinding()] param([string]$ArrayKey = '')
    return @{ Shape = 'none'; Total = 0; Names = @(); ListMarker = $false; ArrayKey = $ArrayKey; Accepted = $false; Why = '' }
}

# Decide whether a response body is a model list of the expected shape.
#   /api/tags  -> an object with a 'models' array whose entries carry a name
#   /v1/models -> an object with a 'data' array whose entries carry an id
# The body is parsed once, here; the Evidence lines are built from the record this returns.
function Get-TcpkAiModelList {
    [CmdletBinding()]
    param(
        [AllowNull()][AllowEmptyString()][string]$Body,
        [Parameter(Mandatory)][ValidateSet('/api/tags', '/v1/models')][string]$Route
    )
    $key = 'models'; $nameKeys = @('name', 'model')
    if ($Route -eq '/v1/models') { $key = 'data'; $nameKeys = @('id') }
    $r = New-TcpkAiListInfo -ArrayKey $key
    try {
        if ([string]::IsNullOrWhiteSpace($Body)) { $r.Why = 'empty body'; return $r }
        $o = ConvertFrom-TcpkAiJson -Text $Body
        if ($null -eq $o) {
            if ([regex]::IsMatch($Body, '\A\s*<')) { $r.Why = 'markup body, not JSON' }
            else { $r.Why = 'body is not a JSON object' }
            return $r
        }
        $prop = $o.PSObject.Properties[$key]
        if ($null -eq $prop -or -not ($prop.Value -is [System.Array])) {
            $r.Why = "JSON object without a '$key' array"
            return $r
        }
        $marker = $o.PSObject.Properties['object']
        if ($null -ne $marker -and "$($marker.Value)" -ceq 'list') { $r.ListMarker = $true }

        $items = @($prop.Value)
        $r.Total = $items.Count
        if ($items.Count -eq 0) { $r.Shape = 'empty-list'; $r.Why = "'$key' array is empty"; return $r }

        $names = New-Object 'System.Collections.Generic.List[string]'
        $checked = 0
        $modelMarker = $false
        foreach ($it in $items) {
            if ($checked -ge 50) { break }
            $checked++
            $nm = ''
            if ($it -is [System.Management.Automation.PSCustomObject]) {
                foreach ($k in $nameKeys) {
                    $p = $it.PSObject.Properties[$k]
                    if ($null -ne $p -and $p.Value -is [string] -and $p.Value) { $nm = [string]$p.Value; break }
                }
                $om = $it.PSObject.Properties['object']
                if ($null -ne $om -and "$($om.Value)" -ceq 'model') { $modelMarker = $true }
            }
            if (-not $nm) { $r.Why = "'$key' array entries are not model records"; return $r }
            if ($names.Count -lt 5) { $names.Add((Get-TcpkAiSafeName -Text $nm -Max 60)) }
        }
        # On /v1/models an array of records with a string id is what ANY REST collection
        # looks like. It counts as a model list only when the body says so itself: the
        # "object":"list" marker on the body or "object":"model" on an entry, which every
        # OpenAI-compatible server sends. /api/tags is an engine-specific route and needs
        # no such marker.
        if ($Route -eq '/v1/models' -and -not $r.ListMarker -and -not $modelMarker) {
            $r.Shape = 'unmarked-list'
            $r.Why = "'$key' array of records with an id, but no 'object':'list' or 'object':'model' marker, so not counted as a model list"
            return $r
        }
        $r.Names = $names.ToArray()
        $r.Shape = 'list'
        return $r
    } catch {
        $r.Shape = 'none'
        $r.Why = 'body could not be evaluated'
        return $r
    }
}

# Does a parsed body count as a model list? A non-empty array of model records does. An
# empty array says nothing by itself: on /api/tags it counts only together with the Ollama
# banner, on /v1/models only when the body marks itself "object":"list".
function Test-TcpkAiListAccepted {
    [CmdletBinding()]
    param([AllowNull()][hashtable]$List, [string]$Route, [bool]$Banner = $false)
    if ($null -eq $List) { return $false }
    if ($List.Shape -eq 'list') { return $true }
    if ($List.Shape -ne 'empty-list') { return $false }
    if ($Route -eq '/api/tags') { return [bool]$Banner }
    return [bool]$List.ListMarker
}

# Did this response ask for a credential? A 401 does, and so does a 403 that carries
# WWW-Authenticate. A 403 without that header does not: its cause is not established.
function Test-TcpkAiAuthAsked {
    [CmdletBinding()]
    param([AllowNull()][hashtable]$Response)
    if ($null -eq $Response) { return $false }
    if ($Response.Status -eq 401) { return $true }
    if ($Response.Status -eq 403 -and $Response.WwwAuthenticate) { return $true }
    return $false
}

# Did this response refuse the request without saying why? A 403 with no WWW-Authenticate
# header: an access rule, a Host or Origin filter, or an authentication scheme that does
# not announce itself. It is never counted as a credential check, and never as the lack
# of one.
function Test-TcpkAiBareForbidden {
    [CmdletBinding()]
    param([AllowNull()][hashtable]$Response)
    if ($null -eq $Response) { return $false }
    return ($Response.Status -eq 403 -and -not $Response.WwwAuthenticate)
}

# Route names as running text: "a", "a and b", "a, b and c".
function Join-TcpkAiWord {
    [CmdletBinding()]
    param([AllowNull()][string[]]$Items)
    $list = @($Items | Where-Object { $_ })
    if ($list.Count -eq 0) { return '' }
    if ($list.Count -eq 1) { return "$($list[0])" }
    $head = @($list[0..($list.Count - 2)]) -join ', '
    return ($head + ' and ' + $list[$list.Count - 1])
}

# One line of Evidence for one request: what was sent and what came back.
function Format-TcpkAiRouteEvidence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [AllowNull()][hashtable]$Response,
        [AllowNull()][hashtable]$List,
        [string]$Variant = ''
    )
    $head = "GET $Path"
    if ($Variant) { $head = "$head with $Variant" }
    if ($null -eq $Response) { return "$head -> not requested" }
    if ($Response.Status -eq 0) {
        # No complete response. The reason is this file's own wording, or the first line of
        # the client's error reduced to a safe alphabet.
        if ($Response.TooLarge) { return "$head -> response over the $($script:TcpkAiMaxBodyBytes)-byte cap, not read" }
        if ($Response.TimedOut) { return "$head -> no complete HTTP response within the timeout" }
        $why = 'no HTTP response'
        if ($Response.Error) { $why = "no HTTP response ($($Response.Error))" }
        return "$head -> $why"
    }
    $s = "$head -> $($Response.Status)"
    if ($Response.Status -ge 300 -and $Response.Status -lt 400) {
        $loc = ''
        if ($null -ne $Response.Location) { $loc = Get-TcpkAiSafeLocation -Text "$($Response.Location)" }
        if ($loc) { return "$s redirect to $loc (not followed)" }
        return "$s redirect (not followed)"
    }
    if ($Response.Status -eq 401 -or $Response.Status -eq 403) {
        if ($Response.WwwAuthenticate) { return "$s with WWW-Authenticate" }
        return "$s without WWW-Authenticate"
    }
    if ($Response.Status -ne 200) { return $s }
    if ($null -eq $List) { return $s }
    if ($List.Shape -eq 'list') {
        $more = ''
        if ($List.Total -gt @($List.Names).Count) { $more = ', ...' }
        $noun = 'entries'
        if ($List.Total -eq 1) { $noun = 'entry' }
        return "$s, JSON model list ($($List.Total) ${noun}: $((@($List.Names) -join ', '))$more)"
    }
    if ($List.Shape -eq 'empty-list') {
        # Only an empty array that was counted is called a model list. One that was not
        # counted is described as what it is, so Evidence and Description agree.
        if ($List.Accepted) { return "$s, JSON model list with 0 entries" }
        return "$s, JSON object with an empty '$($List.ArrayKey)' array, not counted as a model list"
    }
    $ct = ''
    if ($Response.ContentType) { $ct = (Get-TcpkAiSafeText -Text $Response.ContentType -Max 40) + ', ' }
    return "$s, ${ct}$($List.Why)"
}

# Run the whole exchange against one endpoint and return what was observed. No policy here:
# no severity, no attribution, no finding. At most six requests:
#   GET /api/tags, GET /v1/models                      always
#   GET /                                              only after /api/tags returned a models
#                                                      array or /v1/models a model list
#   GET /api/version                                   only after a model list was counted
#   GET <model route> with a foreign Origin, then Host only after a model list was counted
#                                                      and no probed route asked for a
#                                                      credential
#
# GET / and GET /api/version do two jobs. They carry Ollama's banner and version. And they
# are two more routes on which the listener can ask for a credential: a server that keeps
# its model list public while it checks a key everywhere else answers 401 there, and a
# public model list must not be read as an API with no authentication.
#
# What the caller reads:
#   ListSeen         a model list was counted (Route, List say which one)
#   AuthRoutes       the probed paths that asked for a credential
#   ForbiddenRoutes  the probed paths that answered 403 with no WWW-Authenticate header
#   Unauth           ListSeen and no probed path asked for a credential
#
# -AlreadyProbed holds the address:port values a caller has finished with. An endpoint that
# connects to one of them (the same listener named a second way) returns State 'duplicate'
# before any HTTP request is sent.
function Invoke-TcpkAiProbe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$EndpointHost,
        [Parameter(Mandatory)][int]$Port,
        [int]$TimeoutMs = 3000,
        [AllowNull()][hashtable]$AlreadyProbed
    )
    $o = @{
        State = 'error'; Detail = ''; Address = $null; HostPort = ''; IsLoopback = $false
        Tags = $null; TagsList = $null; V1 = $null; V1List = $null
        Root = $null; Banner = $false
        Ver = $null; VersionText = ''; Version = ''; VersionZero = $false
        Ollama = $false; Unauth = $false; Route = ''; List = $null
        ListSeen = $false; AuthRoutes = @(); ForbiddenRoutes = @()
        OriginVar = $null; OriginList = $null; OriginAccepted = $false; AcaoClass = 'none'; AcaoText = ''
        HostVar = $null; HostList = $null; HostAccepted = $false
    }
    try {
        $res = Resolve-TcpkAiAddress -HostName $EndpointHost -TimeoutMs $TimeoutMs
        if (-not $res.Ok) { $o.State = 'unresolved'; $o.Detail = $res.Reason; return $o }

        # Try each address with a socket of its own family; the first that connects is the
        # address every later request goes to, and the one loopback is decided on.
        $anyTimeout = $false; $anyError = ''
        foreach ($ip in @($res.Addresses)) {
            $c = Test-TcpkAiTcpConnect -Address $ip -Port $Port -TimeoutMs $TimeoutMs
            if ($c.State -eq 'connected') { $o.Address = $ip; break }
            if ($c.State -eq 'timeout') { $anyTimeout = $true }
            elseif ($c.State -eq 'error') { $anyError = $c.Detail }
        }
        if ($null -eq $o.Address) {
            if ($anyError) { $o.State = 'error'; $o.Detail = $anyError }
            elseif ($anyTimeout) { $o.State = 'timeout'; $o.Detail = "no answer within $TimeoutMs ms" }
            else { $o.State = 'refused' }
            return $o
        }
        $o.HostPort = Get-TcpkAiHostPort -Address $o.Address -Port $Port
        $o.IsLoopback = [System.Net.IPAddress]::IsLoopback($o.Address)
        if ($AlreadyProbed -and $AlreadyProbed.ContainsKey($o.HostPort)) {
            $o.State = 'duplicate'
            return $o
        }
        $o.State = 'connected'

        $get = @{ Address = $o.Address; Port = $Port; TimeoutMs = $TimeoutMs }

        $o.Tags = Invoke-TcpkAiHttpGet @get -Path '/api/tags'
        $o.TagsList = New-TcpkAiListInfo -ArrayKey 'models'
        if ($o.Tags.Status -eq 200) {
            $o.TagsList = Get-TcpkAiModelList -Body $o.Tags.Body -Route '/api/tags'
        }

        $o.V1 = Invoke-TcpkAiHttpGet @get -Path '/v1/models'
        $o.V1List = New-TcpkAiListInfo -ArrayKey 'data'
        if ($o.V1.Status -eq 200) {
            $o.V1List = Get-TcpkAiModelList -Body $o.V1.Body -Route '/v1/models'
        }
        $v1Ok = Test-TcpkAiListAccepted -List $o.V1List -Route '/v1/models'

        # Ollama identity needs BOTH of its own answers from this same endpoint: the models
        # array on /api/tags and the banner on GET /. The port number plays no part.
        $tagsOk = $false
        if ($o.TagsList.Shape -ne 'none' -or $v1Ok) {
            $o.Root = Invoke-TcpkAiHttpGet @get -Path '/'
            if ($o.Root.Status -eq 200 -and ("$($o.Root.Body)".Trim() -ceq $script:TcpkAiOllamaBanner)) { $o.Banner = $true }
            $tagsOk = Test-TcpkAiListAccepted -List $o.TagsList -Route '/api/tags' -Banner $o.Banner
            if ($tagsOk -and $o.Banner) { $o.Ollama = $true }
        }
        $o.TagsList.Accepted = [bool]$tagsOk
        $o.V1List.Accepted   = [bool]$v1Ok

        if ($tagsOk -or $v1Ok) {
            $o.Ver = Invoke-TcpkAiHttpGet @get -Path '/api/version'
            # The version is read only from a server already identified as Ollama. From any
            # other server this response is looked at for its status alone.
            if ($o.Ollama -and $o.Ver.Status -eq 200) {
                $vo = ConvertFrom-TcpkAiJson -Text $o.Ver.Body
                if ($null -ne $vo) {
                    $vp = $vo.PSObject.Properties['version']
                    if ($null -ne $vp -and $vp.Value -is [string]) {
                        $raw = [string]$vp.Value
                        $o.VersionText = Get-TcpkAiSafeText -Text $raw -Max 40
                        # Three numeric components, at most five digits each: nothing else is
                        # compared, so a crafted string cannot overflow or reach a title.
                        if ([regex]::IsMatch($raw, '\A[0-9]{1,5}\.[0-9]{1,5}\.[0-9]{1,5}\z')) {
                            $o.Version = $raw
                            $o.VersionZero = [regex]::IsMatch($raw, '\A0+\.0+\.0+\z')
                        }
                    }
                }
            }
        }

        # Which probed routes asked for a credential. Recorded whether or not a model list
        # came back, so the caller never has to work it out a second time.
        $asked = New-Object 'System.Collections.Generic.List[string]'
        if (Test-TcpkAiAuthAsked -Response $o.Tags) { $asked.Add('/api/tags') }
        if (Test-TcpkAiAuthAsked -Response $o.V1)   { $asked.Add('/v1/models') }
        if (Test-TcpkAiAuthAsked -Response $o.Root) { $asked.Add('/') }
        if (Test-TcpkAiAuthAsked -Response $o.Ver)  { $asked.Add('/api/version') }
        $o.AuthRoutes = $asked.ToArray()

        # A 403 that names no authentication scheme is kept apart: its cause is not known,
        # so the caller reports it as seen and draws no conclusion from it.
        $refused = New-Object 'System.Collections.Generic.List[string]'
        if (Test-TcpkAiBareForbidden -Response $o.Tags) { $refused.Add('/api/tags') }
        if (Test-TcpkAiBareForbidden -Response $o.V1)   { $refused.Add('/v1/models') }
        if (Test-TcpkAiBareForbidden -Response $o.Root) { $refused.Add('/') }
        if (Test-TcpkAiBareForbidden -Response $o.Ver)  { $refused.Add('/api/version') }
        $o.ForbiddenRoutes = $refused.ToArray()

        if ($tagsOk)   { $o.ListSeen = $true; $o.Route = '/api/tags';  $o.List = $o.TagsList }
        elseif ($v1Ok) { $o.ListSeen = $true; $o.Route = '/v1/models'; $o.List = $o.V1List }

        # One public model-list route does not stand for the whole API. A listener that asked
        # for a credential on any probed route has an authentication mechanism, so its model
        # list is not reported as an API without one, and the header variants are not sent.
        $o.Unauth = ($o.ListSeen -and $asked.Count -eq 0)

        if ($o.Unauth) {
            # Cross-origin handling is observed, not assumed: the same GET, one header changed.
            $o.OriginVar = Invoke-TcpkAiHttpGet @get -Path $o.Route -Origin $script:TcpkAiForeignOrigin
            $o.OriginList = New-TcpkAiListInfo -ArrayKey $o.List.ArrayKey
            if ($o.OriginVar.Status -eq 200) {
                $o.OriginList = Get-TcpkAiModelList -Body $o.OriginVar.Body -Route $o.Route
            }
            $o.OriginList.Accepted = [bool](Test-TcpkAiListAccepted -List $o.OriginList -Route $o.Route -Banner $o.Banner)
            $o.OriginAccepted = ($o.OriginVar.Status -eq 200 -and $o.OriginList.Accepted)
            if ($null -ne $o.OriginVar.Acao) {
                # A header sent twice arrives joined with commas. A browser rejects a response
                # that carries more than one Access-Control-Allow-Origin value, so a repeated
                # header (a proxy and the application both adding one) or a comma list does
                # NOT let a page on another site read the response. Only a single value that
                # is '*' or the probe origin is permissive; anything else is printed as
                # received and classed 'other'.
                $acao = "$($o.OriginVar.Acao)".Trim()
                $acaoValues = @($acao -split ',' | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
                if ($acaoValues.Count -eq 1 -and $acaoValues[0] -ceq '*') { $o.AcaoClass = 'wildcard'; $o.AcaoText = '*' }
                elseif ($acaoValues.Count -eq 1 -and $acaoValues[0] -eq $script:TcpkAiForeignOrigin) { $o.AcaoClass = 'echo'; $o.AcaoText = $script:TcpkAiForeignOrigin }
                else { $o.AcaoClass = 'other'; $o.AcaoText = Get-TcpkAiSafeText -Text $acao -Max 80 }
            }

            $foreignHost = $script:TcpkAiForeignHost + ':' + $Port
            $o.HostVar = Invoke-TcpkAiHttpGet @get -Path $o.Route -HostHeader $foreignHost
            $o.HostList = New-TcpkAiListInfo -ArrayKey $o.List.ArrayKey
            if ($o.HostVar.Status -eq 200) {
                $o.HostList = Get-TcpkAiModelList -Body $o.HostVar.Body -Route $o.Route
            }
            $o.HostList.Accepted = [bool](Test-TcpkAiListAccepted -List $o.HostList -Route $o.Route -Banner $o.Banner)
            $o.HostAccepted = ($o.HostVar.Status -eq 200 -and $o.HostList.Accepted)
        }
        return $o
    } catch {
        if ($o.State -ne 'connected') { $o.State = 'error' }
        $o.Detail = (Get-TcpkAiErrorText $_.Exception)
        return $o
    }
}

# Is this address one of this machine's own? The owner lookup below reads the LOCAL
# listener table, so it must not run for a remote endpoint that happens to use a port
# some local process also listens on.
function Test-TcpkAiLocalAddress {
    [CmdletBinding()]
    param([Parameter(Mandatory)][System.Net.IPAddress]$Address)
    try {
        if ([System.Net.IPAddress]::IsLoopback($Address)) { return $true }
        foreach ($nic in [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
            foreach ($ua in $nic.GetIPProperties().UnicastAddresses) {
                if ($ua.Address.Equals($Address)) { return $true }
            }
        }
    } catch { }
    return $false
}

# The local listener table for one TCP port, reduced to what the owner lookup needs.
# Returns @{ Ok; Rows; Note } where each row is { LocalAddress; OwningProcess }. This is the
# only call to Get-NetTCPConnection, kept apart so the row selection in
# Get-TcpkAiListenerOwner can be tested with plain objects on any host.
function Get-TcpkAiListenRow {
    [CmdletBinding()]
    param([Parameter(Mandatory)][int]$Port)
    $r = @{ Ok = $false; Rows = @(); Note = '' }
    try {
        if (-not (Get-Command -Name 'Get-NetTCPConnection' -ErrorAction SilentlyContinue)) {
            $r.Note = 'Get-NetTCPConnection is not available on this system'
            return $r
        }
        $raw = @()
        try { $raw = @(Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction Stop) }
        catch { $r.Note = 'no listening socket was found for this port'; return $r }

        $rows = New-Object 'System.Collections.Generic.List[object]'
        foreach ($c in $raw) {
            if ($null -eq $c) { continue }
            $rows.Add([pscustomobject]@{ LocalAddress = "$($c.LocalAddress)"; OwningProcess = [int]$c.OwningProcess })
        }
        if ($rows.Count -eq 0) { $r.Note = 'no listening socket was found for this port'; return $r }
        $r.Rows = $rows.ToArray()
        $r.Ok = $true
        return $r
    } catch {
        $r.Ok = $false
        $r.Rows = @()
        $r.Note = 'the listener table could not be read'
        return $r
    }
}

# Which process owns the listening socket, and where is its image on disk?
#
# This is the one piece of evidence that can tie a listener to the audited target: a port
# number cannot. Windows only (listener table -> owning process -> image path). The
# lookup fails closed: more than one candidate process, no row, or an image path that
# cannot be read all return Resolved = $false, and an unresolved owner never attributes.
# Returns { Resolved; ProcessId; ProcessName; ImagePath; Note }.
function Get-TcpkAiListenerOwner {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][int]$Port,
        [AllowNull()][System.Net.IPAddress]$Address
    )
    $o = [pscustomobject]@{ Resolved = $false; ProcessId = 0; ProcessName = ''; ImagePath = ''; Note = '' }
    try {
        if (-not (Test-TcpkIsWindows)) { $o.Note = 'owner lookup needs Windows'; return $o }

        $table = Get-TcpkAiListenRow -Port $Port
        if (-not $table -or -not $table.Ok) {
            $o.Note = 'the listener table could not be read'
            if ($table -and $table.Note) { $o.Note = "$($table.Note)" }
            return $o
        }
        $rows = @($table.Rows)
        if ($rows.Count -eq 0) { $o.Note = 'no listening socket was found for this port'; return $o }

        # Prefer the socket bound to the exact address that was connected; fall back to a
        # wildcard bind of the same family, then to the dual-stack wildcard.
        $addr = ''; $isV6 = $false
        if ($null -ne $Address) {
            $addr = $Address.ToString()
            $isV6 = ($Address.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6)
        }
        $pick = @($rows | Where-Object { "$($_.LocalAddress)" -eq $addr })
        if ($pick.Count -eq 0) {
            $wild = '0.0.0.0'
            if ($isV6) { $wild = '::' }
            $pick = @($rows | Where-Object { "$($_.LocalAddress)" -eq $wild })
        }
        if ($pick.Count -eq 0 -and -not $isV6) { $pick = @($rows | Where-Object { "$($_.LocalAddress)" -eq '::' }) }
        if ($pick.Count -eq 0) { $o.Note = 'no listening socket matches the connected address'; return $o }

        $owners = @($pick | ForEach-Object { [int]$_.OwningProcess } | Sort-Object -Unique)
        if ($owners.Count -ne 1) { $o.Note = 'more than one process listens on this port'; return $o }
        $ownerId = [int]$owners[0]
        $o.ProcessId = $ownerId

        $image = ''
        try {
            $proc = Get-Process -Id $ownerId -ErrorAction Stop
            $o.ProcessName = "$($proc.ProcessName)"
            try { $image = "$($proc.Path)" } catch { $image = '' }
        } catch { }
        if (-not $image) {
            # Get-Process cannot read the module path of a process in another session or at
            # a higher integrity level; the process table often still can.
            try {
                $wp = @(Get-TcpkCimSafe -ClassName 'Win32_Process' -Filter "ProcessId=$ownerId" -Property @('ProcessId', 'Name', 'ExecutablePath') -TimeoutSec 10)
                if ($wp.Count -gt 0) {
                    if ($wp[0].ExecutablePath) { $image = "$($wp[0].ExecutablePath)" }
                    if (-not $o.ProcessName -and $wp[0].Name) { $o.ProcessName = "$($wp[0].Name)" }
                }
            } catch { }
        }
        if (-not $image) {
            $o.Note = 'the image path of the owning process could not be read (try an elevated session)'
            # PID 4 is the kernel. A port it owns is served through the HTTP driver on behalf
            # of some other process, which the listener table does not name.
            if ($ownerId -eq 4) { $o.Note = 'the port is owned by the System process (PID 4), so the application behind it is not visible in the listener table' }
            return $o
        }

        $o.ImagePath = $image
        $o.Resolved = $true
        return $o
    } catch {
        $o.Resolved = $false
        $o.Note = 'owner lookup failed'
        return $o
    }
}
