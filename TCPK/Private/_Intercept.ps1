# Traffic interception support for Invoke-TcpkIntercept. TCPK does NOT reimplement a
# proxy: it orchestrates mitmproxy (mitmdump) and parses the captured flows into
# intercept.* findings. This file holds the tool-locators and the deterministic
# flow -> finding parser (the cross-platform, unit-testable core).

# Locate the mitmdump binary: explicit override, then tools\mitmproxy\, then PATH.
function Get-TcpkMitmdump {
    param([string]$Override)
    $cands = @()
    if ($Override) { $cands += $Override }
    $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent   # repo root (parent of TCPK\)
    $cands += (Join-Path $repo 'tools/mitmproxy/mitmdump')
    $cands += (Join-Path $repo 'tools/mitmproxy/mitmdump.exe')
    foreach ($c in $cands) { if ($c -and (Test-Path -LiteralPath $c)) { return (Resolve-Path -LiteralPath $c).Path } }
    $cmd = Get-Command 'mitmdump' -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    return $null
}

# Path to the bundled mitmproxy capture addon (ships with the module).
function Get-TcpkInterceptAddon {
    return (Join-Path (Split-Path $PSScriptRoot -Parent) 'Data/tcpk_capture.py')
}

# Path to the bundled mitmproxy tamper addon.
function Get-TcpkTamperAddon {
    return (Join-Path (Split-Path $PSScriptRoot -Parent) 'Data/tcpk_tamper.py')
}

# Turn 'find=>replace' (optionally 'find=>replace=>req|resp|both') rule strings into the
# JSON list the tamper addon reads. Always emits a JSON ARRAY (PS 5.1-safe: single-item
# ConvertTo-Json would otherwise emit an object).
function ConvertTo-TcpkTamperRules {
    param([string[]]$Rules)
    $items = New-Object 'System.Collections.Generic.List[string]'
    foreach ($r in @($Rules)) {
        $parts = "$r" -split '=>', 3
        if ($parts.Count -lt 2) { continue }
        $where = if ($parts.Count -ge 3 -and $parts[2]) { $parts[2] } else { 'both' }
        $items.Add(([ordered]@{ find = $parts[0]; replace = $parts[1]; where = $where } | ConvertTo-Json -Compress))
    }
    return ('[' + (($items.ToArray()) -join ',') + ']')
}

# Turn the tamper addon's log (TCPKTAMPER lines) into a finding: what was modified in flight.
function ConvertFrom-TcpkTamperLog {
    param([string]$LogFile, [string[]]$Rules, [string]$Target)
    $lines = @()
    if (Test-Path -LiteralPath $LogFile) { $lines = @(Get-Content -LiteralPath $LogFile) }
    $applied = @($lines | Where-Object { "$_" -match '^\s*TCPKTAMPER\b' -and "$_" -notmatch 'TCPKTAMPERRESP' })
    $respLog = @($lines | Where-Object { "$_" -match 'TCPKTAMPERRESP' })
    if (-not $applied.Count) {
        return (New-TcpkFinding -Module 'network' -RuleId 'intercept.tamper-inactive' -Severity 'INFO' -Confidence 'Inferred' `
            -Title 'Tamper rules matched no traffic' -File $Target -Evidence "$(@($Rules).Count) rule(s), 0 applied" `
            -Description "The app produced no traffic matching the tamper rules. It may not have sent the targeted request, may pin certificates / ignore the proxy, or the rule string did not match the on-the-wire bytes." `
            -Fix 'Drive the app to send the targeted request, confirm the rule matches the wire bytes, and ensure the app honours the proxy and trusts the mitmproxy CA.')
    }

    $findings = New-Object 'System.Collections.Generic.List[object]'
    $findings.Add((New-TcpkFinding -Module 'network' -RuleId 'intercept.tamper-applied' -Severity 'HIGH' -Confidence 'Confirmed (dynamic)' `
        -Title "Modified $($applied.Count) live request/response(s) in flight" -File $Target `
        -Evidence (($applied | Select-Object -First 8) -join ' | ') -Cwe @('CWE-602', 'CWE-807') `
        -Description "TCPK modified the app's traffic in flight via the mitmproxy tamper addon. Use this to probe whether the backend re-validates client-supplied values (authorization, role, price, injection) SERVER-side rather than trusting the client -- if a tampered value is honoured, the server trusts the client." `
        -Fix 'Enforce every security decision server-side and validate all input independently of the client; never trust a client-supplied value.'))

    # Response-differential verdict: for requests whose value TCPK tampered, did the server
    # ACCEPT (2xx/3xx) or REJECT (4xx/5xx) the change? An accepted tamper is the strong signal
    # that the backend trusts the client-supplied value instead of re-validating it server-side.
    if ($respLog.Count) {
        $accepted = @(); $rejected = @()
        foreach ($rl in $respLog) {
            $sm = [regex]::Match("$rl", 'status=(\d{3})')
            if (-not $sm.Success) { continue }
            $code = [int]$sm.Groups[1].Value
            if ($code -ge 200 -and $code -lt 400) { $accepted += $code } else { $rejected += $code }
        }
        if ($accepted.Count) {
            $findings.Add((New-TcpkFinding -Module 'network' -RuleId 'intercept.tamper-accepted' -Severity 'HIGH' -Confidence 'Confirmed (dynamic)' `
                -Title "Server returned success to $($accepted.Count) tampered request(s)" -File $Target `
                -Evidence ("tampered-request response codes: " + (($accepted | Select-Object -First 8) -join ', ')) -Cwe @('CWE-602','CWE-639','CWE-807') `
                -Description "For $($accepted.Count) request(s) whose security-relevant value TCPK altered in flight, the backend returned a 2xx/3xx success. That is the differential signal that the server may be TRUSTING the client-supplied value rather than re-validating it -- the class behind broken access control / IDOR / price or role tampering. Confirm the tampered field actually changed the outcome (not a static page)." `
                -Fix 'Re-validate every security-relevant value (identity, role, price, entitlement) on the server against the authenticated session; never trust a client-supplied value even if the client normally sends the right one.'))
        }
        if ($rejected.Count -and -not $accepted.Count) {
            $findings.Add((New-TcpkFinding -Module 'network' -RuleId 'intercept.tamper-rejected' -Severity 'INFO' -Confidence 'Confirmed (dynamic)' `
                -Title "Server rejected $($rejected.Count) tampered request(s)" -File $Target `
                -Evidence ("tampered-request response codes: " + (($rejected | Select-Object -First 8) -join ', ')) `
                -Description "The backend returned a 4xx/5xx to every tampered request, which is consistent with server-side re-validation (good). Still confirm the rejection is due to server-side checks and not an unrelated error." `
                -Fix 'No action if the rejections are genuine server-side authorization/validation failures; keep enforcing server-side.'))
        }
    }
    return $findings.ToArray()
}

# A free loopback TCP port.
function Get-TcpkFreePort {
    $l = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $l.Start(); $p = ([System.Net.IPEndPoint]$l.LocalEndpoint).Port; $l.Stop(); return $p
}

# Luhn check -- keeps the payment-card (PAN) response-mining rule from firing on any
# random 13-16 digit run. Returns $true only for a Luhn-valid digit string.
function Test-TcpkLuhn {
    [CmdletBinding()] param([string]$Digits)
    $d = "$Digits" -replace '\D', ''
    if ($d.Length -lt 13 -or $d.Length -gt 19) { return $false }
    $sum = 0; $alt = $false
    for ($i = $d.Length - 1; $i -ge 0; $i--) {
        $n = [int][string]$d[$i]
        if ($alt) { $n *= 2; if ($n -gt 9) { $n -= 9 } }
        $sum += $n; $alt = -not $alt
    }
    return ($sum % 10 -eq 0)
}

# Parse a captured-flows JSONL file (written by tcpk_capture.py) into intercept.* findings.
# Deterministic; no network; the unit-testable core of Invoke-TcpkIntercept.
function ConvertFrom-TcpkInterceptCapture {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$FlowFile)
    if (-not (Test-Path -LiteralPath $FlowFile)) { return @() }

    $endpoints = @{}   # scheme://host -> isHttp
    $credSeen  = New-Object 'System.Collections.Generic.HashSet[string]'
    $tokSeen   = New-Object 'System.Collections.Generic.HashSet[string]'
    $findings  = New-Object 'System.Collections.Generic.List[object]'

    $secretRx = '(?i)(password|passwd|pwd|pass|token|apikey|api_key|secret|access_key)=([^&\s]{3,})'
    $jsonRx   = '(?i)"(password|passwd|pwd|pass|token|apikey|api_key|secret|access_key)"\s*:\s*"([^"]{3,})"'

    foreach ($line in (Get-Content -LiteralPath $FlowFile)) {
        if (-not "$line".Trim()) { continue }
        $flow = $null; try { $flow = $line | ConvertFrom-Json } catch { continue }
        $scheme = "$($flow.scheme)".ToLower(); $hst = "$($flow.host)"
        if (-not $hst) { continue }
        $isHttp = ($scheme -eq 'http')
        $url = "$($flow.url)"; if (-not $url) { $url = "$scheme`://$hst$($flow.path)" }
        $wire = if ($isHttp) { ' over cleartext http' } else { ' (recovered via TLS interception)' }

        $ekey = "$scheme`://$hst"
        if (-not $endpoints.ContainsKey($ekey)) { $endpoints[$ekey] = $isHttp }

        # Authorization header: Basic (recoverable creds) or Bearer (replayable token)
        $auth = ''
        if ($flow.req_headers) { foreach ($h in $flow.req_headers.PSObject.Properties) { if ("$($h.Name)".ToLower() -eq 'authorization') { $auth = "$($h.Value)" } } }
        if ($auth -match '^(?i)Basic\s+([A-Za-z0-9+/=]+)\s*$') {
            $dec = ''; try { $dec = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($matches[1])) } catch { }
            if ($dec -match '^(.*?):(.*)$') {
                $user = $matches[1]; $pass = $matches[2]
                if ($credSeen.Add("basic|$hst|$user")) {
                    $findings.Add((New-TcpkFinding -Module 'network' -RuleId 'intercept.cleartext-credential' `
                        -Severity $(if ($isHttp) { 'CRITICAL' } else { 'HIGH' }) -Confidence 'Confirmed (dynamic)' `
                        -Title 'HTTP Basic credentials observed on the wire' -File $url `
                        -Evidence ("user '$user' pass '" + (Format-TcpkMaskedSecret $pass) + "' to $hst$wire") -Cwe @('CWE-522','CWE-319') `
                        -Description "Invoke-TcpkIntercept captured an HTTP Basic Authorization header the app sent to $hst. The credentials are recoverable by anyone who can see the traffic$wire." `
                        -Fix 'Do not use HTTP Basic auth for the app credential; use a short-lived token over pinned TLS. Rotate the exposed credential.'))
                }
            }
        }
        elseif ($auth -match '^(?i)Bearer\s+(.+?)\s*$') {
            if ($tokSeen.Add("bearer|$hst")) {
                $findings.Add((New-TcpkFinding -Module 'network' -RuleId 'intercept.session-token' `
                    -Severity $(if ($isHttp) { 'HIGH' } else { 'MEDIUM' }) -Confidence 'Confirmed (dynamic)' `
                    -Title 'Bearer/session token observed on the wire' -File $url `
                    -Evidence ('Authorization: Bearer ' + (Format-TcpkMaskedSecret ("$($matches[1])")) + " to $hst$wire") -Cwe @('CWE-522','CWE-319') `
                    -Description "The app sent a bearer token to $hst$wire. A captured token can be replayed for the lifetime of its validity." `
                    -Fix 'Send tokens only over pinned TLS; keep token lifetimes short; bind tokens to the client where possible.'))
            }
        }

        # credential/secret parameters in the query or request body (form + JSON)
        $hay = "$($flow.path) $($flow.req_body)"
        foreach ($rx in @($secretRx, $jsonRx)) {
            foreach ($m in [regex]::Matches($hay, $rx)) {
                $pname = $m.Groups[1].Value; $pval = $m.Groups[2].Value
                if ($credSeen.Add("param|$hst|$pname|$pval")) {
                    $findings.Add((New-TcpkFinding -Module 'network' -RuleId 'intercept.cleartext-credential' `
                        -Severity $(if ($isHttp) { 'CRITICAL' } else { 'HIGH' }) -Confidence 'Confirmed (dynamic)' `
                        -Title 'Credential/secret parameter observed in a request' -File $url `
                        -Evidence ("$pname = " + (Format-TcpkMaskedSecret $pval) + " to $hst$wire") -Cwe @('CWE-522','CWE-319') `
                        -Description "The app sent a '$pname' value to $hst in the request$wire. Treat it as an exposed secret." `
                        -Fix 'Never place credentials/secrets in URLs or unencrypted request bodies; use a proper auth flow over pinned TLS.'))
                }
            }
        }

        # --- response-body mining: secrets / tokens / PII RETURNED by the server ---
        # A server that echoes a credential, hands back another user's token, or returns
        # PII in its response body is a data-exposure primitive the request-only scan misses.
        $respHay = "$($flow.resp_body)"
        if ($respHay) {
            foreach ($rx in @($secretRx, $jsonRx)) {
                foreach ($m in [regex]::Matches($respHay, $rx)) {
                    $pname = $m.Groups[1].Value; $pval = $m.Groups[2].Value
                    if ($credSeen.Add("resp|$hst|$pname|$pval")) {
                        $findings.Add((New-TcpkFinding -Module 'network' -RuleId 'intercept.secret-in-response' `
                            -Severity 'HIGH' -Confidence 'Confirmed (dynamic)' `
                            -Title 'Credential/secret returned in a response body' -File $url `
                            -Evidence ("$pname = " + (Format-TcpkMaskedSecret $pval) + " from $hst$wire") -Cwe @('CWE-200','CWE-359') `
                            -Description "The server at $hst returned a '$pname' value in its response body$wire. A response that hands back a credential / secret / token is a data-exposure sink -- captured on the wire and reachable by any client that can make the call." `
                            -Fix 'Never return secrets/credentials in a response body; return opaque handles and scope every field to the authenticated caller.'))
                    }
                }
            }
            # JWT-shaped token returned to the client (replayable session material)
            $jm = [regex]::Match($respHay, 'eyJ[A-Za-z0-9_-]{6,}\.eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{4,}')
            if ($jm.Success -and $tokSeen.Add("resp-jwt|$hst")) {
                $findings.Add((New-TcpkFinding -Module 'network' -RuleId 'intercept.token-in-response' `
                    -Severity $(if ($isHttp) { 'HIGH' } else { 'MEDIUM' }) -Confidence 'Confirmed (dynamic)' `
                    -Title 'JWT / session token returned in a response body' -File $url `
                    -Evidence ('JWT ' + (Format-TcpkMaskedSecret $jm.Value) + " from $hst$wire") -Cwe @('CWE-522') `
                    -Description "The server returned a JWT-shaped token in its response$wire. Captured on the wire (or logged), it can be replayed for its validity window." `
                    -Fix 'Deliver session tokens over pinned TLS with short lifetimes; prefer an httpOnly cookie over a body-returned token.'))
            }
            # PII returned in the response: US SSN (dashed) and Luhn-valid payment card (PAN)
            if (($sm = [regex]::Match($respHay, '\b\d{3}-\d{2}-\d{4}\b')).Success -and $credSeen.Add("pii-ssn|$hst")) {
                $findings.Add((New-TcpkFinding -Module 'network' -RuleId 'intercept.pii-in-response' `
                    -Severity 'MEDIUM' -Confidence 'Confirmed (dynamic)' `
                    -Title 'US SSN pattern returned in a response body' -File $url `
                    -Evidence "SSN-shaped value observed in the response from $hst$wire" -Cwe @('CWE-359') `
                    -Description "The server returned a value matching a US SSN in its response$wire. Confirm it is the caller's OWN data and minimized; PII on the wire is an exposure." `
                    -Fix 'Return only the minimum PII the caller is entitled to, over pinned TLS; mask or tokenize where possible.'))
            }
            foreach ($cm in [regex]::Matches($respHay, '\b(?:\d[ -]?){13,19}\b')) {
                if (-not (Test-TcpkLuhn $cm.Value)) { continue }
                if ($credSeen.Add("pii-pan|$hst")) {
                    $findings.Add((New-TcpkFinding -Module 'network' -RuleId 'intercept.pii-in-response' `
                        -Severity 'MEDIUM' -Confidence 'Confirmed (dynamic)' `
                        -Title 'Payment-card (PAN) returned in a response body' -File $url `
                        -Evidence "Luhn-valid card number observed in the response from $hst$wire" -Cwe @('CWE-359') `
                        -Description "The server returned a Luhn-valid payment-card number in its response$wire. Confirm PCI scope and that the PAN is masked / tokenized rather than returned in full." `
                        -Fix 'Never return a full PAN; return only the last four digits (or a token) over pinned TLS.'))
                }
                break
            }
        }
    }

    foreach ($ekey in $endpoints.Keys) {
        $isHttp = $endpoints[$ekey]; $hst = ($ekey -split '://', 2)[-1]
        $findings.Add((New-TcpkFinding -Module 'network' -RuleId 'intercept.endpoint-confirmed' `
            -Severity 'INFO' -Confidence 'Confirmed (dynamic)' `
            -Title "Backend endpoint confirmed on the wire: $hst" -File $ekey `
            -Evidence "observed live traffic to $ekey" `
            -Description "The app was observed actually communicating with $ekey. Upgrades the static backend-endpoint inference to a confirmed, live destination." `
            -Fix 'Confirm this endpoint is expected and authenticated over TLS.'))
        if ($isHttp) {
            $findings.Add((New-TcpkFinding -Module 'network' -RuleId 'intercept.weak-transport' `
                -Severity 'MEDIUM' -Confidence 'Confirmed (dynamic)' `
                -Title "Cleartext http traffic observed to $hst" -File $ekey `
                -Evidence "app sent http (not https) to $hst" -Cwe @('CWE-319') `
                -Description "The app communicated with $hst over cleartext http. Any on-path attacker can read and tamper with these requests and responses." `
                -Fix 'Move all backend communication to TLS (https) and reject cleartext.'))
        }
    }
    return $findings.ToArray()
}

# ---- Hook mode (Frida inline API hooking, the Echo Mirage approach) -----------

# Locate the frida CLI: explicit override, then tools\frida\, then PATH.
function Get-TcpkFrida {
    param([string]$Override)
    $cands = @()
    if ($Override) { $cands += $Override }
    $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $cands += (Join-Path $repo 'tools/frida/frida')
    $cands += (Join-Path $repo 'tools/frida/frida.exe')
    foreach ($c in $cands) { if ($c -and (Test-Path -LiteralPath $c)) { return (Resolve-Path -LiteralPath $c).Path } }
    $cmd = Get-Command 'frida' -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    return $null
}

# Path to the bundled Frida hook script.
function Get-TcpkHookScript { return (Join-Path (Split-Path $PSScriptRoot -Parent) 'Data/tcpk_hook.js') }

# Parse a Frida hook capture (lines of 'TCPKHOOK <json>' written by tcpk_hook.js) into
# intercept.* findings. The buffers are raw plaintext read at the socket/TLS API, so the
# detection is protocol-agnostic. Deterministic; the unit-testable core of hook mode.
function ConvertFrom-TcpkHookCapture {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$HookFile)
    if (-not (Test-Path -LiteralPath $HookFile)) { return @() }

    $credSeen = New-Object 'System.Collections.Generic.HashSet[string]'
    $tokSeen  = New-Object 'System.Collections.Generic.HashSet[string]'
    $epSeen   = New-Object 'System.Collections.Generic.HashSet[string]'
    $findings = New-Object 'System.Collections.Generic.List[object]'
    $tlsSeen  = $false
    $secretRx = '(?i)(password|passwd|pwd|token|apikey|api_key|secret|access_key)=([^&\s]{3,})'
    $jsonRx   = '(?i)"(password|passwd|pwd|pass|token|apikey|api_key|secret|access_key)"\s*:\s*"([^"]{3,})"'
    $tlsFuncs = @('SSL_write', 'SSL_read', 'EncryptMessage', 'DecryptMessage',
                  'WinHttpWriteData', 'WinHttpReadData', 'HttpSendRequestW', 'HttpSendRequestA', 'InternetReadFile')

    foreach ($line in (Get-Content -LiteralPath $HookFile)) {
        $ix = "$line".IndexOf('TCPKHOOK ')
        if ($ix -lt 0) { continue }
        $rec = $null; try { $rec = ("$line".Substring($ix + 9)) | ConvertFrom-Json } catch { continue }
        if ("$($rec.dir)" -eq 'meta' -or "$($rec.dir)" -eq 'intercept') { continue }
        $data = "$($rec.data)"; if (-not $data) { continue }
        $func = "$($rec.func)"
        if ($tlsFuncs -contains $func) { $tlsSeen = $true }

        # HTTP request line + Host -> a confirmed live endpoint
        if ($data -match '(?im)^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+\S+\s+HTTP/1' -and $data -match '(?im)^Host:\s*([^\r\n]+)') {
            $h = "$($matches[1])".Trim()
            if ($h -and $epSeen.Add($h)) {
                $findings.Add((New-TcpkFinding -Module 'network' -RuleId 'intercept.endpoint-confirmed' `
                    -Severity 'INFO' -Confidence 'Confirmed (dynamic)' `
                    -Title "Backend endpoint confirmed via API hook: $h" -File $h `
                    -Evidence "captured an HTTP request to $h (hooked $func)" `
                    -Description "Captured an HTTP request to $h by hooking $func in the target process (no proxy, no CA). Confirms a live backend destination." `
                    -Fix 'Confirm this endpoint is expected and authenticated over TLS.'))
            }
        }
        # HTTP Basic credentials
        if ($data -match '(?im)Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)') {
            $dec = ''; try { $dec = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($matches[1])) } catch { }
            if ($dec -match '^(.*?):(.*)$') {
                $u = $matches[1]; $p = $matches[2]
                if ($credSeen.Add("basic|$u")) {
                    $findings.Add((New-TcpkFinding -Module 'network' -RuleId 'intercept.cleartext-credential' `
                        -Severity 'HIGH' -Confidence 'Confirmed (dynamic)' `
                        -Title 'HTTP Basic credentials captured via API hook' -File 'hook' `
                        -Evidence ("user '$u' pass '" + (Format-TcpkMaskedSecret $p) + "' (hooked $func)") -Cwe @('CWE-522') `
                        -Description "Recovered HTTP Basic credentials by hooking $func inside the process, so TLS / certificate pinning did not prevent capture. Assess whether the credential is also network-exposed (proxy mode) or only recoverable with local code execution." `
                        -Fix 'Use a short-lived token bound to the client; rotate the exposed credential.'))
                }
            }
        }
        # bearer / session token
        if ($data -match '(?im)Authorization:\s*Bearer\s+([^\r\n]+)') {
            if ($tokSeen.Add('bearer')) {
                $findings.Add((New-TcpkFinding -Module 'network' -RuleId 'intercept.session-token' `
                    -Severity 'MEDIUM' -Confidence 'Confirmed (dynamic)' `
                    -Title 'Bearer/session token captured via API hook' -File 'hook' `
                    -Evidence ('Bearer ' + (Format-TcpkMaskedSecret ("$($matches[1])".Trim())) + " (hooked $func)") -Cwe @('CWE-522') `
                    -Description "Captured a bearer token by hooking $func. A captured token can be replayed within its validity." `
                    -Fix 'Keep token lifetimes short and bind tokens to the client.'))
            }
        }
        # credential/secret parameters (protocol-agnostic) -- key=value form AND JSON REST bodies
        foreach ($rx in @($secretRx, $jsonRx)) {
        foreach ($m in [regex]::Matches($data, $rx)) {
            $pn = $m.Groups[1].Value; $pv = $m.Groups[2].Value
            if ($credSeen.Add("param|$pn|$pv")) {
                $findings.Add((New-TcpkFinding -Module 'network' -RuleId 'intercept.cleartext-credential' `
                    -Severity 'HIGH' -Confidence 'Confirmed (dynamic)' `
                    -Title 'Credential/secret parameter captured via API hook' -File 'hook' `
                    -Evidence ("$pn = " + (Format-TcpkMaskedSecret $pv) + " (hooked $func)") -Cwe @('CWE-522') `
                    -Description "The app sent a '$pn' value, recovered by hooking $func in the process regardless of transport encryption." `
                    -Fix 'Do not send credentials/secrets in the clear inside the protocol; use a proper auth flow.'))
            }
        }
        }
    }

    if ($tlsSeen) {
        $findings.Add((New-TcpkFinding -Module 'network' -RuleId 'intercept.api-hook-plaintext' `
            -Severity 'LOW' -Confidence 'Confirmed (dynamic)' `
            -Title 'TLS plaintext recovered via in-process API hook' -File 'hook' `
            -Evidence 'plaintext captured at the SSL/TLS API (SSL_write/SSL_read or SChannel)' -Cwe @('CWE-319') `
            -Description "Plaintext was recovered by hooking the TLS functions inside the process, demonstrating that transport encryption and certificate pinning do not protect the data from code running in the app context (a malicious dependency, a local attacker, or the tester). This is the interception capability, not a remote vulnerability by itself." `
            -Fix 'Recognize that client-side TLS / pinning does not defend against local code execution; minimize what the client can access and protect secrets at rest.'))
    }
    return $findings.ToArray()
}

# ---- Intercept edit pipe (Gap 2 fix: synchronous buffer modification) ----
# The TCPK GUI calls Start-TcpkInterceptPipe to create \\.\pipe\tcpk_intercept.
# The Frida hook (tcpk_hook.js) connects on its first send call and offers each
# outbound buffer for modification before the OS call completes.
#
# State hashtable keys (synchronized -- safe to read/write from any thread):
#   PacketBytes  - byte[] of the pending packet (set by server, read by GUI)
#   Decision     - 'IDLE'|'PENDING'|'FORWARD'|'PASSTHRU'|'DROP'
#   ReplyBytes   - byte[] of modified content (used when Decision = 'FORWARD')
#   Connected    - $true once the Frida hook has connected to the pipe
#   Stop         - set to $true to shut the server down

function Start-TcpkInterceptPipe {
    $state = [hashtable]::Synchronized(@{
        PacketBytes = $null
        Decision    = 'IDLE'
        ReplyBytes  = $null
        Connected   = $false
        Stop        = $false
    })

    $rs = [runspacefactory]::CreateRunspace()
    $rs.ApartmentState = 'MTA'
    $rs.ThreadOptions  = 'UseNewThread'
    $rs.Open()

    $ps = [PowerShell]::Create()
    $ps.Runspace = $rs
    [void]$ps.AddScript({
        param($State)
        $pipe = $null
        try {
            $pipe = [System.IO.Pipes.NamedPipeServerStream]::new(
                'tcpk_intercept',
                [System.IO.Pipes.PipeDirection]::InOut,
                1,
                [System.IO.Pipes.PipeTransmissionMode]::Byte,
                [System.IO.Pipes.PipeOptions]::Asynchronous)
            # Non-blocking WaitForConnection so we can honour $State.Stop
            $iar = $pipe.BeginWaitForConnection($null, $null)
            while (-not $State.Stop) {
                if ($iar.AsyncWaitHandle.WaitOne(500)) { $pipe.EndWaitForConnection($iar); break }
            }
            if ($State.Stop) { return }
            $State.Connected = $true
            $lenBuf = [byte[]]::new(4)
            while (-not $State.Stop) {
                # Read 4-byte LE length prefix
                $rd = 0; $ok = $true
                while ($rd -lt 4) {
                    try { $n = $pipe.Read($lenBuf, $rd, 4 - $rd) } catch { $ok = $false; break }
                    if ($n -eq 0) { $ok = $false; break }
                    $rd += $n
                }
                if (-not $ok -or $State.Stop) { break }
                $msgLen = [uint32][BitConverter]::ToUInt32($lenBuf, 0)
                if ($msgLen -eq 0 -or $msgLen -gt 1048576) { continue }
                # Read data
                $data = [byte[]]::new([int]$msgLen); $rd2 = 0
                while ($rd2 -lt [int]$msgLen) {
                    try { $n = $pipe.Read($data, $rd2, [int]$msgLen - $rd2) } catch { break }
                    if ($n -eq 0) { break }
                    $rd2 += $n
                }
                if ($State.Stop) { break }
                # Signal GUI: packet pending
                $State.ReplyBytes  = $null
                $State.PacketBytes = $data
                $State.Decision    = 'PENDING'
                # Wait for GUI to resolve (max 30 s, then pass through)
                $deadline = [Environment]::TickCount + 30000
                while ($State.Decision -eq 'PENDING' -and -not $State.Stop) {
                    Start-Sleep -Milliseconds 50
                    if (([Environment]::TickCount - $deadline) -gt 0) { $State.Decision = 'PASSTHRU' }
                }
                # Send reply to hook
                switch ($State.Decision) {
                    'DROP' {
                        $rl = [BitConverter]::GetBytes([uint32]0)
                        $pipe.Write($rl, 0, 4)
                    }
                    'FORWARD' {
                        $rb = $State.ReplyBytes
                        if ($null -eq $rb -or $rb.Length -eq 0) { $rb = $data }
                        $rl = [BitConverter]::GetBytes([uint32]$rb.Length)
                        $pipe.Write($rl, 0, 4); $pipe.Write($rb, 0, $rb.Length)
                    }
                    default {
                        # PASSTHRU: echo original unchanged
                        $rl = [BitConverter]::GetBytes([uint32]$data.Length)
                        $pipe.Write($rl, 0, 4); $pipe.Write($data, 0, $data.Length)
                    }
                }
                try { $pipe.Flush() } catch { }
                $State.Decision = 'IDLE'
            }
        } catch { }
        finally { if ($null -ne $pipe) { try { $pipe.Dispose() } catch { } } }
    })
    [void]$ps.AddParameter('State', $state)
    [void]$ps.BeginInvoke()

    return [pscustomobject]@{ Runspace = $rs; PowerShell = $ps; State = $state }
}

function Stop-TcpkInterceptPipe {
    param([pscustomobject]$Handle)
    if ($null -eq $Handle) { return }
    try { $Handle.State.Stop     = $true     } catch { }
    try { $Handle.State.Decision = 'PASSTHRU' } catch { }  # unblock any waiting server loop
    Start-Sleep -Milliseconds 700
    try { $Handle.PowerShell.Stop()    } catch { }
    try { $Handle.PowerShell.Dispose() } catch { }
    try { $Handle.Runspace.Close()     } catch { }
    try { $Handle.Runspace.Dispose()   } catch { }
}
