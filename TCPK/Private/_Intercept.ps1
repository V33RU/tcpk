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
    $applied = @()
    if (Test-Path -LiteralPath $LogFile) { $applied = @(Get-Content -LiteralPath $LogFile | Where-Object { "$_" -match 'TCPKTAMPER' }) }
    if (-not $applied.Count) {
        return (New-TcpkFinding -Module 'network' -RuleId 'intercept.tamper-inactive' -Severity 'INFO' -Confidence 'Inferred' `
            -Title 'Tamper rules matched no traffic' -File $Target -Evidence "$(@($Rules).Count) rule(s), 0 applied" `
            -Description "The app produced no traffic matching the tamper rules. It may not have sent the targeted request, may pin certificates / ignore the proxy, or the rule string did not match the on-the-wire bytes." `
            -Fix 'Drive the app to send the targeted request, confirm the rule matches the wire bytes, and ensure the app honours the proxy and trusts the mitmproxy CA.')
    }
    return (New-TcpkFinding -Module 'network' -RuleId 'intercept.tamper-applied' -Severity 'HIGH' -Confidence 'Confirmed (dynamic)' `
        -Title "Modified $($applied.Count) live request/response(s) in flight" -File $Target `
        -Evidence (($applied | Select-Object -First 8) -join ' | ') -Cwe @('CWE-602', 'CWE-807') `
        -Description "TCPK modified the app's traffic in flight via the mitmproxy tamper addon. Use this to probe whether the backend re-validates client-supplied values (authorization, role, price, injection) SERVER-side rather than trusting the client -- if a tampered value is honoured, the server trusts the client." `
        -Fix 'Enforce every security decision server-side and validate all input independently of the client; never trust a client-supplied value.')
}

# A free loopback TCP port.
function Get-TcpkFreePort {
    $l = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $l.Start(); $p = ([System.Net.IPEndPoint]$l.LocalEndpoint).Port; $l.Stop(); return $p
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
    $tlsFuncs = @('SSL_write', 'SSL_read', 'EncryptMessage', 'DecryptMessage')

    foreach ($line in (Get-Content -LiteralPath $HookFile)) {
        $ix = "$line".IndexOf('TCPKHOOK ')
        if ($ix -lt 0) { continue }
        $rec = $null; try { $rec = ("$line".Substring($ix + 9)) | ConvertFrom-Json } catch { continue }
        if ("$($rec.dir)" -eq 'meta') { continue }
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
        # credential/secret parameters (protocol-agnostic)
        foreach ($m in [regex]::Matches($data, $secretRx)) {
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
