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
