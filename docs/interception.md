# Traffic interception (Invoke-TcpkIntercept)

Thick-client interception in TCPK. TCPK does not reimplement a proxy: it orchestrates
[mitmproxy](https://mitmproxy.org) (`mitmdump`) with a bundled capture addon
(`TCPK/Data/tcpk_capture.py`) and parses the captured flows into `intercept.*` findings.

Status: `2.4.1-dev`. The flow parser and the mitmproxy capture pipeline are verified end
to end on Linux. The active app-launch path is Windows-verified-pending (see below).

## Prerequisite: mitmdump

Not bundled (size + separate license). Get the portable binary from
<https://mitmproxy.org/downloads> and either:

- drop `mitmdump` / `mitmdump.exe` in `tools/mitmproxy/`, or
- put it on `PATH`, or
- pass `-MitmdumpPath <path>`.

## Mode 1 - parse an existing capture (`-FlowFile`)

Cross-platform, ungated. Run mitmproxy yourself (or on any box), capture with the TCPK
addon, then hand TCPK the JSONL:

```powershell
# capture (any OS):  mitmdump -s TCPK/Data/tcpk_capture.py    (writes to $env:TCPK_INTERCEPT_OUT)
Invoke-TcpkIntercept -FlowFile .\tcpk-flows.jsonl
```

## Mode 2 - active capture (`-Target`, GATED, Windows)

Launches the app through a local `mitmdump` and observes its traffic:

```powershell
Enable-TcpkExploit -Acknowledge
Invoke-TcpkIntercept -Target 'C:\path\App.exe' -ConfirmDynamic -DurationSec 30
```

Requirements: `Enable-TcpkExploit` + `-ConfirmDynamic` (it launches the target), Windows,
and the app must honour the system proxy and trust the mitmproxy CA
(`~/.mitmproxy/mitmproxy-ca-cert.cer`) for TLS. TCPK's static `tls.pinning-absent` /
accept-all findings tell you in advance whether interception will work; a pinned or
proxy-ignoring app needs a pinning bypass or transparent proxying first.

Read-only: the addon observes and records flows; it never modifies a request or response.

## Findings

All `Confirmed (dynamic)` (observed on the wire):

| RuleId | What |
|--------|------|
| `intercept.endpoint-confirmed` | a backend endpoint the app actually talked to (upgrades the static inference) |
| `intercept.cleartext-credential` | HTTP Basic (decoded) or a `password`/`token`/`secret` parameter in the query or body |
| `intercept.session-token` | a bearer / session token sent by the app (replayable) |
| `intercept.weak-transport` | cleartext `http` traffic (no TLS) |

Recovered secrets are masked in the evidence; the username and parameter names are shown.
