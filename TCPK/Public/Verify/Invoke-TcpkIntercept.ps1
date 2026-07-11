function Invoke-TcpkIntercept {
<#
.SYNOPSIS
    Traffic interception for a thick client, via mitmproxy. Two modes: parse an existing
    mitmproxy capture into findings (-FlowFile, cross-platform, ungated), or actively
    launch the target through a local mitmdump and observe its traffic (-Target, GATED).

.DESCRIPTION
    TCPK does not reimplement a proxy. It orchestrates mitmproxy (mitmdump) with a bundled
    capture addon (Data/tcpk_capture.py) that records each flow, then parses the flows into
    intercept.* findings: endpoints confirmed on the wire (Confirmed dynamic), HTTP Basic /
    bearer credentials, credential/secret parameters, and cleartext-http transport.

    ACTIVE mode is GATED (Enable-TcpkExploit -Acknowledge, plus -ConfirmDynamic) and Windows-
    only, because it LAUNCHES the target and routes it through the proxy. It observes only;
    the addon never modifies a flow. For TLS interception the app must trust the mitmproxy
    CA (mitmproxy.org: ~/.mitmproxy/mitmproxy-ca-cert.cer) and honour the system proxy;
    TCPK's static tls.pinning-absent / accept-all findings tell you in advance whether that
    will work. mitmdump is NOT bundled: drop the portable binary in tools\mitmproxy\ or PATH.

.PARAMETER FlowFile
    Parse mode. A JSONL capture written by the TCPK mitmproxy addon; produces findings with
    no launch and no gating.

.PARAMETER Target
    Active mode. Path to the app executable to launch through the proxy.

.PARAMETER ConfirmDynamic
    Required for active mode. Acknowledges that this LAUNCHES the target and intercepts it.

.PARAMETER Port
    Proxy listen port (0 = auto-pick a free loopback port).

.PARAMETER DurationSec
    Seconds to capture before stopping (default 20).

.PARAMETER MitmdumpPath
    Explicit path to mitmdump (overrides tools\mitmproxy\ and PATH discovery).

.PARAMETER ExtraArgs
    Extra launch arguments for the target (e.g. a file to open).

.OUTPUTS
    [TcpkFinding] - intercept.* findings ('Confirmed (dynamic)' for observed traffic).
#>
    [CmdletBinding(DefaultParameterSetName = 'Parse')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'Parse')][string]$FlowFile,
        [Parameter(Mandatory, ParameterSetName = 'Active')][string]$Target,
        [Parameter(ParameterSetName = 'Active')][switch]$ConfirmDynamic,
        [Parameter(ParameterSetName = 'Active')][int]$Port = 0,
        [Parameter(ParameterSetName = 'Active')][int]$DurationSec = 20,
        [Parameter(ParameterSetName = 'Active')][string]$MitmdumpPath,
        [Parameter(ParameterSetName = 'Active')][string[]]$ExtraArgs = @()
    )

    if ($PSCmdlet.ParameterSetName -eq 'Parse') {
        if (-not (Test-Path -LiteralPath $FlowFile)) { throw "Flow file not found: $FlowFile" }
        return (ConvertFrom-TcpkInterceptCapture -FlowFile $FlowFile)
    }

    Assert-TcpkExploitEnabled 'Invoke-TcpkIntercept'
    if (-not $ConfirmDynamic) {
        throw "Invoke-TcpkIntercept LAUNCHES the target and actively intercepts its traffic. Re-run with -ConfirmDynamic to acknowledge (authorized targets only)."
    }
    if (-not (Assert-TcpkWindows 'Invoke-TcpkIntercept')) { return }
    if (-not (Test-Path -LiteralPath $Target)) { throw "Target not found: $Target" }

    $mitm = Get-TcpkMitmdump -Override $MitmdumpPath
    if (-not $mitm) { throw "mitmdump not found. Drop the portable mitmproxy binary in tools\mitmproxy\ (https://mitmproxy.org/downloads) or add it to PATH." }
    $addon = Get-TcpkInterceptAddon
    if (-not (Test-Path -LiteralPath $addon)) { throw "capture addon missing: $addon" }
    if ($Port -le 0) { $Port = Get-TcpkFreePort }

    $out = Join-Path ([System.IO.Path]::GetTempPath()) ("tcpk-flows-" + [guid]::NewGuid().ToString('N') + ".jsonl")
    $env:TCPK_INTERCEPT_OUT = $out
    $mp = $null; $tp = $null; $prevHttp = $env:HTTP_PROXY; $prevHttps = $env:HTTPS_PROXY
    try {
        Write-TcpkInfo "[intercept] starting mitmdump on 127.0.0.1:$Port (capture -> $out)"
        $mp = Start-Process -FilePath $mitm -ArgumentList @('--listen-host', '127.0.0.1', '-p', "$Port", '-s', "$addon", '-q') -PassThru -WindowStyle Minimized -ErrorAction Stop
        Start-Sleep -Seconds 2
        $env:HTTP_PROXY = "http://127.0.0.1:$Port"; $env:HTTPS_PROXY = "http://127.0.0.1:$Port"
        Write-TcpkInfo "[intercept] launching $(Split-Path $Target -Leaf) via proxy (~${DurationSec}s). Trust the mitmproxy CA if TLS does not intercept."
        $tp = Start-Process -FilePath $Target -ArgumentList $ExtraArgs -PassThru -WindowStyle Minimized -ErrorAction Stop
        $deadline = (Get-Date).AddSeconds($DurationSec)
        while ((Get-Date) -lt $deadline -and $tp -and -not $tp.HasExited) { Start-Sleep -Milliseconds 500 }
    } finally {
        $env:HTTP_PROXY = $prevHttp; $env:HTTPS_PROXY = $prevHttps
        if ($tp -and -not $tp.HasExited) { try { Stop-Process -Id $tp.Id -Force -ErrorAction SilentlyContinue } catch { } }
        if ($mp -and -not $mp.HasExited) { try { Stop-Process -Id $mp.Id -Force -ErrorAction SilentlyContinue } catch { } }
        Remove-Item Env:\TCPK_INTERCEPT_OUT -ErrorAction SilentlyContinue
    }

    if (-not (Test-Path -LiteralPath $out)) {
        return (New-TcpkFinding -Module 'network' -RuleId 'intercept.no-traffic' -Severity 'INFO' -Confidence 'Inferred' `
            -Title 'No traffic intercepted' -File $Target -Evidence "no flows captured in ${DurationSec}s" `
            -Description "The app produced no proxied traffic. It may ignore the system proxy (needs transparent proxying), pin certificates (needs a pinning bypass; see tls.pinning-absent), need more time, or require UI interaction during capture." `
            -Fix 'Re-run with a longer -DurationSec, drive the app UI during capture, or handle proxy-ignoring / certificate-pinned transport.')
    }
    ConvertFrom-TcpkInterceptCapture -FlowFile $out
}
