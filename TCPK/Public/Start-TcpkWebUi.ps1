function Start-TcpkWebUi {
<#
.SYNOPSIS
    Launch the TCPK local web control panel -- a browser front-end that drives a
    discovery audit and shows the result in the intelligence dashboard.

.DESCRIPTION
    Starts a LOOPBACK-ONLY HTTP server (raw TcpListener; no admin / no urlacl, no
    external dependencies) and opens your default browser to it. From the page you can
    point at a target (install dir, EXE/DLL, or an MSIX/MSI/ZIP that TCPK auto-unwraps),
    run the audit, and read the findings with the same evidence-ladder cards as the
    offline intel.html report.

    SECURITY MODEL (this is a pentest tool -- the panel is built not to become a hole):
      * Binds 127.0.0.1 ONLY. No other machine on the network can reach it.
      * Every /api/* request must carry an 'X-TCPK-Token' header equal to the random
        per-session token. A web page you happen to visit cannot set a custom header on
        a cross-origin request without a CORS preflight (which this server never grants),
        so it cannot drive the panel -- this closes the localhost-CSRF / DNS-rebind hole.
      * The Host header must be 127.0.0.1:<port> (anti DNS-rebind).
      * The API is a FIXED verb set over a validated target path -- the browser cannot
        send arbitrary PowerShell, and the gated exploit bucket (K01-K06) is NEVER
        reachable from here. This is a discovery-only surface.

    Stop it with Ctrl+C, the 'stop server' link on the page, or the idle timeout.

.PARAMETER Port
    TCP port to bind on 127.0.0.1. Default 0 = let the OS pick a free high port.

.PARAMETER NoBrowser
    Do not auto-open the browser; just print the URL.

.PARAMETER IdleTimeoutMinutes
    Auto-stop after this many minutes with no requests. Default 30. 0 = no timeout.

.PARAMETER Token
    Optional. Pin the session token (gives a stable, bookmarkable URL across restarts,
    and lets automation drive the panel). LEAVE UNSET for normal use -- a fresh, secure
    random token is generated each launch, which is the stronger default.
#>
    [CmdletBinding()]
    param(
        [ValidateRange(0, 65535)][int]$Port = 0,
        [switch]$NoBrowser,
        [int]$IdleTimeoutMinutes = 30,
        [string]$Token
    )

    $token = if ($Token) { $Token } else { New-TcpkWebToken }
    $listener = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, $Port)
    try { $listener.Start() }
    catch { throw "Could not bind 127.0.0.1:$Port -- $($_.Exception.Message)" }

    $actualPort = ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
    $ver = try { "$((Get-Module TCPK | Select-Object -First 1).Version)" } catch { '2.4.3-dev' }
    $state = @{
        Token = $token; Port = $actualPort; Version = $ver; Stop = $false
        Jobs = @{}                                   # jobId -> running/finished audit
        Psd1 = (Join-Path $script:TcpkRoot 'TCPK.psd1')
        ChkTotal = (Get-TcpkWebCheckCount)           # progress denominator
    }
    $url = "http://127.0.0.1:$actualPort/?t=$token"

    Write-Host ""
    Write-Host "  TCPK web control panel" -ForegroundColor Cyan
    Write-Host "  ----------------------------------------------------------"
    Write-Host "  URL    : " -NoNewline; Write-Host $url -ForegroundColor Green
    Write-Host "  Bind   : 127.0.0.1:$actualPort  (loopback only -- not on the network)"
    Write-Host "  Auth   : per-session token (in the URL above)"
    Write-Host "  Scope  : DISCOVERY ONLY -- the exploit bucket is not reachable here."
    Write-Host "  Stop   : Ctrl+C, the 'stop server' link, or $IdleTimeoutMinutes min idle."
    Write-Host "  ----------------------------------------------------------"
    Write-Host ""

    if (-not $NoBrowser) { try { Start-Process $url | Out-Null } catch { Write-Host "  (open the URL manually)" } }

    $lastActivity = [DateTime]::UtcNow
    try {
        while (-not $state.Stop) {
            if (-not $listener.Pending()) {
                Start-Sleep -Milliseconds 150
                if ($IdleTimeoutMinutes -gt 0 -and ([DateTime]::UtcNow - $lastActivity).TotalMinutes -ge $IdleTimeoutMinutes) {
                    Write-Host "  Idle timeout reached -- stopping." -ForegroundColor Yellow
                    break
                }
                continue
            }
            $lastActivity = [DateTime]::UtcNow
            $client = $listener.AcceptTcpClient()
            try {
                $client.ReceiveTimeout = 15000; $client.SendTimeout = 15000
                $ns = $client.GetStream()
                $req = Read-TcpkHttpRequest -Stream $ns
                if ($req) {
                    $resp = try { Invoke-TcpkWebApi -Request $req -State $state }
                            catch { New-TcpkWebJson 500 @{ error = "$($_.Exception.Message)" } }
                    if ($resp.File) { Write-TcpkHttpFile -Stream $ns -Path $resp.File -ContentType $resp.ContentType -Download $resp.Download }
                    else { Write-TcpkHttpResponse -Stream $ns -Status $resp.Status -ContentType $resp.ContentType -Body $resp.Body }
                }
            } catch {
                # one bad client must never kill the server
                Write-Verbose "request error: $($_.Exception.Message)"
            } finally {
                try { $client.Close() } catch { }
            }
        }
    } finally {
        try { $listener.Stop() } catch { }
        # stop any audits still running and clean up their pause flags
        foreach ($e in @($state.Jobs.Values)) {
            try { if ($e.Job) { Stop-Job -Job $e.Job -ErrorAction SilentlyContinue; Remove-Job -Job $e.Job -Force -ErrorAction SilentlyContinue } } catch { }
            try { Remove-Item -LiteralPath $e.PauseFlag -Force -ErrorAction SilentlyContinue } catch { }
        }
        Write-Host "  TCPK web control panel stopped." -ForegroundColor Yellow
    }
}
