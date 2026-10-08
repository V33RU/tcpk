function Test-TcpkSelfHostedServer {
<#
.SYNOPSIS
    F07. Self-hosted HTTP/web-server surface detection.

.DESCRIPTION
    Thick clients that self-host a web server (Kestrel, HttpListener, Nancy,
    EmbedIO, OWIN, SignalR) open a local network surface: any web page can hit
    http://localhost:<port> (CSRF / DNS-rebinding), and a 0.0.0.0/+ bind exposes
    it to the whole LAN. This static check looks for self-hosting markers and
    bind URLs in first-party assemblies and config.

    Severity:
      * bind to 0.0.0.0 / + / *           -> HIGH (remote-reachable)
      * localhost-only self-host marker   -> MEDIUM (verify auth + CSRF token)

.PARAMETER Path
    File or directory.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    # Specific self-hosting markers only. Ambiguous ones ('SignalR' can be a
    # client; 'WebServer(' matches unrelated types) are excluded to avoid FPs
    # in third-party libraries that merely ship alongside the app.
    $hostMarkers = @(
        'Microsoft.AspNetCore.Hosting','UseKestrel','WebApplication.CreateBuilder','IWebHostBuilder',
        'HttpListener','Nancy.Hosting','EmbedIO','Microsoft.Owin.Hosting','WebApp.Start',
        'Microsoft.AspNetCore.SignalR.Hosting','NHttp','GenHTTP','Suave.Web','WatsonWebserver','Grapevine.Server'
    )
    $rxBindAny   = [regex]'(?i)(https?://(\+|0\.0\.0\.0|\*|\[::\])):\d{2,5}'
    $rxBindLocal = [regex]'(?i)https?://(localhost|127\.0\.0\.1):\d{2,5}'
    # Cross-origin defence markers. A loopback listener is reachable by any page the user
    # visits (CSRF / DNS-rebinding); these are the named-framework signals that SOME defence
    # (anti-forgery token, Host-header filtering, or a CORS/Origin allow-list) is present in
    # the self-hosting assembly. Absence is a string signal, not proof none exists, so the
    # finding stays Inferred.
    $defenseMarkers = @(
        'AddAntiforgery','IAntiforgery','ValidateAntiForgeryToken','AutoValidateAntiforgeryToken',
        'RequestVerificationToken','__RequestVerificationToken','XSRF-TOKEN','X-CSRF','X-XSRF-TOKEN',
        'HostFilteringMiddleware','UseHostFiltering','AddHostFiltering','AllowedHosts',
        'UseCors','AddCors','WithOrigins','SetIsOriginAllowed','CorsPolicyBuilder','Access-Control-Allow-Origin'
    )

    foreach ($pe in Get-TcpkPeFiles -Path $Path) {
        if ($pe.Extension -notin '.dll','.exe') { continue }
        # Skip non-first-party binaries: the Electron main exe embeds V8/Chromium debug symbols
        # (loadVMSymbols fetching localhost:8000, OnHttp* names) that look like a self-hosted
        # server but are runtime code, not the app's -- a top false-positive source here.
        if (-not (Test-TcpkIsFirstParty -Name $pe.Name -SizeBytes $pe.Length -Path $pe.FullName)) { continue }
        $text = Read-TcpkAllText -Path $pe.FullName
        if (-not $text) { continue }

        $hit = @()
        foreach ($m in $hostMarkers) {
            if ($text.IndexOf($m, [StringComparison]::OrdinalIgnoreCase) -ge 0) { $hit += $m }
        }
        if ($hit.Count -eq 0) { continue }

        $anyBind = $rxBindAny.Match($text)
        $localBind = $rxBindLocal.Match($text)

        if ($anyBind.Success) {
            New-TcpkFinding -Module 'network' -RuleId 'selfhost.bind-all-interfaces' `
                -Severity 'MEDIUM' -Confidence 'Inferred' `
                -Title "Self-hosted server bound to all interfaces in $($pe.Name)" `
                -File $pe.FullName -Evidence ("markers: " + (($hit | Select-Object -First 4) -join ', ') + " | bind: $($anyBind.Value)") `
                -Cwe @('CWE-1327','CWE-352') `
                -Description 'The app self-hosts a web server bound to 0.0.0.0/+/* -- reachable from other hosts on the network. Without authentication this is a remote attack surface.' `
                -Fix 'Bind to 127.0.0.1 only, require authentication, and add CSRF + Origin/Host validation. Prefer named pipes for local IPC.'
        } else {
            $ev = "markers: " + (($hit | Select-Object -First 4) -join ', ')
            if ($localBind.Success) { $ev += " | bind: $($localBind.Value)" }
            New-TcpkFinding -Module 'network' -RuleId 'selfhost.local-server' `
                -Severity 'MEDIUM' -Confidence 'Inferred' `
                -Title "Self-hosted local web server in $($pe.Name)" `
                -File $pe.FullName -Evidence $ev -Cwe @('CWE-352','CWE-1327') `
                -Description 'The app appears to self-host an HTTP server (likely localhost). Local web servers are reachable by any browser page (CSRF / DNS-rebinding) and by other local users unless authenticated.' `
                -Fix 'Require auth on every endpoint, validate Origin/Host headers, use unguessable per-session tokens, and restrict to 127.0.0.1.'
        }

        # Is the listener DEFENDED against cross-origin abuse? The binary self-hosts (first-party,
        # already established above); if it carries no anti-forgery / Host-filtering / CORS marker,
        # a page the user merely visits can drive the loopback listener with the user's privileges.
        $hasDefense = $false
        foreach ($d in $defenseMarkers) {
            if ($text.IndexOf($d, [StringComparison]::OrdinalIgnoreCase) -ge 0) { $hasDefense = $true; break }
        }
        if (-not $hasDefense) {
            New-TcpkFinding -Module 'network' -RuleId 'selfhost.no-origin-check' `
                -Severity 'HIGH' -Confidence 'Inferred' `
                -Title "Self-hosted server has no Origin/Host or anti-forgery defence in $($pe.Name)" `
                -File $pe.FullName `
                -Evidence ("self-host markers: " + (($hit | Select-Object -First 4) -join ', ') + " | no Origin allow-list / Host-filtering / anti-forgery marker found in this assembly") `
                -Cwe @('CWE-352','CWE-346') `
                -AttributionBasis 'established-code' -Subject $pe.FullName `
                -Description 'The app self-hosts an HTTP listener but its binary carries no Origin allow-list, Host-header filtering, or anti-forgery token marker. A page the user merely visits can issue cross-origin requests to the loopback listener (CSRF / DNS-rebinding) and act with the user''s local privileges. This is a string signal (no KNOWN defence marker found), not proof none exists -- confirm by sending a request with a foreign Origin header to the running listener; an app that rolls its own inline Origin/Host check will not carry a named marker.' `
                -Fix 'Require auth on every endpoint, validate Origin/Host headers against an allow-list, use unguessable per-session anti-forgery tokens, and restrict to 127.0.0.1. Prefer named pipes for local IPC.'
        }
    }
}
