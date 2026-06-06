function Test-TcpkRpcChannels {
<#
.SYNOPSIS
    F10. gRPC / SignalR channel security: insecure credentials and cleartext hubs.

.DESCRIPTION
    Recon fingerprints gRPC / SignalR; this audits how they are wired:

      * gRPC insecure credentials -- first-party code that uses ChannelCredentials /
        ServerCredentials together with Insecure (i.e. ChannelCredentials.Insecure /
        GrpcChannelOptions with an insecure handler) sends RPCs with no TLS.
      * gRPC cleartext target     -- GrpcChannel.ForAddress("http://...") (h2c).
      * SignalR cleartext hub      -- a hub connection built with a ws:// or http://
        URL (HubConnectionBuilder().withUrl("http://...") in JS/TS, or an http/ws
        hub URL in shipped config).

    Binary checks are co-presence heuristics (Confidence='Inferred'); URL checks over
    shipped JS / config use anchored regexes. The gRPC/SignalR libraries themselves
    are skipped so only first-party usage is reported.

.PARAMETER Path
    File or directory.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    # ---- binaries: insecure gRPC credentials (first-party only) ----
    foreach ($pe in Get-TcpkPeFiles -Path $Path) {
        if (Test-TcpkIsFrameworkFile $pe.Name) { continue }
        if (Test-TcpkIsNativeNoise $pe.Name) { continue }
        # skip the gRPC libraries themselves (they DEFINE ChannelCredentials.Insecure)
        if ($pe.Name -match '(?i)^grpc') { continue }
        $text = Read-TcpkAllText -Path $pe.FullName
        if (-not $text) { continue }

        $usesGrpc = $text.Contains('ChannelCredentials') -or $text.Contains('ServerCredentials') -or $text.Contains('GrpcChannel')
        if ($usesGrpc -and $text.Contains('Insecure')) {
            New-TcpkFinding -Module 'static' -RuleId 'rpc.grpc-insecure-credentials' `
                -Severity 'HIGH' -Confidence 'Inferred' `
                -Title "Insecure gRPC channel credentials in $($pe.Name)" `
                -File $pe.FullName -Evidence 'references ChannelCredentials/ServerCredentials + Insecure' `
                -Cwe @('CWE-319') `
                -Description 'First-party code appears to create a gRPC channel with insecure (no-TLS) credentials, so RPC traffic -- including any auth tokens -- is sent in cleartext.' `
                -Fix 'Use ChannelCredentials.SecureSsl / a TLS GrpcChannel; never ChannelCredentials.Insecure outside local tests. Decompile the method to confirm.'
        }
    }

    # ---- shipped JS / TS / config: cleartext SignalR hubs + gRPC targets ----
    $scanExt = @('.js', '.mjs', '.cjs', '.ts', '.json', '.config', '.xml', '.html')
    $item = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
    if (-not $item) { return }
    $textFiles = if ($item.PSIsContainer) {
        Get-ChildItem -LiteralPath $Path -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension.ToLowerInvariant() -in $scanExt -and $_.Length -lt 6MB }
    } else { @($item) }

    $signalrRx = [regex]'(?i)withUrl\s*\(\s*["''](ws|http)://[^"'']+'
    $grpcRx    = [regex]'(?i)ForAddress\s*\(\s*["'']http://[^"'']+'

    foreach ($tf in $textFiles) {
        $t = $null
        try { $t = [IO.File]::ReadAllText($tf.FullName) } catch { continue }
        if (-not $t) { continue }

        $sm = $signalrRx.Match($t)
        if ($sm.Success) {
            $v = $sm.Value; if ($v.Length -gt 100) { $v = $v.Substring(0, 100) + ' ...' }
            New-TcpkFinding -Module 'static' -RuleId 'rpc.signalr-cleartext-hub' `
                -Severity 'MEDIUM' -Confidence 'Inferred' `
                -Title "Cleartext SignalR hub URL in $($tf.Name)" `
                -File $tf.FullName -Evidence $v `
                -Cwe @('CWE-319') `
                -Description 'A SignalR hub connection is built with a ws:// or http:// URL, so the real-time channel (and its bearer/access tokens) is unencrypted and interceptable.' `
                -Fix 'Use wss:// / https:// for hub URLs.'
        }

        $gm = $grpcRx.Match($t)
        if ($gm.Success) {
            $v = $gm.Value; if ($v.Length -gt 100) { $v = $v.Substring(0, 100) + ' ...' }
            New-TcpkFinding -Module 'static' -RuleId 'rpc.grpc-cleartext-target' `
                -Severity 'MEDIUM' -Confidence 'Inferred' `
                -Title "Cleartext gRPC target in $($tf.Name)" `
                -File $tf.FullName -Evidence $v `
                -Cwe @('CWE-319') `
                -Description 'A gRPC channel address uses http:// (HTTP/2 cleartext / h2c), so RPC traffic is not encrypted.' `
                -Fix 'Use an https:// gRPC address with TLS credentials.'
        }
    }
}
