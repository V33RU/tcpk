function Test-TcpkInsecureSchemes {
<#
.SYNOPSIS
    F07. Cleartext network scheme references (http:// and ws://).

.DESCRIPTION
    Extracts non-TLS URLs -- http:// and ws:// -- from first-party binaries.
    A cleartext endpoint that carries real traffic is trivially MITM-able.

    XML-namespace and documentation URIs (w3.org, schemas.*, purl.org, etc.)
    are NOT network calls, so they are filtered out to avoid false positives.
    Findings are Confidence=Inferred: confirm the host is actually contacted at
    runtime (some remaining http:// literals can still be doc links).

.PARAMETER Path
    File or directory.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $httpRx = [regex]'http://[A-Za-z0-9.\-]+(?::\d+)?(?:/[A-Za-z0-9./?_=&%:#@~+\-]*)?'
    $wsRx   = [regex]'ws://[A-Za-z0-9.\-]+(?::\d+)?(?:/[A-Za-z0-9./?_=&%:#@~+\-]*)?'
    # ftp:// is cleartext transport too (commands, file data, and credentials in the clear).
    # Host-only match: in a .NET binary, string literals run together with non-ASCII separators
    # (ftp://host is immediately followed by the next literal), so the host class [A-Za-z0-9.\-]+
    # stops cleanly at the separator. Unlike http/ws we allow an IPv4 host: an FTP backup target
    # is commonly a bare IP and IS a real endpoint (not an ASN.1 cert artifact). A separate strict,
    # contiguous-ASCII pattern detects genuine ftp://user:pass@host embedded credentials.
    $ftpRx     = [regex]'ftp://[A-Za-z0-9.\-]+(?::\d+)?'
    $ftpCredRx = [regex]'ftp://[A-Za-z0-9._~%\-]{1,40}:[A-Za-z0-9._~%!#$*.\-]{1,40}@([A-Za-z0-9.\-]+)'
    $ipv4Rx    = '^(?:\d{1,3}\.){3}\d{1,3}$'

    # Namespace / documentation hosts that are not live network endpoints. Also includes
    # stock-tool homepages baked into bundled helper binaries -- nsis.sf.net (the NSIS
    # installer/uninstaller stub) and int3.de (the author site embedded in the stock
    # elevate.exe helper) -- which are NOT the audited app's endpoints.
    $skipHost = '(?i)(w3\.org|xmlsoap\.org|schemas\.|purl\.org|ns\.adobe\.com|aiim\.org|color\.org|iec\.ch|openxmlformats|oasis-open|docbook|relaxng|json-schema\.org|tools\.ietf|gnu\.org|whatwg\.org|wikipedia|example\.(com|org)|localhost|127\.0\.0\.1|crbug\.com|anglebug\.com|issuetracker\.google|nsis\.sf\.net|sourceforge\.net|int3\.de)'

    # PKI / certificate-revocation hosts. CRL, OCSP, AIA (CA issuer) and CA
    # distribution URLs are http:// BY DESIGN (RFC 5280 / 6960) and almost always
    # come from embedded X.509 certificate chains, not from app code. Flagging
    # them as "cleartext endpoints" is a false positive.
    $skipPki = '(?i)(^crl\d*\.|^ocsp\.|^cacerts?\.|^pki\.|^aia\.|\.?digicert\.com|crl\.microsoft\.com|go\.microsoft\.com|www\.microsoft\.com|verisign|globalsign|sectigo|usertrust|comodoca|entrust|godaddy|symantec|letsencrypt|amazontrust|quovadis|certum|identrust|\.pki\.)'

    # A real host must end in a proper TLD. This rejects ASN.1 byte artifacts
    # parsed out of embedded certificates (e.g. "ocsp.digicert.com0", "...com0a").
    $validHost = '(?i)^([a-z0-9]([a-z0-9\-]*[a-z0-9])?\.)+[a-z]{2,24}$'

    foreach ($pe in Get-TcpkPeFiles -Path $Path) {
        if (Test-TcpkIsFrameworkFile $pe.Name) { continue }
        if (Test-TcpkIsNativeNoise $pe.Name) { continue }   # bundled native runtimes are not the app's endpoints
        $text = Read-TcpkAllText -Path $pe.FullName
        if (-not $text) { continue }
        # The Chromium/Electron runtime binary embeds the whole CA OCSP/CRL/AIA URL list
        # from its root store (http:// by design); those are not the app's endpoints.
        if (Test-TcpkIsChromiumRuntime -Name $pe.Name -Text $text) { continue }

        # --- http:// ---
        $httpHosts = @{}
        foreach ($m in $httpRx.Matches($text)) {
            $h = $null; try { $h = ([Uri]$m.Value).Host } catch { continue }
            if (-not $h -or $h -notmatch $validHost -or $h -match $skipHost -or $h -match $skipPki) { continue }
            if (-not $httpHosts.ContainsKey($h)) { $httpHosts[$h] = $m.Value }
        }
        foreach ($h in ($httpHosts.Keys | Sort-Object)) {
            New-TcpkFinding -Module 'network' -RuleId 'scheme.cleartext-http' `
                -Severity 'MEDIUM' -Confidence 'Inferred' `
                -Title "Cleartext http:// endpoint: $h" `
                -File $pe.FullName -Evidence $httpHosts[$h] -Cwe @('CWE-319') `
                -Description 'Non-TLS http:// reference in first-party code. If this host is contacted at runtime, traffic (and any credentials/tokens) is exposed to network attackers and is trivially MITM-able. Confirm whether it is a live call or a documentation link.' `
                -Fix 'Use https:// with certificate validation. If the host is HTTP-only, proxy it through an authenticated TLS endpoint.'
        }

        # --- ws:// (cleartext WebSocket) ---
        $wsHosts = @{}
        foreach ($m in $wsRx.Matches($text)) {
            $h = $null; try { $h = ([Uri]$m.Value).Host } catch { continue }
            if (-not $h -or $h -notmatch $validHost -or $h -match $skipHost -or $h -match $skipPki) { continue }
            if (-not $wsHosts.ContainsKey($h)) { $wsHosts[$h] = $m.Value }
        }
        foreach ($h in ($wsHosts.Keys | Sort-Object)) {
            New-TcpkFinding -Module 'network' -RuleId 'scheme.cleartext-websocket' `
                -Severity 'HIGH' -Confidence 'Inferred' `
                -Title "Cleartext ws:// WebSocket: $h" `
                -File $pe.FullName -Evidence $wsHosts[$h] -Cwe @('CWE-319') `
                -Description 'Unencrypted WebSocket (ws://). WebSocket URLs in binaries are almost always live connections; cleartext means full message interception and injection. Confirm and migrate to wss://.' `
                -Fix 'Use wss:// (TLS) with certificate validation for all WebSocket connections.'
        }

        # --- ftp:// (cleartext file transfer; IPv4 hosts allowed) ---
        # Merge two match sources: host-only (ftp://host[/...]) and the contiguous-ASCII
        # embedded-credential form (ftp://user:pass@host, host in group 1). The latter must be
        # collected separately because the host-only regex would stop at the userinfo and reject
        # it -- so a credential URL would otherwise produce NO finding at all.
        $ftpHits = @{}   # host -> @{ ev = <evidence>; creds = <bool> }
        foreach ($m in $ftpRx.Matches($text)) {
            $h = $null; try { $h = ([Uri]$m.Value).Host } catch { continue }
            if (-not $h) { continue }
            if (($h -notmatch $validHost) -and ($h -notmatch $ipv4Rx)) { continue }
            if ($h -match $skipHost) { continue }
            if (-not $ftpHits.ContainsKey($h)) { $ftpHits[$h] = @{ ev = $m.Value; creds = $false } }
        }
        foreach ($m in $ftpCredRx.Matches($text)) {
            $h = "$($m.Groups[1].Value)"
            if (-not $h) { continue }
            if (($h -notmatch $validHost) -and ($h -notmatch $ipv4Rx)) { continue }
            if ($h -match $skipHost) { continue }
            $ftpHits[$h] = @{ ev = $m.Value; creds = $true }   # credential form wins (HIGH)
        }
        foreach ($h in ($ftpHits.Keys | Sort-Object)) {
            $hit = $ftpHits[$h]
            New-TcpkFinding -Module 'network' -RuleId 'scheme.cleartext-ftp' `
                -Severity $(if ($hit.creds) { 'HIGH' } else { 'MEDIUM' }) -Confidence 'Inferred' `
                -Title "Cleartext ftp:// endpoint: $h$(if ($hit.creds) { ' (embedded credentials)' } else { '' })" `
                -File $pe.FullName -Evidence $hit.ev -Cwe @('CWE-319') `
                -Description 'Non-TLS FTP reference in first-party code. FTP transmits commands, file contents, and any credentials in cleartext -- trivially intercepted or MITM-able. Confirm whether it is a live transfer, and check for hardcoded FTP credentials nearby.' `
                -Fix 'Use FTPS (FTP over TLS) or SFTP (SSH-based). Never send data or credentials over plain FTP, and never embed credentials in the URL.'
        }
    }
}
