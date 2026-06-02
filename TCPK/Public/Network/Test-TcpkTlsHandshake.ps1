function Test-TcpkTlsHandshake {
<#
.SYNOPSIS
    F09. Active TLS handshake probe (testssl-lite) - which protocol versions a backend
    actually negotiates, plus the certificate-validity result.

.DESCRIPTION
    Complements the STATIC TLS checks (Test-TcpkTlsProtocols reads enum markers in the
    binary). This makes a real client handshake to each endpoint, once per protocol
    version (SSL3 / TLS 1.0 / 1.1 / 1.2 / 1.3 where the platform supports it), and
    reports which are negotiable. Any of SSL3 / TLS 1.0 / TLS 1.1 is flagged HIGH
    (downgrade / weak-protocol exposure). It also records whether the server
    certificate validates against the machine trust store.

    This OPENS NETWORK CONNECTIONS to the target's backend, so it is gated behind
    Enable-TcpkExploit (treat as authorized active testing).

.PARAMETER Endpoint
    One or more 'host' or 'host:port' targets (default port 443). Pass the backend
    hosts from Test-TcpkBackendEndpoints / Test-TcpkEndpoints.

.PARAMETER TimeoutMs
    Per-connection timeout (default 4000).

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string[]]$Endpoint,
        [int]$TimeoutMs = 4000
    )

    Assert-TcpkExploitEnabled 'Test-TcpkTlsHandshake'
    if (-not (Assert-TcpkWindows 'Test-TcpkTlsHandshake')) { return }

    # Candidate protocols that exist in this runtime's SslProtocols enum.
    $enumNames = [Enum]::GetNames([System.Security.Authentication.SslProtocols])
    $candidates = @(
        @{ Name='Ssl3';  Weak=$true  }
        @{ Name='Tls';   Weak=$true  }   # TLS 1.0
        @{ Name='Tls11'; Weak=$true  }   # TLS 1.1
        @{ Name='Tls12'; Weak=$false }
        @{ Name='Tls13'; Weak=$false }
    ) | Where-Object { $enumNames -contains $_.Name }

    foreach ($ep in $Endpoint) {
        if (-not $ep) { continue }
        $parts = $ep -replace '^\w+://','' -split '[/:]' | Where-Object { $_ }
        $eHost = $parts[0]
        $port = if ($ep -match ':(\d+)') { [int]$matches[1] } else { 443 }

        $negotiated = New-Object System.Collections.Generic.List[string]
        $weakNeg    = New-Object System.Collections.Generic.List[string]
        $certBad    = $null

        foreach ($c in $candidates) {
            $tcp = $null; $ssl = $null
            try {
                $tcp = New-Object System.Net.Sockets.TcpClient
                $iar = $tcp.BeginConnect($eHost, $port, $null, $null)
                if (-not $iar.AsyncWaitHandle.WaitOne($TimeoutMs)) { $tcp.Close(); continue }
                $tcp.EndConnect($iar)

                $script:_tcpkCertErr = 'None'
                $cb = [System.Net.Security.RemoteCertificateValidationCallback]{
                    param($sender,$cert,$chain,$errors)
                    $script:_tcpkCertErr = "$errors"
                    return $true   # accept so the handshake completes; we record the error
                }
                $ssl = New-Object System.Net.Security.SslStream($tcp.GetStream(), $false, $cb)
                $proto = [System.Security.Authentication.SslProtocols]$c.Name
                $ssl.AuthenticateAsClient($eHost, $null, $proto, $false)

                $negotiated.Add($c.Name)
                if ($c.Weak) { $weakNeg.Add($c.Name) }
                if ($script:_tcpkCertErr -ne 'None' -and $null -eq $certBad) { $certBad = $script:_tcpkCertErr }
            } catch {
                # handshake refused for this protocol -> not negotiable (expected for disabled versions)
            } finally {
                if ($ssl) { $ssl.Dispose() }
                if ($tcp) { $tcp.Close() }
            }
        }

        if ($negotiated.Count -eq 0) {
            New-TcpkFinding -Module 'network' -RuleId 'tls-handshake.unreachable' `
                -Severity 'INFO' -Confidence 'Skipped' `
                -Title "No TLS handshake completed: ${eHost}:$port" `
                -File "${eHost}:$port" -Evidence 'host unreachable, non-TLS port, or all probed versions refused' `
                -Description 'Could not complete a TLS handshake on any probed version.'
            continue
        }

        New-TcpkFinding -Module 'network' -RuleId 'tls-handshake.supported' `
            -Severity 'INFO' -Confidence 'Confirmed' `
            -Title "Negotiable TLS on ${eHost}:$port - $($negotiated -join ', ')" `
            -File "${eHost}:$port" -Evidence "protocols: $($negotiated -join ', ')" `
            -Description 'Protocol versions the backend actually negotiates from a client handshake.'

        if ($weakNeg.Count -gt 0) {
            New-TcpkFinding -Module 'network' -RuleId 'tls-handshake.weak-protocol' `
                -Severity 'HIGH' -Confidence 'Confirmed' `
                -Title "Weak TLS version negotiable on ${eHost}:$port - $($weakNeg -join ', ')" `
                -File "${eHost}:$port" -Evidence "weak: $($weakNeg -join ', ')" -Cwe @('CWE-326','CWE-757') `
                -Description 'The backend still negotiates a deprecated/broken TLS version, enabling downgrade and known protocol attacks (POODLE/BEAST etc.).' `
                -Fix 'Disable SSL3 / TLS 1.0 / TLS 1.1 server-side; require TLS 1.2+ (prefer 1.3).'
        }
        if ($certBad) {
            New-TcpkFinding -Module 'network' -RuleId 'tls-handshake.bad-cert' `
                -Severity 'MEDIUM' -Confidence 'Confirmed' `
                -Title "Server certificate does not validate: ${eHost}:$port" `
                -File "${eHost}:$port" -Evidence "SslPolicyErrors: $certBad" -Cwe @('CWE-295') `
                -Description 'The server certificate failed machine-trust validation (name mismatch / untrusted root / expired). If the client also skips validation, MITM is trivial.' `
                -Fix 'Serve a valid, properly-chained certificate matching the hostname; ensure the client validates it.'
        }
    }
}
