function Test-TcpkNativeCertFlags {
<#
.SYNOPSIS
    F12. Certificate-validation suppression through the NATIVE HTTP stacks and through
    scripting-runtime flags, neither of which is reachable from managed IL.

.DESCRIPTION
    WHY THIS EXISTS. Test-TcpkTlsBypass finds the managed shape: a
    ServerCertificateValidationCallback that returns true unconditionally. That is only one
    of the ways a Windows desktop app turns certificate checking off, and it is the one a
    decompiler can see. The native stacks do it with an integer, and a shipped Python or
    Node payload does it with a keyword argument. Neither leaves a managed callback to find,
    so neither was detected anywhere in this tool.

    WinHTTP and WinINet both take a bitmask of SECURITY_FLAG_IGNORE_* values:
        0x0100 IGNORE_UNKNOWN_CA            0x0200 IGNORE_CERT_DATE_INVALID
        0x1000 IGNORE_CERT_CN_INVALID       0x2000 IGNORE_CERT_WRONG_USAGE
    The combined value 13056 (0x3300) is the idiom that appears in real code, usually as
    WinHttpRequest.SetOption(4, 13056) where option 4 is WinHttpRequestOption_SslErrorIgnoreFlags.
    Setting it means the handshake succeeds against any certificate at all, including one a
    network attacker minted seconds ago, which removes the only thing making TLS more than
    encryption-without-identity.

    Rules:
      tls.native-ignore-cert-errors  HIGH  A WinHTTP / WinINet certificate-error bitmask is
                                           set, or the SECURITY_FLAG_IGNORE_* constants
                                           appear alongside a set-option call.
      tls.script-verify-disabled     HIGH  A shipped script disables verification:
                                           requests verify=False, urllib3 disable_warnings
                                           with an unverified context, curl --insecure /
                                           CURLOPT_SSL_VERIFYPEER 0, or Node
                                           NODE_TLS_REJECT_UNAUTHORIZED=0.

    Text-based by design. These live in native binaries, embedded scripts and packaged
    payloads where no IL exists, so the evidence is the literal that was found and the
    confidence is Inferred unless the bitmask is unambiguous.

.PARAMETER Path
    File or directory.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { return }

    $files = @()
    $item = Get-Item -LiteralPath $Path
    if ($item.PSIsContainer) {
        try {
            $files = @(Get-ChildItem -LiteralPath $Path -Recurse -File -ErrorAction SilentlyContinue |
                       Where-Object { $_.Length -gt 0 -and $_.Length -lt 67108864 } |
                       Select-Object -First 4000)
        } catch { return }
    } else { $files = @($item) }
    if ($files.Count -eq 0) { return }

    # Extensions worth reading as text. Binaries are covered too (a native PE carries the
    # constant as a literal), but only up to the size cap above.
    $scriptExt = @('.py', '.js', '.ts', '.ps1', '.bat', '.cmd', '.vbs', '.json', '.ini', '.conf', '.cfg', '.sh')

    foreach ($f in $files) {
        if (Test-TcpkIsFrameworkFile $f.Name) { continue }
        $text = ''
        try { $text = Read-TcpkAllText -Path $f.FullName } catch { $text = '' }
        if (-not $text) { continue }

        # ---- native WinHTTP / WinINet bitmask --------------------------------
        $hits = New-Object 'System.Collections.Generic.List[string]'
        # The combined ignore-all value, as decimal or hex, next to an option setter.
        if ($text -match '(?i)(SetOption|WinHttpSetOption|InternetSetOption)' ) {
            foreach ($m in [regex]::Matches($text, '(?i)\b(13056|0x3300|&H3300)\b')) {
                if ($hits.Count -lt 4) { $hits.Add("ignore-all bitmask $($m.Value) with a set-option call") }
            }
            foreach ($n in @('SECURITY_FLAG_IGNORE_UNKNOWN_CA', 'SECURITY_FLAG_IGNORE_CERT_CN_INVALID',
                             'SECURITY_FLAG_IGNORE_CERT_DATE_INVALID', 'SECURITY_FLAG_IGNORE_WRONG_USAGE')) {
                if ($text.Contains($n) -and $hits.Count -lt 4) { $hits.Add($n) }
            }
        }
        # WinHttpRequest option 4 is SslErrorIgnoreFlags; any non-zero value there is a
        # deliberate relaxation, so the ProgID plus the option number is enough on its own.
        if ($text -match '(?i)WinHttp\.WinHttpRequest' -and $text -match '(?i)SetOption\s*\(?\s*4\s*[,)]') {
            if ($hits.Count -lt 4) { $hits.Add('WinHttpRequest.SetOption(4, ...) SslErrorIgnoreFlags') }
        }

        if ($hits.Count) {
            New-TcpkFinding -Module 'network' -RuleId 'tls.native-ignore-cert-errors' `
                -Severity 'HIGH' -Confidence 'Inferred' `
                -Title "Certificate errors suppressed in a native HTTP call: $($f.Name)" `
                -File $f.FullName -Evidence (($hits | Select-Object -Unique) -join '; ') `
                -Cwe @('CWE-295', 'CWE-297') `
                -Description ('WinHTTP and WinINet accept a bitmask that tells the stack to continue after ' +
                    'a certificate error. With the ignore-all combination set, the handshake succeeds ' +
                    'against any certificate presented, including a self-signed one an attacker on the ' +
                    'path generated for this connection. TLS still encrypts, but it no longer establishes ' +
                    'who is on the other end, which is the property the rest of the design depends on. ' +
                    'This route leaves no managed callback behind, so a decompiler-based check cannot ' +
                    'find it; the evidence here is the literal in the shipped file.') `
                -Fix 'Remove the ignore flags and let the handshake fail on an invalid certificate. If the target genuinely uses a private CA, install that CA as a trusted root on the machine or pin its public key, rather than disabling validation for every endpoint the process talks to.'
        }

        # ---- scripting-runtime verification switches -------------------------
        if ($scriptExt -notcontains $f.Extension.ToLowerInvariant()) { continue }
        $s = New-Object 'System.Collections.Generic.List[string]'
        if ($text -match '(?i)verify\s*=\s*False')                        { $s.Add('requests verify=False') }
        if ($text -match '(?i)_create_unverified_context')                { $s.Add('ssl._create_unverified_context') }
        if ($text -match '(?i)CURLOPT_SSL_VERIFYPEER\s*,?\s*(0|false)')   { $s.Add('CURLOPT_SSL_VERIFYPEER 0') }
        if ($text -match '(?i)curl[^\r\n]{0,40}(\s-k\b|--insecure)')      { $s.Add('curl --insecure') }
        if ($text -match '(?i)NODE_TLS_REJECT_UNAUTHORIZED\s*[=:]\s*.?0') { $s.Add('NODE_TLS_REJECT_UNAUTHORIZED=0') }
        if ($text -match '(?i)rejectUnauthorized\s*:\s*false')            { $s.Add('rejectUnauthorized: false') }

        if ($s.Count) {
            New-TcpkFinding -Module 'network' -RuleId 'tls.script-verify-disabled' `
                -Severity 'HIGH' -Confidence 'Confirmed' `
                -Title "Shipped script disables certificate verification: $($f.Name)" `
                -File $f.FullName -Evidence (($s | Select-Object -Unique) -join '; ') `
                -Cwe @('CWE-295') `
                -Description ('A script or config shipped inside the application turns certificate ' +
                    'verification off. This is frequently left over from a developer working against a ' +
                    'self-signed test endpoint and never removed, and it applies to every request the ' +
                    'affected client makes, not only the one it was added for. An attacker on the path ' +
                    'presents any certificate and the client accepts it.') `
                -Fix 'Remove the switch. For a private CA, point the client at the CA bundle explicitly (requests verify="/path/ca.pem", NODE_EXTRA_CA_CERTS, curl --cacert) so verification still happens against a known issuer instead of being skipped.'
        }
    }
}
