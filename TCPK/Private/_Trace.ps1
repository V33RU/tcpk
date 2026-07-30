# Runtime API-tracer engine for Invoke-TcpkApiTrace. TCPK drives the operator's Frida
# (Get-TcpkFrida) with the tcpk_apitrace.js agent, which hooks security-relevant Windows APIs
# in a running target and prints one 'TCPKTRACE <json>' line per call. The deterministic,
# unit-testable core is the PARSER below (ConvertFrom-TcpkApiTrace): trace lines -> findings.

# Path to the bundled API-tracer Frida agent.
function Get-TcpkApiTraceScript { return (Join-Path (Split-Path $PSScriptRoot -Parent) 'Data/tcpk_apitrace.js') }

# Weak CryptoAPI CALG_* ids -> name (BCrypt uses string alg names instead).
$script:TcpkWeakCalg = @{ 0x8001 = 'MD2'; 0x8002 = 'MD4'; 0x8003 = 'MD5'; 0x6601 = 'DES'; 0x6602 = 'RC2'; 0x6603 = '3DES'; 0x6801 = 'RC4' }

# Parse a Frida API-trace capture (lines of 'TCPKTRACE <json>' from tcpk_apitrace.js) into
# api-trace.* findings. Every finding is a DIRECTLY OBSERVED live call, so Confidence is
# 'Confirmed (dynamic)'. Deterministic; this is the unit-testable heart of the tracer.
function ConvertFrom-TcpkApiTrace {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$TraceFile)
    if (-not (Test-Path -LiteralPath $TraceFile)) { return @() }

    $out = New-Object 'System.Collections.Generic.List[object]'
    $seen = New-Object 'System.Collections.Generic.HashSet[string]'
    $counts = @{ crypto = 0; process = 0; command = 0; file = 0; registry = 0; dpapi = 0 }
    $weakAlgRx = '(?i)^(MD2|MD4|MD5|RC2|RC4|DES|DESX|3DES)$'
    $shellRx = '(?i)(cmd(\.exe)?["\s]|/c\s|/k\s|powershell|-enc\b|-e[nc]{0,7}\s|&&|\|\||;\s|\$\(|`)'
    $secretRx = '(?i)(password|passwd|pwd|token|apikey|api[_-]?key|secret|access[_-]?key|bearer\s|private[_-]?key|client[_-]?secret)'
    $dpapiCount = 0

    foreach ($line in (Get-Content -LiteralPath $TraceFile)) {
        $ix = "$line".IndexOf('TCPKTRACE ')
        if ($ix -lt 0) { continue }
        $rec = $null; try { $rec = ("$line".Substring($ix + 10)) | ConvertFrom-Json } catch { continue }
        if (-not $rec) { continue }
        $cat = "$($rec.cat)"
        if ($counts.ContainsKey($cat)) { $counts[$cat]++ }

        switch ($cat) {
            'crypto' {
                $alg = "$($rec.alg)"
                if (-not $alg -and $rec.PSObject.Properties['algid']) { $alg = $script:TcpkWeakCalg[[int]$rec.algid] }
                if ($alg -and $alg -match $weakAlgRx) {
                    if ($seen.Add("weakcrypto:$alg")) {
                        $out.Add((New-TcpkFinding -Module 'runtime' -RuleId 'api-trace.weak-crypto-call' -Severity 'MEDIUM' `
                            -Confidence 'Confirmed (dynamic)' -Cwe @('CWE-327') `
                            -Title "Weak cryptographic algorithm used at runtime: $alg" `
                            -Evidence "hooked $($rec.api) selecting $alg" `
                            -Description "The running process called $($rec.api) with the broken/weak algorithm $alg. Observed live in the target." `
                            -Fix 'Replace with AES-GCM / SHA-256+ and a vetted KDF; remove DES/RC4/MD5 usage.'))
                    }
                }
            }
            'process' {
                $cmd = if ($rec.cmd) { "$($rec.cmd)" } else { (@("$($rec.file)", "$($rec.params)") | Where-Object { $_ } ) -join ' ' }
                $cmd = $cmd.Trim()
                if ($cmd -and $seen.Add("proc:$cmd")) {
                    $sev = if ($cmd -match $shellRx) { 'MEDIUM' } else { 'INFO' }
                    $out.Add((New-TcpkFinding -Module 'runtime' -RuleId 'api-trace.process-launch' -Severity $sev `
                        -Confidence 'Confirmed (dynamic)' -Cwe @('CWE-78') `
                        -Title "Process launch at runtime: $($rec.api)" `
                        -Evidence $cmd `
                        -Description "The target launched a process via $($rec.api). $(if ($sev -eq 'MEDIUM') { 'The command line uses a shell / encoded payload -- review for command injection.' } else { 'Confirm the command line is not attacker-influenced.' })" `
                        -Fix 'Launch executables by absolute path with an argument array; never build a shell command line from untrusted input.'))
                }
            }
            'command' {
                $cmd = "$($rec.cmd)".Trim()
                if ($cmd -and $seen.Add("cmd:$cmd")) {
                    $out.Add((New-TcpkFinding -Module 'runtime' -RuleId 'api-trace.command-exec' -Severity 'MEDIUM' `
                        -Confidence 'Confirmed (dynamic)' -Cwe @('CWE-78') `
                        -Title 'C runtime system() call at runtime' -Evidence $cmd `
                        -Description "The target called system() with a shell command line. If any part is attacker-controlled this is command injection." `
                        -Fix 'Do not use system(); exec the program directly with a validated argument vector.'))
                }
            }
            'file' {
                $pv = "$($rec.preview)"
                if ($pv -match $secretRx) {
                    $key = "$($matches[1])".ToLowerInvariant()
                    if ($seen.Add("filewrite:$key")) {
                        $out.Add((New-TcpkFinding -Module 'runtime' -RuleId 'api-trace.plaintext-secret-write' -Severity 'MEDIUM' `
                            -Confidence 'Confirmed (dynamic)' -Cwe @('CWE-312') `
                            -Title "Secret-looking data written to disk at runtime ($key)" `
                            -Evidence ($pv.Substring(0, [Math]::Min(120, $pv.Length))) `
                            -Description "The target wrote a buffer containing a '$key' token to a file (hooked WriteFile). A credential may be persisted in cleartext." `
                            -Fix 'Encrypt secrets at rest (DPAPI / a keystore); never write credentials to disk in cleartext.'))
                    }
                }
            }
            'registry' {
                $blob = (@("$($rec.name)", "$($rec.preview)") -join ' ')
                if ($blob -match $secretRx) {
                    $key = "$($matches[1])".ToLowerInvariant()
                    if ($seen.Add("regwrite:${key}:$($rec.name)")) {
                        $out.Add((New-TcpkFinding -Module 'runtime' -RuleId 'api-trace.registry-secret-write' -Severity 'MEDIUM' `
                            -Confidence 'Confirmed (dynamic)' -Cwe @('CWE-312') `
                            -Title "Secret-looking value written to the registry at runtime ($key)" `
                            -Evidence "value '$($rec.name)'" `
                            -Description "The target wrote a registry value whose name/data contains a '$key' token (hooked RegSetValueExW). Credentials in the registry are readable by the user." `
                            -Fix 'Store secrets with DPAPI (CurrentUser) or a proper keystore, not as plain registry values.'))
                    }
                }
            }
            'dpapi' { $dpapiCount++ }
        }
    }

    if ($dpapiCount -gt 0) {
        $out.Add((New-TcpkFinding -Module 'runtime' -RuleId 'api-trace.dpapi-use' -Severity 'INFO' `
            -Confidence 'Confirmed (dynamic)' `
            -Title "DPAPI used at runtime ($dpapiCount call(s))" `
            -Evidence "CryptProtectData / CryptUnprotectData hooked $dpapiCount time(s)" `
            -Description 'The target uses DPAPI to protect/unprotect data. Anything DPAPI-protected as CurrentUser is recoverable by code running as that user (see Get-TcpkStoredCredentials).'))
    }

    $total = ($counts.Values | Measure-Object -Sum).Sum
    $out.Add((New-TcpkFinding -Module 'runtime' -RuleId 'api-trace.summary' -Severity 'INFO' `
        -Confidence 'Confirmed (dynamic)' `
        -Title "API trace: $total security-relevant call(s) observed" `
        -Evidence (($counts.GetEnumerator() | Where-Object { $_.Value -gt 0 } | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join ', ') `
        -Description 'Counts of hooked security-relevant API calls seen during the trace window.'))

    return $out.ToArray()
}
