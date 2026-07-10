function Invoke-TcpkSecretRecovery {
<#
.SYNOPSIS
    Turn shipped crypto material into a DEMONSTRATED secret. When an app ships a
    symmetric key + IV + ciphertext together, decrypt it and recover the plaintext -
    upgrading three 'Inferred' findings to one 'Confirmed (exploit)'.

.DESCRIPTION
    The static secret checks are INFERRED: they see a hardcoded key, an IV, and an
    encrypted value, but do not prove the encryption is defeatable. This proves it,
    without touching a live system:

      1. Gather candidate keys / IVs / ciphertexts from the passed findings and from the
         target's .config / .xml appSettings.
      2. For every (key, IV, ciphertext) combination, try AES / TripleDES / DES x CBC /
         ECB x PKCS7.
      3. When a combination yields printable plaintext, emit a 'Confirmed (exploit)'
         finding carrying the recovered secret.

    LAB-SAFE BY CONSTRUCTION: it reads local files and does arithmetic. No process is
    launched, no network call is made, nothing is written to the target. Authorized
    targets only. The recovered secret is MASKED in the finding evidence unless -Reveal
    is passed.

.PARAMETER Findings
    Optional. TcpkFinding objects from an audit (e.g. the pipeline from Invoke-TcpkAudit).
    Their evidence values seed the key / IV / ciphertext candidate pool.

.PARAMETER Target
    Optional. Path to the app folder / config file whose appSettings are also mined for
    candidate crypto material. Pass this, the findings, or both.

.PARAMETER Reveal
    Show the full recovered secret in the finding evidence. Default masks it.

.EXAMPLE
    $f = Invoke-TcpkAudit -Target C:\App -Acknowledge
    $f | Invoke-TcpkSecretRecovery -Target C:\App -Reveal

.OUTPUTS
    [TcpkFinding] - one 'Confirmed (exploit)' finding per unique recovered secret.
#>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)][object[]]$Findings,
        [string]$Target,
        [switch]$Reveal
    )
    begin { $all = New-Object 'System.Collections.Generic.List[object]' }
    process { foreach ($f in $Findings) { if ($f) { $all.Add($f) } } }
    end {
        # 1) candidate string pool: appSettings values + secret-ish finding evidence
        $pool = @{}   # value -> source file
        foreach ($p in (Get-TcpkAppSettingsPairs -Target $Target)) { if (-not $pool.ContainsKey($p.Value)) { $pool[$p.Value] = $p.File } }
        foreach ($fnd in $all) {
            $rid = "$($fnd.RuleId)"
            if ($rid -match '(?i)crypto|secret|iv|entropy|credential|password|connection|key') {
                $v = (("$($fnd.Evidence)") -split '\s+\[', 2)[0].Trim()
                if ($v -and -not $pool.ContainsKey($v)) { $pool[$v] = "$($fnd.File)" }
            }
        }
        $strings = @($pool.Keys)
        if ($strings.Count -eq 0) { return }

        # 2) role pools (byte interpretations, length-filtered)
        $keyCands = foreach ($s in $strings) { foreach ($c in (Get-TcpkByteCandidates -Value $s -Role 'key')) { [pscustomobject]@{ s = $s; b = $c.Bytes } } }
        $ivCands  = foreach ($s in $strings) { foreach ($c in (Get-TcpkByteCandidates -Value $s -Role 'iv'))  { [pscustomobject]@{ s = $s; b = $c.Bytes } } }
        $ivCands  = @($ivCands) + [pscustomobject]@{ s = '(none)'; b = (New-Object byte[] 16) }   # lets ECB run when no IV was found
        $ctCands  = foreach ($s in $strings) { if (Test-TcpkLooksCipher $s) { foreach ($c in (Get-TcpkByteCandidates -Value $s -Role 'cipher')) { [pscustomobject]@{ s = $s; b = $c.Bytes } } } }
        if (-not @($ctCands).Count -or -not @($keyCands).Count) { return }

        # 3) brute the (key, iv, ciphertext) combinations; emit one finding per unique recovery
        $seen = New-Object 'System.Collections.Generic.HashSet[string]'
        foreach ($ct in @($ctCands)) {
            foreach ($k in @($keyCands)) {
                if ($ct.s -eq $k.s) { continue }   # a value is not its own key
                foreach ($iv in @($ivCands)) {
                    $r = Invoke-TcpkTryDecrypt -Key $k.b -Iv $iv.b -Cipher $ct.b
                    if (-not $r.Ok) { continue }
                    $dedup = "$($ct.s)|$($r.Plaintext)"
                    if (-not $seen.Add($dedup)) { continue }

                    $preview = if ($Reveal) { $r.Plaintext } else { Format-TcpkMaskedSecret $r.Plaintext }
                    $ivNote  = if ($r.Mode -eq 'CBC') { "IV '$($iv.s)'" } else { 'no IV (ECB)' }
                    $ctShort = if ($ct.s.Length -gt 40) { $ct.s.Substring(0, 40) + '...' } else { $ct.s }
                    $src     = "$($pool[$ct.s])"; if (-not $src) { $src = "$Target" }

                    New-TcpkFinding -Module 'exploit' -RuleId 'exploit.secret-recovered' `
                        -Severity 'CRITICAL' -Confidence 'Confirmed (exploit)' `
                        -Title "Recovered secret: shipped key defeats the app's own encryption" `
                        -File $src `
                        -Evidence "recovered '$preview' (len $($r.Plaintext.Length)) from ciphertext '$ctShort' via $($r.Algorithm)-$($r.KeyBits)/$($r.Mode) using the shipped key '$($k.s)' + $ivNote" `
                        -Cwe @('CWE-321','CWE-798','CWE-312') `
                        -Description ("The app ships a symmetric key, IV and ciphertext together. TCPK decrypted the ciphertext with the shipped key/IV ($($r.Algorithm)-$($r.KeyBits) $($r.Mode), PKCS7) and recovered the plaintext, DEMONSTRATING the encryption provides no protection: any holder of the binary/config recovers it. Chain: shipped artifact -> hardcoded key + IV -> decrypt -> recovered secret. Rotate the exposed secret and stop shipping the key.") `
                        -Fix 'Never ship symmetric keys/IVs in the binary or config. Protect secrets with a per-user OS keystore (DPAPI/Keychain) or a server-side secret; rotate the exposed value immediately.'
                }
            }
        }
    }
}
