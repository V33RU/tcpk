function Test-TcpkEntropySecrets {
<#
.SYNOPSIS
    A12. Entropy-based secret detection in text / config / source files.

.DESCRIPTION
    Complements the pattern-based Test-TcpkSecrets (which keys off known
    provider prefixes). This check finds *unlabelled* high-entropy tokens --
    random API keys, bearer tokens, symmetric keys, base64 secret blobs that
    no regex prefix matches.

    Scope is deliberately limited to TEXT-ish files (.json/.xml/.config/.env/
    source/...). Compiled PE binaries are excluded: they are full of naturally
    high-entropy data (relocations, resources, metadata tokens), so entropy
    scanning them produces noise -- the pattern scanner already covers binaries.

    Noise control:
      * GUIDs, repeated chars, all-digit ids, plain words are dropped.
      * HEX tokens only count when a secret-ish key name precedes them
        (bare SHA hashes / integrity digests are otherwise far too common).
      * base64 tokens need entropy >= 4.2, or >= 4.6 with no key-name context.

.PARAMETER Path
    File or directory.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $textExt = @('.json','.xml','.config','.ini','.txt','.yml','.yaml','.env',
                 '.properties','.js','.ts','.jsx','.tsx','.cs','.vb','.ps1','.psm1',
                 '.bat','.cmd','.conf','.cfg','.settings','.toml','.html','.htm','.sql')

    $files = if ((Get-Item -LiteralPath $Path).PSIsContainer) {
        Get-ChildItem -LiteralPath $Path -Recurse -File -ErrorAction SilentlyContinue
    } else { Get-Item -LiteralPath $Path }

    $rxB64 = [regex]'[A-Za-z0-9+/_\-]{24,256}={0,2}'
    $rxHex = [regex]'\b[A-Fa-f0-9]{32,256}\b'
    $rxKeyCtx = [regex]'(?i)(key|secret|token|password|pwd|apikey|api[_-]?key|auth|bearer|cred|iv|salt|connection|conn|signature|private)'
    $rxIntegrityCtx = [regex]'(?i)(sha\d|hash|integrity|checksum|thumbprint|etag|sri|digest|fingerprint|commit|revision)'

    $cap = 50
    $emitted = 0
    $seen = @{}

    foreach ($f in $files) {
        if ($emitted -ge $cap) { break }
        if ($f.Extension.ToLowerInvariant() -notin $textExt) { continue }
        if ($f.Length -gt 8MB) { continue }
        if (Test-TcpkIsFrameworkFile $f.Name) { continue }
        # NuGet/runtime manifests are full of package hashes + long identifiers, not secrets
        if ($f.Name -match '(?i)\.(deps|runtimeconfig|nuspec)\.json$') { continue }
        # Certificate-pin / public-key trust stores hold base64 SHA-256 cert FINGERPRINTS
        # (public data, not secrets) -- a known false-positive class (e.g. cert-pins.json).
        if ($f.Name -match '(?i)(cert-?pins?|pinned-?certs?|known_?hosts|trusted-?certs?)') { continue }

        $v = Read-TcpkStringViews -Path $f.FullName
        if (-not $v) { continue }
        $text = $v.Utf8

        foreach ($spec in @(
            @{ Rx = $rxB64; Kind = 'base64'; Min = 4.2 },
            @{ Rx = $rxHex; Kind = 'hex';    Min = 3.2 }
        )) {
            foreach ($m in $spec.Rx.Matches($text)) {
                if ($emitted -ge $cap) { break }
                $tok = $m.Value
                if ($tok.Length -lt 24) { continue }
                if ($tok -match '^[A-Fa-f0-9]{8}-')   { continue }   # GUID
                if ($tok -match '^(.)\1{8,}')          { continue }   # repeated char
                if ($tok -match '^[0-9]+$')            { continue }   # all-digit id
                if ($tok.StartsWith('eyJ'))            { continue }   # JWT segment -> Test-TcpkJwt handles it
                if ($tok -match '^[A-Za-z]+$')         { continue }   # pure-alpha = identifier (PascalCase class/namespace), not a key
                # real keys/tokens almost always contain a digit; a digit-free base64 run is an identifier
                if ($spec.Kind -eq 'base64' -and $tok -notmatch '[0-9]') { continue }

                $pre = if ($m.Index -gt 0) { $text.Substring([Math]::Max(0, $m.Index - 32), [Math]::Min(32, $m.Index)) } else { '' }
                $hasKeyCtx = $rxKeyCtx.IsMatch($pre)
                $isIntegrity = $rxIntegrityCtx.IsMatch($pre)
                if ($isIntegrity) { continue }                        # hash/digest, not a secret

                if ($spec.Kind -eq 'hex' -and -not $hasKeyCtx) { continue }   # bare hashes too common

                $ent = Get-TcpkShannonEntropy -Text $tok
                $min = $spec.Min
                if ($spec.Kind -eq 'base64' -and -not $hasKeyCtx) { $min = 4.6 }
                if ($ent -lt $min) { continue }

                $key = $tok.Substring(0, [Math]::Min(24, $tok.Length))
                if ($seen.ContainsKey($key)) { continue }
                $seen[$key] = $true

                $red = $tok.Substring(0,6) + '...' + $tok.Substring($tok.Length-4) + " (len=$($tok.Length), H=$ent)"
                $sev = if ($hasKeyCtx) { 'HIGH' } else { 'MEDIUM' }
                New-TcpkFinding -Module 'static' -RuleId 'entropy.high-entropy-token' `
                    -Severity $sev -Confidence 'Inferred' `
                    -Title "High-entropy $($spec.Kind) token in $($f.Name)" `
                    -File $f.FullName -Evidence $red -Cwe @('CWE-798','CWE-312') `
                    -Description 'A high-entropy string was found in a shipped text/config file. Such tokens are frequently API keys, bearer tokens, or symmetric keys that prefix-based rules miss. Confirm whether it is a live credential.' `
                    -Fix 'Do not ship secrets in files. Load them from a protected store (DPAPI / OS keychain / server-issued token) at runtime and rotate any exposed value.'
                $emitted++
            }
        }
    }
}
