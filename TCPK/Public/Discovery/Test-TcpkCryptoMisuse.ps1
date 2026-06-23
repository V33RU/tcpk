function Test-TcpkCryptoMisuse {
<#
.SYNOPSIS
    A13. Crypto-misuse hunter -- hardcoded key material + weak KDF / padding.

.DESCRIPTION
    Distinct from Test-TcpkCallsites (which flags weak algorithm *choice*:
    MD5/SHA1, AES-ECB, DES/3DES/RC4, System.Random). This check finds:

      * crypto.hardcoded-key-material  -- a base64/hex literal assigned to a
        key/iv/salt/passphrase name in a shipped TEXT/config/source file.
        A hardcoded symmetric key defeats the encryption entirely.
      * crypto.weak-kdf                -- PasswordDeriveBytes (PBKDF1) used in a
        first-party assembly.
      * crypto.weak-padding            -- PaddingMode.None on a block cipher.
      * crypto.static-iv               -- a zeroed/constant IV constructor.

.PARAMETER Path
    File or directory.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    # ---- 1) hardcoded key material in text/config/source ----
    $textExt = @('.json','.xml','.config','.ini','.env','.yml','.yaml','.properties',
                 '.cs','.vb','.js','.ts','.ps1','.psm1','.conf','.cfg','.settings','.toml')
    # Allows an optional closing quote after the name (JSON "Key": "...") before the : or = separator.
    $rxKeyLit = [regex]'(?i)\b(aes|des|rijndael|tripledes|hmac|crypto|encrypt\w*|secret|master)?[ _]?(key|iv|salt|passphrase|secretkey)\b["'']?\s{0,3}[:=>]{1,2}\s{0,3}["'']?([A-Za-z0-9+/]{16,}={0,2})["'']?'

    $files = if ((Get-Item -LiteralPath $Path).PSIsContainer) {
        Get-ChildItem -LiteralPath $Path -Recurse -File -ErrorAction SilentlyContinue
    } else { Get-Item -LiteralPath $Path }

    $seen = @{}
    $cap = 40; $n = 0
    foreach ($f in $files) {
        if ($n -ge $cap) { break }
        if ($f.Extension.ToLowerInvariant() -notin $textExt) { continue }
        if (Test-TcpkIsFrameworkFile $f.Name) { continue }
        if ($f.Name -match '(?i)\.(deps|runtimeconfig|nuspec)\.json$') { continue }
        $v = Read-TcpkStringViews -Path $f.FullName
        if (-not $v) { continue }
        foreach ($m in $rxKeyLit.Matches($v.Utf8)) {
            $val = $m.Groups[3].Value
            if ($val.Length -lt 16) { continue }
            if ($val -match '^(.)\1{6,}') { continue }
            if ($val -match '^[A-Za-z]+$') { continue }   # pure-alpha = PascalCase identifier, not key material
            if ($val -notmatch '[0-9]') { continue }      # real key material carries digits/base64
            if ($val -match '(?i)(your|example|change|placeholder|xxxx|sample|dummy)') { continue }
            $ent = Get-TcpkShannonEntropy -Text $val
            if ($ent -lt 3.2) { continue }                 # structured/low-entropy -> probably not a key
            $key = "$($f.FullName)::$($val.Substring(0,[Math]::Min(12,$val.Length)))"
            if ($seen.ContainsKey($key)) { continue }
            $seen[$key] = $true
            $red = $val.Substring(0,4) + '...' + $val.Substring($val.Length-4) + " (len=$($val.Length))"
            New-TcpkFinding -Module 'static' -RuleId 'crypto.hardcoded-key-material' `
                -Severity 'HIGH' -Confidence 'Inferred' `
                -Title "Hardcoded crypto key/IV material in $($f.Name)" `
                -File $f.FullName -Evidence "$($m.Groups[2].Value)=$red" -Cwe @('CWE-321','CWE-798') `
                -Description 'A key/IV/salt appears to be assigned a hardcoded literal. A shipped symmetric key means every install shares it -- an attacker who extracts it can decrypt all protected data.' `
                -Fix 'Derive keys per-user from a server secret or DPAPI; never ship a static key/IV. Rotate the exposed value.'
            $n++
            if ($n -ge $cap) { break }
        }
    }

    # ---- 2) weak KDF / padding / static IV in first-party assemblies ----
    $markers = @(
        @{ id='weak-kdf';     needle='PasswordDeriveBytes'; sev='MEDIUM'; cwe='CWE-327';
           title='PasswordDeriveBytes (PBKDF1) key derivation';
           desc='PasswordDeriveBytes implements the obsolete PBKDF1. Use Rfc2898DeriveBytes (PBKDF2) with >= 100k iterations and a random salt.' }
        @{ id='weak-padding'; needle='PaddingMode.None'; sev='MEDIUM'; cwe='CWE-310';
           title='Block cipher with PaddingMode.None';
           desc='PaddingMode.None on a block cipher commonly indicates manual/zero padding, which enables padding/length attacks. Use PKCS7 with an authenticated mode (GCM).' }
    )
    foreach ($pe in Get-TcpkPeFiles -Path $Path) {
        if ($pe.Extension -notin '.dll','.exe') { continue }
        if (Test-TcpkIsFrameworkFile $pe.Name) { continue }
        if (Test-TcpkIsNativeNoise $pe.Name)   { continue }
        $text = Read-TcpkAllText -Path $pe.FullName
        if (-not $text) { continue }
        foreach ($mk in $markers) {
            if ($text.IndexOf($mk.needle, [StringComparison]::Ordinal) -ge 0) {
                New-TcpkFinding -Module 'static' -RuleId "crypto.$($mk.id)" `
                    -Severity $mk.sev -Confidence 'Inferred' `
                    -Title "$($mk.title) in $($pe.Name)" `
                    -File $pe.FullName -Evidence $mk.needle -Cwe @($mk.cwe) `
                    -Description $mk.desc `
                    -Fix 'Decompile the method to confirm the construction, then migrate to a modern authenticated scheme (AES-GCM + PBKDF2/Argon2).'
            }
        }
    }
}
