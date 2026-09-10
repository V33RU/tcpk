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

            # ---- crypto.rsa-pkcs1v15-encrypt ------------------------------------------
        # RSA encryption with PKCS#1 v1.5 padding enables a Bleichenbacher / adaptive
        # chosen-ciphertext oracle against any endpoint whose decryption error leaks.
        # Modern .NET defaults to OAEP; PKCS#1v1.5 has to be explicitly asked for by:
        #   * RSA.Encrypt(data, RSAEncryptionPadding.Pkcs1)
        #   * RSACryptoServiceProvider.Encrypt(data, fOAEP:false)  (managed API)
        #   * RSACryptoServiceProvider::Encrypt with a false operand at the fOAEP slot
        #     visible in IL. String scan of the shipped assembly text.
        $pkcs1Rx = @(
            '(?i)RSAEncryptionPadding\.Pkcs1\b',
            '(?is)\.Encrypt\s*\([^)]*?,\s*RSAEncryptionPadding\.Pkcs1\s*\)',
            '(?is)\.Encrypt\s*\([^)]*?,\s*(?:false|0)\s*\)\s*;.*?RSACryptoServiceProvider',
            '(?is)RSACryptoServiceProvider[^;\r\n]{0,200}\.Encrypt\s*\([^)]*?,\s*(?:false|0)\s*\)'
        )
        foreach ($rx in $pkcs1Rx) {
            $m = [regex]::Match($text, $rx)
            if ($m.Success) {
                New-TcpkFinding -Module 'static' -RuleId 'crypto.rsa-pkcs1v15-encrypt' `
                    -Severity 'MEDIUM' -Confidence 'Inferred' `
                    -Title "RSA encryption with PKCS#1 v1.5 padding in $($pe.Name)" `
                    -File $pe.FullName -Evidence ($m.Value -replace '\s+',' ').Trim() `
                    -Cwe @('CWE-780','CWE-327') `
                    -Description ('The .NET managed code asks for RSA encryption with PKCS#1 v1.5 padding ' +
                        '(RSAEncryptionPadding.Pkcs1 or the legacy fOAEP:false argument on ' +
                        'RSACryptoServiceProvider.Encrypt). PKCS#1 v1.5 encryption is Bleichenbacher-attackable ' +
                        'against any endpoint that leaks decryption-error status; every implementation is ' +
                        'expected to move to OAEP for confidentiality. Inferred because the string match ' +
                        'does not prove the call site is reached in a real flow; the IL prover in ' +
                        'Get-TcpkCryptoVerdicts is authoritative when the call graph reaches the sink.') `
                    -Fix 'Switch to RSAEncryptionPadding.OaepSHA256 (or the fOAEP:true overload on RSACryptoServiceProvider). PKCS#1 v1.5 signatures are still acceptable for signature (with a strong hash); PKCS#1 v1.5 ENCRYPTION is not.'
                break
            }
        }

        # ---- crypto.password-hash-cost-low ---------------------------------------
        # BCrypt.Net-Next / BCrypt.Net: WorkFactor / BCryptWorkFactor parameter <= 10 (2025 floor is
        # 12). Argon2 (Konscious.Security.Cryptography.Argon2) memoryCost / MemorySize <= 8192 KB.
        # Scrypt (scrypt.net) cost N <= 16384 or (r < 8 and p < 1).
        $weakCostShapes = @(
            @{ Rx='(?is)(?:BCrypt(?:Net)?[^;\r\n]{0,60}\.HashPassword\s*\([^)]*?,\s*|WorkFactor\s*=\s*|BCryptWorkFactor\s*=\s*|new\s+BCryptOpenBSD[^;\r\n]{0,60}\.HashPassword\s*\([^)]*?,\s*)(\d{1,2})\b';
               Lib='BCrypt';   MaxOk=11 }
            @{ Rx='(?is)Argon2[a-zA-Z]*[^;\r\n]{0,200}\.MemorySize\s*=\s*(\d{2,7})\b';
               Lib='Argon2';   MaxOk=15360 }   # >= 15 MB is roughly the current floor
            @{ Rx='(?is)(?:scrypt|Scrypt)\.HashPasswordAsync?[^;\r\n]{0,200}?,\s*(\d{1,7})\s*,';
               Lib='scrypt N'; MaxOk=32767 }
        )
        foreach ($shape in $weakCostShapes) {
            $m = [regex]::Match($text, $shape.Rx)
            if (-not $m.Success) { continue }
            $val = 0
            for ($gi = 1; $gi -lt $m.Groups.Count; $gi++) {
                if ($m.Groups[$gi].Success -and $m.Groups[$gi].Value -match '^\d+$') { $val = [int]$m.Groups[$gi].Value; break }
            }
            if ($val -le 0) { continue }
            if ($val -gt $shape.MaxOk) { continue }
            New-TcpkFinding -Module 'static' -RuleId 'crypto.password-hash-cost-low' `
                -Severity 'MEDIUM' -Confidence 'Inferred' `
                -Title "Password hash cost below the 2025 floor ($($shape.Lib)=$val) in $($pe.Name)" `
                -File $pe.FullName -Evidence ($m.Value -replace '\s+',' ').Trim() `
                -Cwe @('CWE-916','CWE-327') `
                -Description ("A $($shape.Lib) call in the shipped code uses a cost parameter of $val, at or " +
                    "below the widely-cited 2025 floor. That makes an offline attack on a stolen hash " +
                    "database dramatically cheaper (bcrypt cost 10 is roughly 100 hashes/s per GPU core; " +
                    "cost 12 is 25 hashes/s per GPU core, 4x slower). Inferred because the string match " +
                    "does not prove this specific call site is reached at password-setting time.") `
                -Fix ("Raise the cost to a modern floor: BCrypt WorkFactor >= 12, Argon2 MemorySize >= " +
                    "65536 (64 MB) with Iterations >= 3, scrypt N >= 131072. Re-hash existing passwords on " +
                    'next successful login.')
            break
        }

    # ---- crypto.iv-equals-key: two flavours -------------------------------------
        # a) Same variable/identifier assigned to both Key and IV within the same 512-char
        #    window: '.Key = X ... .IV = X' or '.IV = X ... .Key = X'. Catches C#, VB,
        #    PowerShell, F# and any other .NET language whose property-set syntax leaves
        #    literals in the IL text. Under AES-GCM this is nonce reuse (catastrophic);
        #    under CBC it collapses to a deterministic-encryption oracle because the same
        #    plaintext always encrypts to the same first block.
        $sameIdRx = '(?is)\.\s*Key\s*=\s*([A-Za-z_][A-Za-z0-9_.]*)\s*[;\r\n].{0,512}?\.\s*IV\s*=\s*([A-Za-z_][A-Za-z0-9_.]*)\s*[;\r\n]|\.\s*IV\s*=\s*([A-Za-z_][A-Za-z0-9_.]*)\s*[;\r\n].{0,512}?\.\s*Key\s*=\s*([A-Za-z_][A-Za-z0-9_.]*)\s*[;\r\n]'
        foreach ($m in [regex]::Matches($text, $sameIdRx)) {
            # Two branch-shapes: (Key first, IV second) captures groups 1+2, (IV first, Key
            # second) captures groups 3+4. Extract the pair whichever branch fired.
            $a = if ($m.Groups[1].Success -and $m.Groups[1].Value) { $m.Groups[1].Value } else { $m.Groups[4].Value }
            $b = if ($m.Groups[2].Success -and $m.Groups[2].Value) { $m.Groups[2].Value } else { $m.Groups[3].Value }
            if (-not $a -or -not $b) { continue }
            if ($a -ne $b) { continue }
            # Skip a common false-positive shape: '.Key = new byte[16]' + '.IV = new byte[16]'
            # would not reach here (the captured identifier would be 'new' - not a valid
            # C# identifier for a property assignment - and 'new' equals 'new' would still
            # fire). Reject 'new' explicitly.
            if ($a -in 'new','null','default') { continue }
            New-TcpkFinding -Module 'static' -RuleId 'crypto.iv-equals-key' `
                -Severity 'HIGH' -Confidence 'Confirmed' `
                -Title "IV = Key: same identifier '$a' assigned to both Key and IV in $($pe.Name)" `
                -File $pe.FullName -Evidence "Key = $a ... IV = $a (within 512 chars)" `
                -Cwe @('CWE-323','CWE-329','CWE-1204') `
                -Description ('The same identifier is assigned to both the Key and IV properties of a ' +
                    "symmetric cipher within a 512-char window. Under GCM (or any AEAD) this is nonce " +
                    'reuse and the CATASTROPHIC failure mode: the authentication key is recoverable ' +
                    "from two ciphertexts encrypted under the same (Key, IV) pair. Under CBC it collapses " +
                    "to a deterministic-encryption oracle - identical plaintext blocks always encrypt to " +
                    "identical ciphertext blocks. Confirmed for what the source text literally says; the " +
                    "IL prover in Get-TcpkCryptoVerdicts is authoritative for compiled binaries.") `
                -Fix 'Generate a fresh random IV per encryption via RandomNumberGenerator.GetBytes and store it prepended to the ciphertext. Never derive IV = Key.'
            break   # one finding per PE is enough scope info; a real .NET codebase does not repeat this
        }
        # b) Same byte-array LITERAL near both Key and IV setters. Catches the shape
        #    'aes.Key = new byte[]{1,2,...16}; aes.IV = new byte[]{1,2,...16}' with the
        #    same content on both sides.
        $litRx = '(?is)\.\s*Key\s*=\s*new\s+[Bb]yte\s*\[\s*\]\s*\{([^}]{16,200})\}.{0,512}?\.\s*IV\s*=\s*new\s+[Bb]yte\s*\[\s*\]\s*\{([^}]{16,200})\}|\.\s*IV\s*=\s*new\s+[Bb]yte\s*\[\s*\]\s*\{([^}]{16,200})\}.{0,512}?\.\s*Key\s*=\s*new\s+[Bb]yte\s*\[\s*\]\s*\{([^}]{16,200})\}'
        foreach ($m in [regex]::Matches($text, $litRx)) {
            $x = if ($m.Groups[1].Success -and $m.Groups[1].Value) { $m.Groups[1].Value } else { $m.Groups[4].Value }
            $y = if ($m.Groups[2].Success -and $m.Groups[2].Value) { $m.Groups[2].Value } else { $m.Groups[3].Value }
            if (-not $x -or -not $y) { continue }
            # Normalise whitespace before comparing.
            $xn = ($x -replace '\s+','')
            $yn = ($y -replace '\s+','')
            if ($xn -ne $yn) { continue }
            New-TcpkFinding -Module 'static' -RuleId 'crypto.iv-equals-key' `
                -Severity 'HIGH' -Confidence 'Confirmed' `
                -Title "IV = Key (literal): the same byte-array is assigned to both in $($pe.Name)" `
                -File $pe.FullName -Evidence ("bytes[0..40]=" + $xn.Substring(0, [Math]::Min(40, $xn.Length)) + '...') `
                -Cwe @('CWE-323','CWE-329','CWE-1204') `
                -Description ('The same byte-array literal is assigned to both the Key and IV of a ' +
                    'symmetric cipher within a 512-char window. Deterministic-encryption / nonce-reuse ' +
                    'primitive; see the identifier-shape rule above for the failure mode under GCM vs CBC.') `
                -Fix 'Generate a fresh random IV per encryption via RandomNumberGenerator.GetBytes and store it prepended to the ciphertext. Never derive IV from the Key.'
            break
        }

        # ---- 3) IL-PROVEN weak crypto (Confirmed): read the actual construction / constant ----
        # A source-string regex rarely survives compilation (a hardcoded key becomes a
        # newarr + InitializeArray; ECB becomes ldc.i4.2 + set_Mode). Reading the IL proves
        # the construct deterministically, so these are Confirmed (IL), not Inferred.
        foreach ($v in (Get-TcpkCryptoVerdicts -DllPath $pe.FullName)) {
            $meta = switch -Regex ($v.Kind) {
                'hardcoded-key' { @{ cwe = @('CWE-321','CWE-798'); fix = 'Derive keys per-user (DPAPI / a server secret); never bake a symmetric key into the binary. Rotate the exposed key.' } }
                'hardcoded-iv'  { @{ cwe = @('CWE-329','CWE-1204'); fix = 'Generate a fresh random IV per encryption and store it with the ciphertext; never a static / all-zero IV.' } }
                'ecb-mode'      { @{ cwe = @('CWE-327'); fix = 'Use an authenticated mode (AES-GCM), or CBC with a random IV plus an HMAC; never ECB.' } }
                'weak-hash'     { @{ cwe = @('CWE-327','CWE-328'); fix = 'Use SHA-256+ for integrity and a real password hash (PBKDF2 / Argon2 / bcrypt) for passwords; never MD5 / SHA-1.' } }
                default         { @{ cwe = @('CWE-327'); fix = 'Replace with AES-GCM (authenticated); do not use DES / 3DES / RC2 / RC4.' } }
            }
            $ev = New-Object 'System.Collections.Generic.List[string]'
            $ev.Add($v.Reason); $ev.Add('')
            $ev.Add('LOCATION (open THIS assembly in ILSpy/dnSpy):')
            $ev.Add("  Assembly : $($v.Assembly)")
            $ev.Add("  Namespace: $($v.Namespace)")
            $ev.Add("  Type     : $($v.Type)")
            $ev.Add("  Method   : $($v.Method)")
            $ev.Add("  MD token : $($v.Token)")
            $ev.Add(''); $ev.Add('IL PROOF:'); $ev.Add($v.Il)
            New-TcpkFinding -Module 'static' -RuleId ('crypto.' + $v.Kind) `
                -Severity $v.Severity -Confidence 'Confirmed (IL)' `
                -Title "Weak crypto proven from IL: $($v.Type)::$($v.Method) in $($pe.Name)" `
                -File $pe.FullName -Evidence ($ev -join "`n") -Cwe $meta.cwe `
                -Description ("$($v.Reason) This is proven from the method IL (the construct and its constant argument are in the Evidence), not a string match.") `
                -Fix $meta.fix
        }
    }
}
