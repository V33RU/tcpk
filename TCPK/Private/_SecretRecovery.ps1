# Secret recovery - the first real occupant of the 'Confirmed (exploit)' rung.
# When an app ships a symmetric KEY, an IV, and a CIPHERTEXT together (the classic
# thick-client anti-pattern), the encryption protects nothing: anyone with the artifact
# can recover the plaintext. This turns three separate 'Inferred' secret findings into a
# single DEMONSTRATED recovery. Read + compute only on local artifacts - no target is
# launched, no network, nothing destructive.

# Is the plaintext a plausible recovered secret (printable, non-trivial)? A wrong
# key/IV almost always fails PKCS7 unpadding (throws); this catches the rare case where
# bad padding validates but yields binary garbage.
function Test-TcpkPrintableSecret {
    param([string]$Text)
    if (-not $Text -or $Text.Length -lt 4 -or $Text.Length -gt 512) { return $false }
    foreach ($ch in $Text.ToCharArray()) {
        $c = [int][char]$ch
        if ($c -eq 9 -or $c -eq 10 -or $c -eq 13) { continue }
        if ($c -lt 32 -or $c -gt 126) { return $false }
    }
    return ($Text.Trim().Length -ge 4)
}

# Mask a recovered secret for report evidence (redaction by default; -Reveal shows it).
function Format-TcpkMaskedSecret {
    param([string]$Secret)
    $n = $Secret.Length
    if ($n -le 3) { return ('*' * $n) }
    $keep = [Math]::Min(2, [Math]::Floor($n / 4))
    return $Secret.Substring(0, $keep) + ('*' * ($n - $keep - 1)) + $Secret.Substring($n - 1, 1)
}

# All byte interpretations of a string that are VALID for a role (key: 8/16/24/32,
# iv: 8/16, cipher: any non-empty). Covers ASCII (DVTA-style), base64 and hex encodings.
function Get-TcpkByteCandidates {
    param([string]$Value, [ValidateSet('key','iv','cipher')][string]$Role)
    $lens = switch ($Role) { 'key' { @(8,16,24,32) } 'iv' { @(8,16) } 'cipher' { $null } }
    # NOTE: each candidate is wrapped in an object. A bare byte[] returned from a function
    # unrolls into individual [byte] values in PowerShell, so a single 16-byte IV would
    # reach the caller as 16 scalars. Wrapping keeps each candidate a whole byte[].
    $out  = New-Object 'System.Collections.Generic.List[object]'
    $seen = New-Object 'System.Collections.Generic.HashSet[string]'
    $tryAdd = {
        param($b)
        if (-not $b -or $b.Length -eq 0) { return }
        if ($null -ne $lens -and $lens -notcontains $b.Length) { return }
        $h = [Convert]::ToBase64String($b)
        if ($seen.Add($h)) { $out.Add([pscustomobject]@{ Bytes = $b }) }
    }
    & $tryAdd ([System.Text.Encoding]::ASCII.GetBytes($Value))
    try { & $tryAdd ([Convert]::FromBase64String($Value)) } catch { }
    if ($Value -match '^[0-9a-fA-F]+$' -and ($Value.Length % 2) -eq 0 -and $Value.Length -ge 16) {
        $hb = New-Object byte[] ($Value.Length / 2)
        for ($i = 0; $i -lt $hb.Length; $i++) { $hb[$i] = [Convert]::ToByte($Value.Substring($i * 2, 2), 16) }
        & $tryAdd $hb
    }
    return $out.ToArray()
}

# Does this string plausibly hold a ciphertext (base64 / hex decoding to a block-aligned
# blob)? Filters plain config values (hosts, names) out of the ciphertext pool cheaply.
function Test-TcpkLooksCipher {
    param([string]$Value)
    if (-not $Value) { return $false }
    $b = $null
    try { $b = [Convert]::FromBase64String($Value) } catch { }
    if (-not $b -and $Value -match '^[0-9a-fA-F]+$' -and ($Value.Length % 2) -eq 0) {
        try { $b = New-Object byte[] ($Value.Length / 2); for ($i = 0; $i -lt $b.Length; $i++) { $b[$i] = [Convert]::ToByte($Value.Substring($i * 2, 2), 16) } } catch { }
    }
    return ($b -and $b.Length -ge 8 -and (($b.Length % 8) -eq 0))
}

# The decryption engine: try AES/3DES/DES x CBC/ECB x PKCS7 for one (key,iv,cipher).
# Returns the first combination that yields printable plaintext, else Ok=$false.
function Invoke-TcpkTryDecrypt {
    param([byte[]]$Key, [byte[]]$Iv, [byte[]]$Cipher)
    $specs = @(
        @{ n = 'AES';       ks = @(16,24,32); bs = 16; make = { [System.Security.Cryptography.Aes]::Create() } },
        @{ n = 'TripleDES'; ks = @(16,24);    bs = 8;  make = { [System.Security.Cryptography.TripleDES]::Create() } },
        @{ n = 'DES';       ks = @(8);        bs = 8;  make = { [System.Security.Cryptography.DES]::Create() } }
    )
    foreach ($s in $specs) {
        if ($s.ks -notcontains $Key.Length) { continue }
        if ($Cipher.Length -eq 0 -or ($Cipher.Length % $s.bs) -ne 0) { continue }
        foreach ($mode in 'CBC','ECB') {
            if ($mode -eq 'CBC' -and $Iv.Length -ne $s.bs) { continue }
            $alg = $null
            try {
                $alg = & $s.make
                $alg.Mode    = [System.Security.Cryptography.CipherMode]::$mode
                $alg.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
                $alg.Key     = $Key
                if ($mode -eq 'CBC') { $alg.IV = $Iv }
                $dec = $alg.CreateDecryptor()
                $pt  = $dec.TransformFinalBlock($Cipher, 0, $Cipher.Length)
                $txt = [System.Text.Encoding]::UTF8.GetString($pt)
                if (Test-TcpkPrintableSecret $txt) {
                    return [pscustomobject]@{ Ok = $true; Plaintext = $txt; Algorithm = $s.n; Mode = $mode; KeyBits = ($Key.Length * 8) }
                }
            } catch { }
            finally { if ($alg) { try { $alg.Dispose() } catch { } } }
        }
    }
    return [pscustomobject]@{ Ok = $false }
}

# Collect appSettings <add key= value=> pairs from a target's .config / .xml files.
function Get-TcpkAppSettingsPairs {
    param([string]$Target)
    $pairs = New-Object 'System.Collections.Generic.List[object]'
    if (-not $Target -or -not (Test-Path -LiteralPath $Target)) { return $pairs }
    $files = if (Test-Path -LiteralPath $Target -PathType Container) {
        @(Get-ChildItem -LiteralPath $Target -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.Extension -in '.config','.xml' })
    } else { @(Get-Item -LiteralPath $Target) }
    foreach ($f in $files) {
        try {
            [xml]$x = Get-Content -LiteralPath $f.FullName -Raw -ErrorAction Stop
            foreach ($node in $x.SelectNodes('//add[@key][@value]')) {
                $v = "$($node.value)"
                if ($v) { $pairs.Add([pscustomobject]@{ Name = "$($node.key)"; Value = $v; File = $f.FullName }) }
            }
        } catch { }
    }
    return $pairs
}
