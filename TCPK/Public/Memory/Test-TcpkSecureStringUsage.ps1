function Test-TcpkSecureStringUsage {
<#
.SYNOPSIS
    I03. SecureString / ProtectedData usage in first-party code, plus reversible-SecureString
    detection in shipped PowerShell scripts.

.DESCRIPTION
    Two complementary rules:

      mem.hygiene-absent            LOW      Inferred    No SecureString / ProtectedData / ProtectedMemory
                                                          reference anywhere in first-party PE text. Triage
                                                          hint for apps that handle passwords / tokens.

      creds.securestring-reversible HIGH     Confirmed   A shipped .ps1 uses ConvertTo-SecureString /
                                                          ConvertFrom-SecureString in a form that is fully
                                                          reversible for anyone who has the same script.
                                                          Three shapes fire:
                                                            a) `ConvertTo-SecureString "literal" -AsPlainText -Force`
                                                               - a plaintext credential embedded verbatim
                                                            b) `ConvertFrom-SecureString -Key @(<literal bytes>)`
                                                               - serialised ciphertext + the exact key needed
                                                                 to reverse it, side-by-side in one file
                                                            c) `ConvertTo-SecureString "<b64>" -Key @(<literal bytes>)`
                                                               - the encrypted blob + its key, together

    The reversibility rule fires only on LITERAL key / plaintext arguments. Variable arguments
    (`$plaintext`, `$key`) are skipped: the variable may be derived from Read-Host, an env-var,
    a Windows credential provider, or an OS keystore, and we cannot statically prove otherwise.
    That trade drops a class of maybe-true findings in exchange for zero false positives at HIGH.

.PARAMETER Path
    File or directory.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { return }

    # ---- mem.hygiene-absent (existing behaviour, unchanged) --------------------------
    $hygieneRefs = @('SecureString','ProtectedData','ProtectedMemory','SafeMemory','Marshal.ZeroFreeBSTR')
    $foundHygiene = $false
    foreach ($pe in Get-TcpkPeFiles -Path $Path) {
        if (Test-TcpkIsFrameworkFile $pe.Name) { continue }
        $text = Read-TcpkAllText -Path $pe.FullName
        if (-not $text) { continue }
        foreach ($r in $hygieneRefs) {
            if ($text.Contains($r)) { $foundHygiene = $true; break }
        }
        if ($foundHygiene) { break }
    }
    if (-not $foundHygiene) {
        New-TcpkFinding -Module 'memory' -RuleId 'mem.hygiene-absent' `
            -Severity 'LOW' -Confidence 'Inferred' `
            -Title 'No SecureString / ProtectedData markers in any first-party PE' `
            -Cwe @('CWE-316') `
            -Description 'Triage hint -- if this app handles passwords / tokens at runtime, those values may live in plain managed strings (GC-tracked, may persist in memory).' `
            -Fix 'For password and token handling, use SecureString and Marshal.SecureStringToGlobalAllocUnicode / ZeroFreeGlobalAllocUnicode, or wrap in ProtectedMemory blocks.'
    }

    # ---- creds.securestring-reversible ----------------------------------------------
    # Scan every shipped .ps1/.psm1 for the three reversible SecureString shapes.
    $psFiles = @()
    $item = Get-Item -LiteralPath $Path
    if ($item.PSIsContainer) {
        try {
            $psFiles = @(Get-ChildItem -LiteralPath $Path -Recurse -File -ErrorAction SilentlyContinue |
                         Where-Object { $_.Extension -in '.ps1', '.psm1', '.ps1xml' -and $_.Length -lt 524288 })
        } catch { }
    } elseif ($item.Extension -in '.ps1', '.psm1', '.ps1xml') {
        $psFiles = @($item)
    }

    # A byte-array literal in PowerShell that could plausibly be a 16+-byte crypto key.
    # Accepts:
    #   @(1,2,3,...,16)                (>=16 comma-separated ints)
    #   @(0xAA,0xBB,...,0x10)          (same, hex)
    #   [byte[]]@(...)                 (with the cast prefix)
    #   1,2,3,...,16                   (bare comma list of >=16 ints)
    #   @(1..16)  or  (1..16)          (range: span validated below)
    #   [byte[]](1..16)
    # Rejects a variable ($key), a function call (Get-Key), any expression that is not
    # a pure literal, and any comma-list with fewer than 16 elements (an 8-byte "key"
    # is not an AES key; false positives on non-crypto byte arrays live below the length
    # bar). Range literals like (1..8) are handled below with a numeric span check.
    #
    # NB '.' MUST be in the class so '@(1..16)' can match, and 'A-F' is case-insensitive
    # (the (?i) flag handles both 'ff' and 'FF' in hex).
    $byteLiteralRx = '(?ix)                                                   # verbose, case-insensitive
        (?:\[byte\[\]\])?                                                    \s*
        (?:@\s*\(\s*[0-9x\s,.A-F]+\s*\)                                       # @(...) - class now includes .
          |\(\s*\d+\s*\.\.\s*\d+\s*\)                                          # (1..N) - range, span validated
          |\d+(?:\s*,\s*\d+){15,}                                              # bare >=16 comma-separated ints
        )'

    # A helper that decides whether a matched byte-literal is actually >=16 elements.
    # The regex is deliberately loose on '@(...)' so the char class stays readable; this
    # function walks the captured expression to decide if it is real crypto-shaped.
    function _IsLongByteLiteral([string]$Expr) {
        if (-not $Expr) { return $false }
        $s = $Expr.Trim() -replace '^\[byte\[\]\]\s*',''
        # Range: (m..n)  or  @(m..n) -> require n-m+1 >= 16
        $r = [regex]::Match($s, '^\s*@?\s*\(\s*(\d+)\s*\.\.\s*(\d+)\s*\)\s*$')
        if ($r.Success) {
            $lo = [int]$r.Groups[1].Value; $hi = [int]$r.Groups[2].Value
            $span = [Math]::Abs($hi - $lo) + 1
            return ($span -ge 16)
        }
        # Comma-list: count the commas inside the outermost parens (or bare list).
        $inner = $s -replace '^@\s*\(\s*|^\s*\(\s*','' -replace '\s*\)\s*$',''
        if ($inner) {
            $count = ($inner -split ',').Count
            return ($count -ge 16)
        }
        return $false
    }

    # Path-based skip. A shipped tests/examples/fixtures folder legitimately contains
    # `ConvertTo-SecureString "test1234" -AsPlainText -Force`; firing HIGH on the vendor's
    # own test corpus is the loudest FP class the docstring's "zero FP at HIGH" claim buys.
    $skipPathRx = '(?i)[\\/](tests?|examples?|samples?|specs?|fixtures?|__tests__)[\\/]'

    foreach ($f in $psFiles) {
        if ($f.FullName -match $skipPathRx) { continue }
        $body = $null
        try { $body = [IO.File]::ReadAllText($f.FullName) } catch { continue }
        if (-not $body) { continue }
        # Fast prefilter to skip files that mention neither cmdlet at all.
        if ($body -notmatch '(?i)Convert(?:To|From)-SecureString') { continue }

        # --- Shape (a): ConvertTo-SecureString "literal" -AsPlainText -Force
        # Two direction-specific patterns (literal BEFORE flags, or flags BEFORE literal),
        # named captures so the extractor never has to guess which group holds the string.
        $aRxLitFirst  = '(?is)ConvertTo-SecureString\b[^\r\n;|]{0,200}?(?:"(?<litD>[^"\r\n]{1,200})"|''(?<litS>[^''\r\n]{1,200})'')[^\r\n;|]{0,200}?-AsPlainText[^\r\n;|]{0,200}?-Force'
        $aRxFlagFirst = '(?is)ConvertTo-SecureString\b[^\r\n;|]{0,200}?-AsPlainText[^\r\n;|]{0,200}?-Force[^\r\n;|]{0,200}?(?:"(?<litD>[^"\r\n]{1,200})"|''(?<litS>[^''\r\n]{1,200})'')'
        $aMatches = @()
        $aMatches += @([regex]::Matches($body, $aRxLitFirst))
        $aMatches += @([regex]::Matches($body, $aRxFlagFirst))
        foreach ($m in $aMatches) {
            $lit = $m.Groups['litD'].Value
            if (-not $lit) { $lit = $m.Groups['litS'].Value }
            if (-not $lit) { continue }
            $masked = if ($lit.Length -le 3) { '***' } else { $lit.Substring(0,1) + '***' + $lit.Substring($lit.Length-1,1) }
            New-TcpkFinding -Module 'memory' -RuleId 'creds.securestring-reversible' `
                -Severity 'HIGH' -Confidence 'Confirmed' `
                -Title "$($f.Name) constructs a SecureString from a hardcoded plaintext literal" `
                -File $f.FullName -Evidence "ConvertTo-SecureString $masked -AsPlainText -Force (len=$($lit.Length))" `
                -Cwe @('CWE-798','CWE-259') `
                -Description ("The shipped PowerShell script constructs a SecureString from a string LITERAL " +
                    "and passes -AsPlainText -Force. The resulting SecureString is just a wrapped copy of the " +
                    "same literal; anyone with the shipped script has the credential. SecureString is not the " +
                    "at-rest protection here, only the runtime memory representation.") `
                -Fix 'Load the plaintext from a per-user store at runtime (Read-Host -AsSecureString, Get-Credential, or Windows Credential Manager via CredMan module). Do not embed the literal.'
        }

        # --- Shape (b): ConvertFrom-SecureString -Key <literal>
        # The SecureString is serialised with a literal key; that key is then obviously
        # available to anyone with the same script who also has the ciphertext.
        $bRx = '(?is)ConvertFrom-SecureString\b[^\r\n;|]{0,300}?-Key\b\s*(' + $byteLiteralRx + ')'
        foreach ($m in [regex]::Matches($body, $bRx)) {
            $keyExpr = $m.Groups[1].Value.Trim()
            if (-not (_IsLongByteLiteral $keyExpr)) { continue }
            New-TcpkFinding -Module 'memory' -RuleId 'creds.securestring-reversible' `
                -Severity 'HIGH' -Confidence 'Confirmed' `
                -Title "$($f.Name) serialises a SecureString with a literal -Key" `
                -File $f.FullName -Evidence "ConvertFrom-SecureString -Key $($keyExpr.Substring(0, [Math]::Min(80, $keyExpr.Length)))" `
                -Cwe @('CWE-798','CWE-321') `
                -Description ("The shipped PowerShell script serialises a SecureString with -Key set to a " +
                    "byte-array literal. Anyone with the script has the key and can reverse any ciphertext " +
                    "produced by it - a hardcoded symmetric key with no per-user or per-machine binding.") `
                -Fix 'Omit -Key so ConvertFrom-SecureString uses DPAPI (per-user, non-exportable). If a cross-machine key is required, derive it per-tenant from a server secret rather than shipping the bytes.'
        }

        # --- Shape (c): ConvertTo-SecureString "<b64>" -Key <literal>
        # The already-encrypted blob and its literal key sit together in one file.
        $cRx = '(?is)ConvertTo-SecureString\b[^\r\n;|]{0,200}?("[A-Za-z0-9+/=]{16,}"|''[A-Za-z0-9+/=]{16,}'')[^\r\n;|]{0,300}?-Key\b\s*(?<keyA>' + $byteLiteralRx + ')|ConvertTo-SecureString\b[^\r\n;|]{0,300}?-Key\b\s*(?<keyB>' + $byteLiteralRx + ')[^\r\n;|]{0,200}?("[A-Za-z0-9+/=]{16,}"|''[A-Za-z0-9+/=]{16,}'')'
        foreach ($m in [regex]::Matches($body, $cRx)) {
            $keyExpr = if ($m.Groups['keyA'].Success -and $m.Groups['keyA'].Value) { $m.Groups['keyA'].Value } else { $m.Groups['keyB'].Value }
            if (-not (_IsLongByteLiteral $keyExpr)) { continue }
            New-TcpkFinding -Module 'memory' -RuleId 'creds.securestring-reversible' `
                -Severity 'HIGH' -Confidence 'Confirmed' `
                -Title "$($f.Name) ships an encrypted SecureString blob alongside its literal -Key" `
                -File $f.FullName -Evidence 'ConvertTo-SecureString "<b64-blob>" -Key <literal bytes> in same statement' `
                -Cwe @('CWE-798','CWE-321') `
                -Description ("The script imports a previously-serialised SecureString and passes -Key as a " +
                    "byte-array literal in the same statement. The ciphertext and the key are together in one " +
                    "shipped file, so the credential is a static read for anyone who has the installer.") `
                -Fix 'Store the encrypted blob per user via DPAPI (Get-Credential + Export-Clixml -Depth), not next to a shipped key. If cross-machine transport is required, use a proper key-management path (Azure Key Vault, HSM).'
        }
    }
}
