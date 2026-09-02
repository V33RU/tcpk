function Test-TcpkDotenvSecrets {
<#
.SYNOPSIS
    A60. Shipped .env / .env.* files parsed as KEY=VALUE and flagged by KEY NAME - closes
    the low-entropy blind spot left by Test-TcpkEntropySecrets.

.DESCRIPTION
    A .env file is the single most common source of accidental production-secret exposure in
    Node / Python / Go / Rust thick clients. Test-TcpkEntropySecrets catches high-entropy
    values (long random strings), but many real credentials do NOT trip the entropy bar:

      * a URL with a password: 'DATABASE_URL=postgres://sa:pw@db01/mydb'
      * a short admin password: 'MQTT_PASSWORD=Kepler42!'
      * an SMTP password: 'SMTP_PASSWORD=OldSMTP2019'
      * a shared secret: 'JWT_SECRET=mycompany-jwt'
      * a Stripe test key: 'STRIPE_SECRET_KEY=sk_test_ABCDEFGH'  (short + all-alphabet)

    All of those are Confirmed credentials shipped with the app; entropy misses them.

    This cmdlet parses shipped .env / .env.local / .env.production files as KEY=VALUE and
    fires on any KEY whose name matches a curated sensitive-name pattern. The value
    contents are recorded MASKED (first + last char, length) so the report shows what was
    found without pasting the secret into the finding text.

    Rules:
      cfg.dotenv-secret-name           HIGH      Confirmed  A shipped .env line has a
                                                              sensitive-keyed KEY and a
                                                              non-placeholder value.
      cfg.dotenv-secret-url-embedded   CRITICAL  Confirmed  A shipped .env value is a URL
                                                              containing 'user:pass@' - the
                                                              password is in cleartext
                                                              alongside the endpoint.
      cfg.dotenv-shipped-in-release    LOW       Confirmed  A .env file is present in a
                                                              non-dev / non-test directory
                                                              (baseline: any .env under
                                                              Path is inventoried).

    Confidence is Confirmed for what the file literally says. A placeholder value
    ('changeme', 'YOUR_KEY', empty, '${VAR}', all X's / 0's) is skipped rather than
    reported as a live secret.

.PARAMETER Path
    Install directory or a single .env file.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { return }

    # Sensitive KEY-name patterns. Case-insensitive. Ordered from strongest signal to
    # weakest so the strongest match wins for a KEY that hits multiple.
    $sensitiveKeyRx = @(
        '(?i)(?:^|_)(secret|password|passwd|pwd|passphrase)(?:_|$)',
        '(?i)(?:^|_)(api[_-]?key|apikey|access[_-]?key|access[_-]?token)(?:_|$)',
        '(?i)(?:^|_)(auth[_-]?token|bearer[_-]?token|session[_-]?token|refresh[_-]?token)(?:_|$)',
        '(?i)(?:^|_)(private[_-]?key|priv[_-]?key|encryption[_-]?key|enc[_-]?key|master[_-]?key)(?:_|$)',
        '(?i)(?:^|_)(aws[_-]?secret[_-]?access[_-]?key|aws[_-]?access[_-]?key[_-]?id)',
        '(?i)(?:^|_)(gcp[_-]?service[_-]?account|google[_-]?application[_-]?credentials)',
        '(?i)(?:^|_)(github[_-]?token|gh[_-]?token|gitlab[_-]?token|bitbucket[_-]?token|npm[_-]?token|pypi[_-]?token)',
        '(?i)(?:^|_)(slack[_-]?token|discord[_-]?token|teams[_-]?token|zoom[_-]?token)',
        '(?i)(?:^|_)(stripe|twilio|sendgrid|mailgun|postmark|ses)[_-]?(secret|key|password)',
        '(?i)(?:^|_)(smtp[_-]?password|imap[_-]?password|pop3[_-]?password)',
        '(?i)(?:^|_)(mqtt[_-]?password|redis[_-]?password|mongo[_-]?password|db[_-]?password|database[_-]?password)',
        '(?i)(?:^|_)(jwt[_-]?secret|hmac[_-]?secret|signing[_-]?secret|cookie[_-]?secret)',
        '(?i)(?:^|_)(client[_-]?secret|oauth[_-]?secret|oauth[_-]?client[_-]?secret)',
        '(?i)(?:^|_)webhook[_-]?secret(?:_|$)'
    )

    # URL-form values with an embedded userinfo password are CRITICAL regardless of key.
    # RFC 3986: userinfo is 'user' or 'user:password'. We only fire on the two-part form.
    $urlWithCredRx = '(?i)^\s*[a-z][a-z0-9+.\-]{1,32}://[^/:\s]+:[^@\s]+@[^\s]+'

    # Placeholder values that are NOT live secrets. Skip case-insensitive.
    $placeholderRx = '(?i)^(?:|null|none|todo|changeme|change[_-]?me|your[_-]?\w+|xxx+|0+|-+|<[^>]+>|\$\{[^}]+\}|\$[A-Z_][A-Z0-9_]*|placeholder|example|sample|demo|test-?value)$'

    # Enumerate .env-like files. Only paths whose basename starts with '.env' (or is '.env').
    $files = @()
    $item = Get-Item -LiteralPath $Path
    if ($item.PSIsContainer) {
        try {
            $files = @(Get-ChildItem -LiteralPath $Path -Recurse -File -Force -ErrorAction SilentlyContinue |
                       Where-Object {
                           # match: .env, .env.local, .env.production, .env.example (skipped later)
                           $_.Name -match '^\.env(?:\..+)?$' -and $_.Length -lt 262144
                       })
        } catch { return }
    } elseif ($item.Name -match '^\.env(?:\..+)?$') {
        $files = @($item)
    }
    if ($files.Count -eq 0) { return }

    foreach ($f in $files) {
        # .env.example / .env.sample / .env.template - by convention placeholders only.
        # Emit the shipped-in-release INFO (they are inventory) and skip the value scan.
        $isSample = ($f.Name -match '(?i)\.(example|sample|template|dist)$')
        # inventory rule for every .env under Path
        New-TcpkFinding -Module 'discovery' -RuleId 'cfg.dotenv-shipped-in-release' `
            -Severity 'LOW' -Confidence 'Confirmed' `
            -Title "Shipped .env file present: $($f.FullName)" `
            -File $f.FullName -Evidence ("size=$($f.Length) bytes" + $(if ($isSample) { ' (sample/template)' } else { '' })) `
            -Cwe @('CWE-540','CWE-1188') `
            -Description ('A .env file is present in the install tree. Even when a specific line is not a ' +
                'live credential, .env is a common accidental-secret exposure surface in Node / Python / Go ' +
                'apps. Sample/template .env files (`.env.example`, `.env.sample`, `.env.template`) are ' +
                'lower-signal and the value-scan skips them.') `
            -Fix 'Do not ship .env in a release build. Load secrets at runtime from a per-user credential store (DPAPI, Windows Credential Manager, KeyVault). If a shipped .env is intentional (defaults + placeholders), rename it to .env.example so this rule downgrades cleanly.'
        if ($isSample) { continue }

        $lines = $null
        try { $lines = [IO.File]::ReadAllLines($f.FullName) } catch { continue }

        for ($li = 0; $li -lt $lines.Length; $li++) {
            $line = $lines[$li]
            if (-not $line) { continue }
            $trim = $line.Trim()
            if ($trim.Length -eq 0 -or $trim.StartsWith('#')) { continue }
            # Some tools use 'export KEY=VALUE'. Strip an optional leading 'export '.
            if ($trim -match '^(?i)export\s+(.*)$') { $trim = $matches[1] }
            # KEY=VALUE. KEY must be shell-safe identifier; VALUE optionally quoted.
            $m = [regex]::Match($trim, '^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$')
            if (-not $m.Success) { continue }
            $k = $m.Groups[1].Value
            $v = $m.Groups[2].Value
            # Strip a wrapping quote pair.
            if ($v -match '^"(.*)"\s*(#.*)?$') { $v = $matches[1] }
            elseif ($v -match "^'(.*)'\s*(#.*)?$") { $v = $matches[1] }
            else {
                # Unquoted: drop a trailing space + '# comment' tail.
                $v = $v -replace '\s+#.*$', ''
                $v = $v.Trim()
            }
            if ($v -match $placeholderRx) { continue }

            # ---- cfg.dotenv-secret-url-embedded ----------------------------------
            if ($v -match $urlWithCredRx) {
                # Mask the password portion; keep everything else so the operator can
                # locate the endpoint.
                $masked = ($v -replace '(://[^/:\s]+):[^@\s]+(@)', '$1:***$2')
                New-TcpkFinding -Module 'discovery' -RuleId 'cfg.dotenv-secret-url-embedded' `
                    -Severity 'CRITICAL' -Confidence 'Confirmed' `
                    -Title "$($f.Name) line $($li + 1): $k contains a URL with embedded credentials" `
                    -File $f.FullName -Evidence "$k=$masked" `
                    -Cwe @('CWE-798','CWE-319') `
                    -Description ('The shipped .env value is a URL whose authority contains a userinfo:password ' +
                        'segment. The credential is present in cleartext alongside the endpoint - every installer ' +
                        'holder has the live authentication material for this backend.') `
                    -Fix 'Split the URL into DATABASE_URL / DATABASE_USER / DATABASE_PASSWORD, and load the password from a per-user credential store at runtime. Do not ship the credential.'
                continue
            }

            # ---- cfg.dotenv-secret-name ------------------------------------------
            $keyHit = $null
            foreach ($rx in $sensitiveKeyRx) {
                if ($k -match $rx) { $keyHit = $rx; break }
            }
            if (-not $keyHit) { continue }
            # Reject values that are a variable-reference only (`$OTHER_VAR`, `${OTHER_VAR}`).
            if ($v -match '^\$\{?[A-Z_][A-Z0-9_]*\}?$') { continue }
            # Mask the value: keep length + first / last char.
            $masked = if ($v.Length -le 2) { '***' }
                      else { $v.Substring(0,1) + '***' + $v.Substring($v.Length-1,1) }
            New-TcpkFinding -Module 'discovery' -RuleId 'cfg.dotenv-secret-name' `
                -Severity 'HIGH' -Confidence 'Confirmed' `
                -Title "$($f.Name) line $($li + 1): sensitive-keyed .env value ($k)" `
                -File $f.FullName -Evidence "$k=$masked (len=$($v.Length))" `
                -Cwe @('CWE-798','CWE-540') `
                -Description ("The shipped .env line assigns a value to a KEY whose name matches a curated " +
                    "credential pattern ('$k'). Value literals that are short, low-entropy, or a plain " +
                    "English word slip past Test-TcpkEntropySecrets - this rule closes that gap by keying " +
                    "on the NAME. Value is masked in evidence.") `
                -Fix 'Remove the credential from the shipped .env. If a default is needed for a first-run flow, ship .env.example with a placeholder value and load the real secret at runtime.'
        }
    }
}
