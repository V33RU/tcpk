function Test-TcpkPasswordPolicy {
<#
.SYNOPSIS
    A74. Local password and lockout policy declared in shipped configuration.

.DESCRIPTION
    A desktop application that authenticates users locally carries its policy with it. For
    the .NET Identity stack that policy is data, not code: PasswordOptions and LockoutOptions
    sit in appsettings.json inside the install tree, so the strength of the rule every user
    is held to is readable from the shipped artifact.

    Two things are worth reporting and they fail differently.

    A short minimum length is the one that matters. Offline guessing against a local store
    is limited by how fast hashes can be tried, and each missing character multiplies the
    work by the size of the alphabet. Complexity rules move that number far less than length
    does, which is why the modern guidance is to raise the floor rather than demand more
    character classes.

    No lockout is the other. Where the credential is checked locally there is no server to
    rate-limit, so an attacker with the machine gets unlimited attempts at whatever speed
    the hardware allows. Lockout is the only thing making an online guess expensive.

    Rules:
      authpolicy.password-length-low    MEDIUM  RequiredLength below 8.
      authpolicy.password-complexity-off LOW    Every Require* switch is false AND the
                                                length floor is not compensating.
      authpolicy.lockout-disabled       MEDIUM  Lockout is off, or the attempt ceiling is
                                                high enough not to bound guessing.

    Reads declared configuration only. A policy enforced in code, or by a server the client
    talks to, is not visible here and its absence from config is not reported as a finding.

.PARAMETER Path
    File or directory.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { return }

    $files = @()
    try {
        $files = @(Get-ChildItem -Path $Path -Recurse -Include 'appsettings*.json', 'identity.json', 'auth.json' `
                     -File -ErrorAction SilentlyContinue | Select-Object -First 20)
    } catch { return }
    if ($files.Count -eq 0) { return }

    foreach ($f in $files) {
        $raw = ''
        try { $raw = Get-Content -LiteralPath $f.FullName -Raw -ErrorAction Stop } catch { continue }
        if (-not $raw) { continue }
        # Only look at files that actually carry an Identity-shaped policy block.
        if ($raw -notmatch '(?i)(RequiredLength|RequireDigit|RequireNonAlphanumeric|MaxFailedAccessAttempts)') { continue }
        $j = $null
        try { $j = $raw | ConvertFrom-Json -ErrorAction Stop } catch { continue }

        # Walk to a Password / Lockout block wherever it sits; layouts vary by host.
        $pw = $null; $lo = $null
        foreach ($root in @($j.Identity, $j.IdentityOptions, $j)) {
            if ($null -eq $root) { continue }
            if ($null -eq $pw) { try { $pw = $root.Password } catch { } }
            if ($null -eq $lo) { try { $lo = $root.Lockout } catch { } }
        }

        if ($null -ne $pw) {
            $len = -1
            try { if ($null -ne $pw.RequiredLength) { $len = [int]$pw.RequiredLength } } catch { $len = -1 }

            if ($len -ge 0 -and $len -lt 8) {
                New-TcpkFinding -Module 'auth' -RuleId 'authpolicy.password-length-low' `
                    -Severity 'MEDIUM' -Confidence 'Confirmed' `
                    -Title "Minimum password length is $len in $($f.Name)" `
                    -File $f.FullName -Evidence "Password.RequiredLength = $len" `
                    -Cwe @('CWE-521') `
                    -Description ('The configured floor lets users choose a password shorter than eight ' +
                        'characters. Length is the dominant term in guessing cost: each character removed ' +
                        'divides the search space by the size of the alphabet, so a six-character password ' +
                        'falls in a small fraction of the time an eight-character one takes, and complexity ' +
                        'rules do not make up the difference. Where the credential is verified locally, the ' +
                        'attacker sets the guessing rate, which removes the only other brake.') `
                    -Fix 'Raise RequiredLength to at least 8, and prefer a longer floor with fewer character-class rules over a short one with many. Check the chosen password against a breached-password list rather than adding complexity requirements.'
            }

            $offs = New-Object 'System.Collections.Generic.List[string]'
            foreach ($k in @('RequireDigit', 'RequireLowercase', 'RequireUppercase', 'RequireNonAlphanumeric')) {
                $v = $null
                try { $v = $pw.$k } catch { $v = $null }
                if ($null -ne $v -and -not [bool]$v) { $offs.Add($k) }
            }
            # Only a complaint when length is not already carrying the weight.
            if ($offs.Count -ge 3 -and $len -ge 0 -and $len -lt 12) {
                New-TcpkFinding -Module 'auth' -RuleId 'authpolicy.password-complexity-off' `
                    -Severity 'LOW' -Confidence 'Confirmed' `
                    -Title "Password complexity rules disabled with a $len-character floor in $($f.Name)" `
                    -File $f.FullName -Evidence (($offs -join ', ') + " = false; RequiredLength = $len") `
                    -Cwe @('CWE-521') `
                    -Description ('Every character-class requirement is switched off and the length floor is ' +
                        'not high enough to compensate. Turning complexity off is a defensible modern choice ' +
                        'on its own, because it pushes users toward longer passphrases instead of ' +
                        'predictable substitutions, but it only works when the length requirement rises to ' +
                        'match. Here neither constraint is doing the work.') `
                    -Fix 'Either raise RequiredLength to 12 or more and keep complexity off, or leave the shorter floor and re-enable the class requirements. The combination of a short floor and no complexity is the weakest of the three.'
            }
        }

        if ($null -ne $lo) {
            $allowed = $null; $maxFail = -1
            try { $allowed = $lo.AllowedForNewUsers } catch { }
            try { if ($null -ne $lo.MaxFailedAccessAttempts) { $maxFail = [int]$lo.MaxFailedAccessAttempts } } catch { $maxFail = -1 }

            $off = ($null -ne $allowed -and -not [bool]$allowed)
            $loose = ($maxFail -gt 20)
            if ($off -or $loose) {
                $why = 'AllowedForNewUsers = false'
                if ($loose) { $why = "MaxFailedAccessAttempts = $maxFail" }
                New-TcpkFinding -Module 'auth' -RuleId 'authpolicy.lockout-disabled' `
                    -Severity 'MEDIUM' -Confidence 'Confirmed' `
                    -Title "Account lockout does not bound guessing in $($f.Name)" `
                    -File $f.FullName -Evidence $why `
                    -Cwe @('CWE-307') `
                    -Description ('Lockout is the control that makes an online guessing attempt expensive. ' +
                        'With it off, or with a ceiling high enough not to bite, an attacker can try ' +
                        'credentials continuously. That matters more for a desktop client than for a ' +
                        'server, because when the check runs locally there is no service in the middle ' +
                        'imposing its own rate limit and the attacker controls the machine doing the work.') `
                    -Fix 'Enable lockout for new users and set MaxFailedAccessAttempts to a small number with a lockout window. Where the verification is local, add a deliberate work factor to the password hash as well, so each attempt costs real time even without lockout.'
            }
        }
    }
}
