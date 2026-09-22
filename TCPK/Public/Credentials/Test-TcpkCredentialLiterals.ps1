function Test-TcpkCredentialLiterals {
<#
.SYNOPSIS
    Credentials hardcoded as positional string literals in compiled code.

.DESCRIPTION
    THE GAP THIS FILLS. Secret detection normally keys on a NAME sitting next to a value:
    a config key called DBPASSWORD, a JSON field called apiKey, an assignment to a variable
    called token. That covers configuration well and covers code badly, because a credential
    passed positionally has no name anywhere near it. Entropy scoring does not cover it
    either: a short human-chosen password is low entropy by construction, which is precisely
    what makes it a weak password and what puts it under any sensible entropy threshold.

    So a call that hands a username and password straight to a network client as two bare
    string literals is invisible to both approaches, while being one of the worst forms of
    the bug: the secret is compiled into the binary, it ships to every customer, and it
    cannot be rotated without a release.

    THE SIGNAL. The name that is missing from the argument is present on the PARAMETER.
    Get-TcpkCredentialLiteralVerdicts reads the IL, finds calls to APIs whose entire purpose
    is to accept a credential, and reports the ones whose arguments are string constants.
    That does not depend on what the secret looks like, so a weak password is as detectable
    as a strong one.

    SEVERITY. HIGH, not CRITICAL. The literal reaching a credential API is proven from IL,
    but whether the credential is live is a separate question this check does not answer.
    Invoke-TcpkSecretRecovery and Test-TcpkCredentialLiveness are the cmdlets that establish
    that, and a confirmed live credential is what earns CRITICAL.

    THE VALUE IS NOT PRINTED. Evidence names the API, the declaring type, the method and the
    metadata token, and reports how many literals were involved. It does not reproduce the
    secret, because a findings file and an HTML report travel further than the binary did.

.PARAMETER Path
    File or directory.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    foreach ($pe in Get-TcpkPeFiles -Path $Path) {
        # First-party only. A bundled library calling its own credential API with a constant
        # is that library's business, and attributing it to the vendor is the misattribution
        # this filter exists to prevent.
        if (-not (Test-TcpkIsFirstParty -Name $pe.Name -SizeBytes $pe.Length -Path $pe.FullName)) { continue }
        $text = Read-TcpkAllText -Path $pe.FullName
        if (-not $text) { continue }
        if (-not $text.Contains('BSJB')) { continue }   # managed only

        $verdicts = @()
        try { $verdicts = @(Get-TcpkCredentialLiteralVerdicts -DllPath $pe.FullName) } catch { $verdicts = @() }
        if ($verdicts.Count -eq 0) { continue }

        # Group by call site so one finding covers one place in the code, rather than one
        # per literal, which would report the username and the password separately.
        foreach ($g in ($verdicts | Group-Object { "$($_.Type)::$($_.Method)" })) {
            $sites = @($g.Group)
            $first = $sites[0]
            $apis = @($sites | ForEach-Object { $_.Api } | Select-Object -Unique)
            $litTotal = 0
            foreach ($s in $sites) { $litTotal = $litTotal + [int]$s.LiteralCount }

            New-TcpkFinding -Module 'creds' -RuleId 'secrets.code-literal-credential' `
                -Severity 'HIGH' -Confidence 'Confirmed (IL)' `
                -Title "Credential passed as a hardcoded literal in $($pe.Name): $($first.Type)::$($first.Method)" `
                -File $pe.FullName `
                -Evidence ("$litTotal string literal(s) loaded as arguments to " + ($apis -join ', ') +
                           " at $($first.Type)::$($first.Method) ($($first.Token))") `
                -Cwe @('CWE-798', 'CWE-259') `
                -Description ("String constants are loaded straight into an API that takes a credential, so the " +
                    "secret is compiled into this assembly. Every copy of the application carries it, anyone who " +
                    "has the binary can read it with a decompiler, and it cannot be changed without shipping a new " +
                    "build. A credential in code is also missed by name-based and entropy-based secret scanning, " +
                    "because the argument carries no key name and a short password scores low on entropy, so this " +
                    "frequently survives review that caught the same secret in configuration. " +
                    "IL proof at $($first.Type)::$($first.Method) ($($first.Token)):`n$($first.Il)") `
                -Fix ('Remove the constant and resolve the credential at runtime from an OS credential store ' +
                    '(DPAPI / Windows Credential Manager) or a secrets service. Treat the embedded value as ' +
                    'disclosed and rotate it, since it has shipped to everyone holding this binary.')
        }
    }
}
