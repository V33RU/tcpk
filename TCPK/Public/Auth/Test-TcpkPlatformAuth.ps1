function Test-TcpkPlatformAuth {
<#
.SYNOPSIS
    A73. Windows Hello / platform authentication: whether biometric is a cryptographic
    factor or a replaceable boolean.

.DESCRIPTION
    Windows offers two different things under the same "Windows Hello" banner and they are
    not interchangeable.

    UserConsentVerifier.RequestVerificationAsync asks the platform to prompt the user and
    returns an ENUM saying what happened. Nothing cryptographic is bound to the result. An
    application that branches on that value has made biometric a true/false gate, and
    anything able to change that value walks straight past it: a patched binary, a hooked
    call, a debugger setting a return register, or an IL rewrite of the comparison. This is
    the same weakness Test-TcpkAuthFlags reports for licence booleans, with a biometric
    prompt in front of it that makes it look stronger than it is.

    KeyCredentialManager.RequestSignAsync is the real mechanism. It releases a key held in
    the TPM and returns a SIGNATURE. The verifier checks that signature, so the outcome
    cannot be faked by flipping a value: an attacker would have to produce the signature,
    which requires the hardware and the user gesture that unlocks it.

    Rules:
      platformauth.consent-boolean-gate  HIGH   RequestVerificationAsync is used and
                                                RequestSignAsync appears nowhere in the
                                                assembly. Biometric is a boolean here.
      platformauth.hello-key-used        INFO   RequestSignAsync is present. The hardware
                                                -bound shape, recorded as de-escalation
                                                evidence.
      platformauth.software-ksp          MEDIUM The assembly names the Microsoft Software
                                                Key Storage Provider while also using
                                                platform authentication, so a key the
                                                design treats as device-bound is held in
                                                software and can be copied off the machine.

    SCOPE, stated because the gap is easy to overclaim. Proving biometric is used strictly
    as a SECOND factor, or that a PIN fallback does not bypass the gate, needs control-flow
    reasoning this does not attempt. What is decided here is the shape: which of the two
    APIs the application actually calls. That is the difference between a factor and a
    flag, and it is visible in the shipping metadata.

.PARAMETER Path
    File or directory.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { return }

    foreach ($pe in Get-TcpkPeFiles -Path $Path) {
        if (Test-TcpkIsFrameworkFile $pe.Name) { continue }

        $asm = Get-TcpkCecilAssembly -DllPath $pe.FullName
        if (-not $asm) { continue }
        $mod = $null
        try { $mod = $asm.MainModule } catch { $mod = $null }
        if (-not $mod) { continue }
        $types = @()
        try { $types = @($mod.GetTypes()) } catch { $types = @() }
        if ($types.Count -eq 0) { continue }

        $consentSites = New-Object 'System.Collections.Generic.List[string]'
        $signSites    = New-Object 'System.Collections.Generic.List[string]'
        $sawSoftKsp   = $false
        $sawPlatKsp   = $false

        foreach ($t in $types) {
            $methods = @()
            try { $methods = @($t.Methods) } catch { continue }
            foreach ($m in $methods) {
                if (-not $m.HasBody) { continue }
                $instrs = $null
                try { $instrs = $m.Body.Instructions } catch { continue }
                if (-not $instrs) { continue }

                foreach ($ins in $instrs) {
                    $op = ''
                    try { $op = "$($ins.OpCode.Name)" } catch { continue }

                    if ($op -eq 'ldstr') {
                        $lit = ''
                        try { $lit = "$($ins.Operand)" } catch { $lit = '' }
                        if ($lit -eq 'Microsoft Software Key Storage Provider') { $sawSoftKsp = $true }
                        if ($lit -eq 'Microsoft Platform Crypto Provider')      { $sawPlatKsp = $true }
                        continue
                    }
                    if ($op -ne 'call' -and $op -ne 'callvirt') { continue }
                    $mref = $ins.Operand -as [Mono.Cecil.MethodReference]
                    if ($null -eq $mref) { continue }
                    $mn = ''; $dt = ''
                    try { $mn = "$($mref.Name)"; $dt = "$($mref.DeclaringType.FullName)" } catch { continue }

                    if ($dt -like '*UserConsentVerifier*' -and $mn -like 'RequestVerification*') {
                        if ($consentSites.Count -lt 6) { $consentSites.Add("$($t.FullName)::$($m.Name)") }
                    }
                    if ($dt -like '*KeyCredential*' -and ($mn -like 'RequestSign*' -or $mn -like 'OpenAsync*' -or $mn -like 'RequestCreate*')) {
                        if ($signSites.Count -lt 6) { $signSites.Add("$($t.FullName)::$($m.Name) -> $mn") }
                    }
                }
            }
        }

        if ($consentSites.Count -eq 0 -and $signSites.Count -eq 0) { continue }

        if ($consentSites.Count -gt 0 -and $signSites.Count -eq 0) {
            New-TcpkFinding -Module 'auth' -RuleId 'platformauth.consent-boolean-gate' `
                -Severity 'HIGH' -Confidence 'Confirmed (IL)' `
                -Title "$($pe.Name) gates on a biometric result value, with no key release" `
                -File $pe.FullName `
                -Evidence ("UserConsentVerifier at: " + ($consentSites -join '; ') + "; no KeyCredentialManager sign/open call in this assembly") `
                -Cwe @('CWE-603', 'CWE-287') `
                -Description ('The application prompts through UserConsentVerifier and branches on the ' +
                    'returned status. That call performs no cryptography: it reports what the user did and ' +
                    'nothing binds the answer to the device. Whoever controls the returned value controls ' +
                    'the decision, so patching the comparison, hooking the call, or setting the return ' +
                    'register under a debugger passes the check without any biometric at all. The prompt ' +
                    'makes the control look stronger than a plain boolean while offering the same ' +
                    'resistance. KeyCredentialManager, which releases a TPM-held key and returns a ' +
                    'signature that a verifier can check, is not called anywhere in this assembly.') `
                -Fix 'Use KeyCredentialManager: create a credential with RequestCreateAsync, then authenticate with RequestSignAsync over a server-supplied challenge and verify the returned signature. The decision then depends on a signature the hardware produces, not on a value the client returns. Keep UserConsentVerifier only for confirming an action the user already has rights to, never as the authentication itself.'
        }

        if ($signSites.Count -gt 0) {
            New-TcpkFinding -Module 'auth' -RuleId 'platformauth.hello-key-used' `
                -Severity 'INFO' -Confidence 'Confirmed (IL)' `
                -Title "$($pe.Name) uses hardware-bound platform credentials" `
                -File $pe.FullName -Evidence ($signSites -join '; ') `
                -Description ('The assembly calls KeyCredentialManager, which holds the credential key in ' +
                    'the TPM and returns a signature rather than a status value. This is the shape that ' +
                    'resists binary patching, so it is recorded as de-escalation evidence. It does not by ' +
                    'itself prove the signature is verified against a fresh server-supplied challenge; ' +
                    'confirm the verifier rejects a replayed one.') `
                -Fix 'No action. Confirm the signature is checked server-side over a per-attempt challenge so a captured signature cannot be replayed.'
        }

        if ($sawSoftKsp -and -not $sawPlatKsp -and ($consentSites.Count -gt 0 -or $signSites.Count -gt 0)) {
            New-TcpkFinding -Module 'auth' -RuleId 'platformauth.software-ksp' `
                -Severity 'MEDIUM' -Confidence 'Confirmed (IL)' `
                -Title "$($pe.Name) uses platform auth but names the software key provider" `
                -File $pe.FullName `
                -Evidence 'literal "Microsoft Software Key Storage Provider" present; "Microsoft Platform Crypto Provider" absent' `
                -Cwe @('CWE-522') `
                -Description ('The assembly performs platform authentication and also names the Microsoft ' +
                    'Software Key Storage Provider, which keeps private keys in a file protected by the ' +
                    'user profile rather than inside the TPM. A key held that way can be copied off the ' +
                    'machine along with the profile and used elsewhere, so a credential the design treats ' +
                    'as bound to this device is not actually bound to it. Reported only because platform ' +
                    'authentication is present in the same assembly; software key storage on its own is a ' +
                    'reasonable default and is not flagged.') `
                -Fix 'Request the Microsoft Platform Crypto Provider for credentials that are meant to identify this device, so the private key is generated in and never leaves the TPM. Keep the software provider for keys that are intended to be portable.'
        }
    }
}
