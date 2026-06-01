function Confirm-TcpkTlsBypass {
<#
.SYNOPSIS
    Phase-2 confirmation for TLS certificate-validation bypass findings.

.DESCRIPTION
    The static scanners (Test-TcpkTlsBypass, Test-TcpkCallsites) flag cert-validation
    callbacks from a byte-text match, so they can only emit Confidence 'Inferred' or
    'Unverified' - the lambda body cannot be read from bytes alone.

    This cmdlet closes that gap deterministically. For a cert-validation finding it
    reads the actual callback method's IL via the Mono.Cecil bridge (Get-TcpkMethodIl,
    matched by the SslPolicyErrors parameter signature so a compiler-generated lambda
    name does not matter) and renders a bytecode verdict with
    Test-TcpkIlReturnsTrueUnconditionally.

    A finding is promoted to Confidence 'Confirmed' (Severity CRITICAL) ONLY when the
    callback body provably cannot return false: it loads the constant 1 (true) and
    returns, with no conditional branch and no comparison opcode. The proof - the IL
    trace - is written to the Evidence field. Any decision logic in the body leaves
    the finding at its original confidence for human review; the prover never
    fabricates a Confirmed verdict.

    Requires Mono.Cecil (ships with ILSpy; the same dependency Get-TcpkMethodIl uses).
    If Cecil or the callback method is unavailable, the finding passes through
    unchanged with a note.

.PARAMETER Finding
    One or more [TcpkFinding] objects (accepts pipeline). Findings whose RuleId is not
    a cert-validation rule, or whose File is missing, pass through untouched.

.PARAMETER Dll
    Confirm a specific assembly directly and emit a verdict object per cert callback
    found, instead of promoting findings. Useful for ad-hoc verification.

.EXAMPLE
    Test-TcpkTlsBypass -Path .\App | Confirm-TcpkTlsBypass

    Re-runs the TLS findings through IL confirmation; unconditional `=> true`
    callbacks come out Confidence 'Confirmed', customized validation stays 'Inferred'.

.EXAMPLE
    Confirm-TcpkTlsBypass -Dll .\App\Net.dll

    Emits { Dll, Type, Method, Verdict, Reason, Il } for each cert callback in Net.dll.

.OUTPUTS
    [TcpkFinding] in the Finding parameter set; [pscustomobject] verdicts in the Dll set.
#>
    [CmdletBinding(DefaultParameterSetName = 'Finding')]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ParameterSetName = 'Finding')]
        [TcpkFinding[]] $Finding,

        [Parameter(Mandatory, ParameterSetName = 'Dll')]
        [string] $Dll
    )

    begin {
        # RuleIds that point at a TLS cert-validation callback.
        $certRulePrefixes = @('tls-bypass.')
        $certRuleExact    = @('callsites.disabled-cert-validation')
    }

    process {
        if ($PSCmdlet.ParameterSetName -eq 'Dll') {
            if (-not (Test-Path -LiteralPath $Dll)) { throw "DLL not found: $Dll" }
            $methods = Get-TcpkCertCallbackIl -DllPath $Dll
            if (-not $methods) {
                Write-Warning "Confirm-TcpkTlsBypass: no cert-callback IL found in '$Dll' (Mono.Cecil unavailable, or no SslPolicyErrors callback present)."
                return
            }
            foreach ($m in $methods) {
                $v = Test-TcpkIlReturnsTrueUnconditionally -Il $m.Il
                [pscustomobject]@{
                    Dll     = $Dll
                    Type    = $m.Type
                    Method  = $m.Method
                    Verdict = $v.Verdict
                    Reason  = $v.Reason
                    Il      = $m.Il
                }
            }
            return
        }

        foreach ($f in $Finding) {
            $isCertRule =
                ($certRuleExact -contains $f.RuleId) -or
                ($certRulePrefixes | Where-Object { $f.RuleId -like "$_*" })

            if (-not $isCertRule -or [string]::IsNullOrEmpty($f.File) -or -not (Test-Path -LiteralPath $f.File)) {
                $f
                continue
            }

            $methods = Get-TcpkCertCallbackIl -DllPath $f.File
            if (-not $methods) {
                $f.Description = "$($f.Description) [TCPK confirm: Mono.Cecil unavailable or no SslPolicyErrors callback located in this assembly; confidence left at $($f.Confidence).]"
                $f
                continue
            }

            $proof = $null
            foreach ($m in $methods) {
                $v = Test-TcpkIlReturnsTrueUnconditionally -Il $m.Il
                if ($v.Verdict -eq 'unconditional-true') { $proof = [pscustomobject]@{ M = $m; V = $v }; break }
            }

            if ($proof) {
                $f.Confidence  = 'Confirmed'
                $f.Severity    = 'CRITICAL'
                $f.Evidence    = $proof.M.Il
                $f.Description  = "$($f.Description) [TCPK confirmed via IL: $($proof.M.Type)::$($proof.M.Method) $($proof.V.Reason)]"
            } else {
                $f.Description  = "$($f.Description) [TCPK confirm: callback body has decision logic (not an unconditional bypass); confidence left at $($f.Confidence) for human review.]"
            }
            $f
        }
    }
}
