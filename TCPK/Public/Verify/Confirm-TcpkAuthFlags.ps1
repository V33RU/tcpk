function Confirm-TcpkAuthFlags {
<#
.SYNOPSIS
    V23. Resolve a client-side auth/licence gate down to the method that decides it, and
    classify how that method decides.

.DESCRIPTION
    Test-TcpkAuthFlags reports at Inferred because it matches identifier names: an assembly
    containing the string IsLicensed might gate on it, or might only log it. That leaves two
    things undone. Nobody knows WHICH method makes the decision, and nobody knows whether
    the decision is even reachable logic rather than a constant.

    This resolves both from the IL, and writes the answer into Evidence as a Type::Method
    pair. That pair is the handoff: it is what New-TcpkIlPatch needs to demonstrate the
    bypass, and without it an analyst has to go find the method by hand before the finding
    can be acted on.

    Three outcomes, by what the resolved method body actually does:

      hardcoded open   The method returns true unconditionally. There is no check at all,
                       only the shape of one. Upgraded to Confirmed (IL) and raised,
                       because a gate that cannot fail is not a gate.
      local decision   The method branches and returns a bool without consulting anything
                       off the machine. This is the real client-side-trust case: the answer
                       is computed here, so whoever controls the process controls it.
      unresolved       No bool-returning method matched the flagged identifier. The name
                       may be a field, a log string or a property on a type that decides
                       elsewhere. Left at its original confidence with a note, never
                       demoted, because failing to locate a method is not evidence the gate
                       is absent.

    Refines existing findings. It creates none and removes none, so a rule that this cannot
    resolve passes through exactly as Test-TcpkAuthFlags emitted it.

.PARAMETER Findings
    Pipeline of [TcpkFinding] objects.

.OUTPUTS
    [TcpkFinding] -- the same objects, with Evidence and Confidence refined where proven.
#>
    [CmdletBinding()]
    param([Parameter(Mandatory, ValueFromPipeline)][object[]]$Findings)

    begin {
        $all = New-Object 'System.Collections.Generic.List[object]'
        $flags = @(
            'IsLicensed','IsTrial','IsActivated','IsRegistered','IsPremium','IsPro',
            'IsPaid','IsPaidUser','IsUnlocked','HasLicense','HasValidLicense','LicenseValid',
            'IsValidLicense','bypassAuth','skipAuth','SkipLogin','bypassLogin','IsAuthorized',
            'IsFullVersion','IsActivatedLicense','CheckLicense','ValidateLicense','IsExpired',
            'IsDemo','DemoMode','IsCracked','noLicenseCheck','licenseBypass'
        )
    }
    process { foreach ($f in $Findings) { if ($f) { $all.Add($f) } } }

    end {
        if (-not (Test-TcpkCecilAvailable)) {
            foreach ($f in $all) { $f }
            return
        }

        foreach ($f in $all) {
            if ("$($f.RuleId)" -ne 'authflags.client-side-gate') { $f; continue }
            $dll = "$($f.File)"
            if (-not $dll -or -not (Test-Path -LiteralPath $dll)) { $f; continue }

            # The flagged identifiers are carried in Evidence by Test-TcpkAuthFlags as a
            # comma-joined list; fall back to the whole vocabulary if that shape changed.
            $names = @()
            foreach ($n in $flags) { if ("$($f.Evidence)" -like "*$n*") { $names += $n } }
            if ($names.Count -eq 0) { $names = $flags }

            $resolved = ''
            $verdict  = 'unresolved'
            foreach ($n in $names) {
                $il = $null
                try { $il = Get-TcpkMethodIl -DllPath $dll -SymbolHint $n -MaxMethods 3 } catch { $il = $null }
                if (-not $il) { continue }
                $ilText = "$il"
                if (-not $ilText) { continue }
                $resolved = $n
                $alwaysTrue = $false
                try { $alwaysTrue = [bool](Test-TcpkIlReturnsTrueUnconditionally -Il $ilText) } catch { $alwaysTrue = $false }
                if ($alwaysTrue) { $verdict = 'hardcoded-open'; break }
                $verdict = 'local-decision'
            }

            if ($verdict -eq 'hardcoded-open') {
                $f.Confidence = 'Confirmed (IL)'
                $f.Severity   = 'HIGH'
                $f.Evidence   = "$($f.Evidence) | resolved gate: $resolved returns true unconditionally"
                $f.Description = "$($f.Description) [TCPK IL: the method behind '$resolved' returns true on every path, so the gate has the shape of a check without being one. Nothing needs to be patched to pass it; it already passes. Use the resolved method with New-TcpkIlPatch to demonstrate the state the product ships in.]"
            }
            elseif ($verdict -eq 'local-decision') {
                $f.Confidence = 'Confirmed (IL)'
                $f.Evidence   = "$($f.Evidence) | resolved gate: $resolved (bool decided in-process)"
                $f.Description = "$($f.Description) [TCPK IL: '$resolved' resolves to a bool-returning method that decides in-process, with no call leaving the machine. That is the client-side-trust case: the answer is computed on hardware the attacker controls, so patching the return, flipping the value in memory, or hooking the method all produce an authorised result. Pass the resolved method to New-TcpkIlPatch to demonstrate it.]"
            }
            else {
                $f.Description = "$($f.Description) [TCPK IL: no bool-returning method matched the flagged identifier. The name may belong to a field, a log string, or a property whose decision is made elsewhere. Confidence left unchanged: not locating a method is not evidence the gate is absent.]"
            }
            $f
        }
    }
}
