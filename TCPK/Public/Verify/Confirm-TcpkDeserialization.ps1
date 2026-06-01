function Confirm-TcpkDeserialization {
<#
.SYNOPSIS
    Phase-2 confirmation for unsafe-deserialization findings.

.DESCRIPTION
    Test-TcpkDeserialization emits Confidence 'Inferred' because a substring match
    proves a formatter type is REFERENCED, not that its Deserialize() is INVOKED.

    This cmdlet closes that gap with the Mono.Cecil bridge: for a deser.* finding it
    scans the assembly's method bodies (Get-TcpkCallSites) for an actual
    call / callvirt to <Formatter>::Deserialize. If a real call site exists the
    finding is promoted to Confidence 'Confirmed' and the call sites are written to
    the Evidence field. If only the type is referenced with no Deserialize() call,
    the finding stays 'Inferred' with a note - the prover never fabricates Confirmed.

    Requires Mono.Cecil (ships with ILSpy). Findings whose assembly cannot be read
    pass through unchanged.

.PARAMETER Finding
    One or more [TcpkFinding] objects (pipeline). Non deser.* findings pass through.

.PARAMETER Dll
    Confirm a specific assembly directly: emits call-site objects for the common
    unsafe formatters instead of promoting findings.

.OUTPUTS
    [TcpkFinding] in the Finding parameter set; [pscustomobject] call sites in the Dll set.
#>
    [CmdletBinding(DefaultParameterSetName = 'Finding')]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ParameterSetName = 'Finding')]
        [TcpkFinding[]] $Finding,

        [Parameter(Mandatory, ParameterSetName = 'Dll')]
        [string] $Dll
    )

    begin {
        # Formatter type fragments whose Deserialize() call is the proof of invocation.
        $formatters = @(
            'BinaryFormatter','NetDataContractSerializer','SoapFormatter',
            'LosFormatter','ObjectStateFormatter'
        )
    }

    process {
        if ($PSCmdlet.ParameterSetName -eq 'Dll') {
            if (-not (Test-Path -LiteralPath $Dll)) { throw "DLL not found: $Dll" }
            foreach ($ft in $formatters) {
                $sites = Get-TcpkCallSites -DllPath $Dll -TypeFragment $ft -MethodName 'Deserialize'
                foreach ($s in @($sites)) {
                    if ($s) { [pscustomobject]@{ Dll = $Dll; Formatter = $ft; In = "$($s.Type)::$($s.Method)"; Op = $s.Op; Target = $s.Target } }
                }
            }
            return
        }

        foreach ($f in $Finding) {
            if ($f.RuleId -notlike 'deser.*' -or [string]::IsNullOrEmpty($f.File) -or -not (Test-Path -LiteralPath $f.File)) {
                $f
                continue
            }

            # token after 'deser.' is the formatter type fragment, e.g. 'binaryformatter'
            $token = $f.RuleId -replace '^deser\.', ''
            $sites = Get-TcpkCallSites -DllPath $f.File -TypeFragment $token -MethodName 'Deserialize'

            if (-not $sites -and -not (Test-TcpkCecilAvailable)) {
                $f.Description = "$($f.Description) [TCPK confirm: Mono.Cecil unavailable; confidence left at $($f.Confidence).]"
                $f
                continue
            }

            if ($sites) {
                $where = (@($sites) | ForEach-Object { "$($_.Type)::$($_.Method) ($($_.Op) -> $($_.Target))" }) -join '; '
                $f.Confidence = 'Confirmed'
                $f.Evidence   = $where
                $f.Description = "$($f.Description) [TCPK confirmed via IL: Deserialize() is invoked at $where.]"
            } else {
                $f.Description = "$($f.Description) [TCPK confirm: formatter type is referenced but no Deserialize() call site was found; confidence left at $($f.Confidence).]"
            }
            $f
        }
    }
}
