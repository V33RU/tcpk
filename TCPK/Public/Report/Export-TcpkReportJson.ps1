function Export-TcpkReportJson {
<#
.SYNOPSIS
    Export TCPK findings as JSON for CI / re-processing.

.PARAMETER Findings
    Pipeline of [TcpkFinding] objects.

.PARAMETER OutFile
    Path to write to. Overwrites if it exists.

.EXAMPLE
    Test-TcpkSecrets -Path .\MyApp | Export-TcpkReportJson -OutFile findings.json
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)][TcpkFinding[]]$Findings,
        [Parameter(Mandatory)][string]$OutFile,
        [object]$Profile = $null
    )

    begin { $all = New-Object 'System.Collections.Generic.List[object]' }
    process { foreach ($f in $Findings) { $all.Add($f) } }
    end {
        Confirm-TcpkParentDir -FilePath $OutFile
        # findings.json stays a bare array (stable contract for re-processing/GUI).
        $all | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $OutFile -Encoding UTF8
        Write-TcpkInfo "JSON written: $OutFile ($($all.Count) findings)"

        # Target profile (recon) is written as a sibling sidecar so the findings
        # array contract is unchanged.
        if ($Profile) {
            $profPath = Join-Path (Split-Path -Parent $OutFile) 'profile.json'
            try {
                $Profile | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $profPath -Encoding UTF8
                Write-TcpkInfo "Profile written: $profPath"
            } catch {
                Write-TcpkInfo "Profile JSON failed: $($_.Exception.Message)"
            }
        }
    }
}
