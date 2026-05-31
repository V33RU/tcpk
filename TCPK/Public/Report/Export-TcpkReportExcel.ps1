function Export-TcpkReportExcel {
<#
.SYNOPSIS
    Export a multi-sheet .xlsx report: Summary, Findings, DLL Hardening (+ CVEs).

.DESCRIPTION
    Pure-PowerShell Excel workbook (no Excel install, no third-party module).
    Sheets:
      Summary        target identity + severity counts + hardening rollup
      Findings       every finding, severity-coloured
      DLL Hardening  per-DLL mitigation matrix (ASLR/DEP/CFG/HighEntropyVA/...)
      CVEs           shipped components matched to the CVE catalog (if any)

.PARAMETER Findings
    Pipeline of [TcpkFinding] objects.

.PARAMETER OutFile
    Path to the .xlsx.

.PARAMETER Hardening
    Output of Get-TcpkPeHardening (per-DLL matrix). If omitted, that sheet is empty.

.PARAMETER Profile
    Optional Get-TcpkTargetProfile object (drives the Summary sheet).

.PARAMETER CveMatches
    Optional Get-TcpkCveMatches output.

.PARAMETER Target
    Optional target string.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)][TcpkFinding[]]$Findings,
        [Parameter(Mandatory)][string]$OutFile,
        [object[]]$Hardening = @(),
        [object]$Profile = $null,
        [object[]]$CveMatches = @(),
        [string]$Target = ''
    )

    begin { $all = New-Object 'System.Collections.Generic.List[object]' }
    process { foreach ($f in $Findings) { $all.Add($f) } }
    end {
        $sevOrder = @('CRITICAL','HIGH','MEDIUM','LOW','INFO')

        # ---------- Summary sheet (Metric / Value) ----------
        $sumRows = New-Object 'System.Collections.Generic.List[object]'
        if ($Profile) {
            $sig = $Profile.Signature
            $sumRows.Add(@('Application',  "$($Profile.Name)"))
            $sumRows.Add(@('Version',      "$($Profile.Version)"))
            $sumRows.Add(@('Publisher',    "$($Profile.Publisher)"))
            $sumRows.Add(@('Architecture', "$($Profile.Architecture)"))
            $sumRows.Add(@('Type',         "$($Profile.AppType)"))
            $sumRows.Add(@('Runtime',      "$($Profile.Runtime)"))
            $sumRows.Add(@('Privilege',    "$($Profile.PrivilegeModel)"))
            $sumRows.Add(@('Signing',      "$($sig.Status)$(if ($sig.Subject){ ' -- ' + $sig.Subject })"))
        }
        $sumRows.Add(@('Target', "$Target"))
        $sumRows.Add(@('Generated (UTC)', (Get-Date).ToUniversalTime().ToString('u')))
        $sumRows.Add(@('', ''))
        $sumRows.Add(@('--- Severity ---', ''))
        foreach ($s in $sevOrder) {
            $c = ($all | Where-Object { $_.Severity -eq $s }).Count
            $sumRows.Add(@($s, "$c"))
        }
        $sumRows.Add(@('Total findings', "$($all.Count)"))
        $sumRows.Add(@('', ''))
        if ($Hardening -and @($Hardening).Count) {
            $sumRows.Add(@('--- DLL Hardening ---', ''))
            $sumRows.Add(@('DLLs analysed', "$(@($Hardening).Count)"))
            $sumRows.Add(@('HARDENED', "$(@($Hardening | Where-Object { $_.Status -eq 'HARDENED' }).Count)"))
            $sumRows.Add(@('PARTIAL',  "$(@($Hardening | Where-Object { $_.Status -eq 'PARTIAL' }).Count)"))
            $sumRows.Add(@('WEAK',     "$(@($Hardening | Where-Object { $_.Status -eq 'WEAK' }).Count)"))
        }

        # ---------- Findings sheet ----------
        $sorted = $all | Sort-Object @{ E = { Get-TcpkSeverityRank $_.Severity }; Descending = $true }, RuleId
        $findRows = foreach ($f in $sorted) {
            ,@(
                "$($f.Severity)",
                "$($f.Confidence)",
                "$(Get-TcpkCvssBand $f.Severity)",
                "$($f.Module)",
                "$($f.RuleId)",
                "$($f.Title)",
                "$($f.File)",
                "$($f.Evidence)",
                "$(if ($f.Cwe) { ($f.Cwe -join ', ') } else { '' })",
                "$(Get-TcpkAttackText $f.RuleId)",
                "$($f.Fix)",
                "$(Get-TcpkVerifyHint -RuleId $f.RuleId -File $f.File -Evidence $f.Evidence)"
            )
        }

        # ---------- DLL Hardening sheet ----------
        $hwSorted = $Hardening | Sort-Object @{ E = { switch ($_.Status) { 'WEAK' {0} 'PARTIAL' {1} default {2} } } }, DLL
        $hwRows = foreach ($h in $hwSorted) {
            ,@("$($h.DLL)", "$($h.Arch)", "$($h.ASLR)", "$($h.DEP)", "$($h.CFG)", "$($h.HighEntropyVA)", "$($h.SafeSEH)", "$($h.ForceIntegrity)", "$($h.Status)", "$($h.Missing)", "$($h.DllCharacteristics)")
        }

        $sheets = @(
            [ordered]@{ Name = 'Summary'; Headers = @('Metric','Value'); Rows = $sumRows; Widths = @(26, 90) }
            [ordered]@{ Name = 'Findings'; Headers = @('Severity','Confidence','CVSS','Module','Rule','Title','File','Evidence','CWE','ATT&CK','Fix','Verify (manual)'); Rows = @($findRows) }
            [ordered]@{ Name = 'DLL Hardening'; Headers = @('DLL','Arch','ASLR','DEP','CFG','HighEntropyVA','SafeSEH','ForceIntegrity','Status','Missing','Flags'); Rows = @($hwRows) }
        )

        # ---------- CVEs sheet (optional) ----------
        if ($CveMatches -and @($CveMatches).Count) {
            $cveRows = foreach ($c in @($CveMatches)) {
                ,@("$($c.Status)", "$($c.Severity)", "$($c.Cve)", "$($c.Package)", "$($c.ShippedVersion)", "$($c.FixedVersion)", "$($c.Area)", "$($c.Title)")
            }
            $sheets += [ordered]@{ Name = 'CVEs'; Headers = @('Status','Severity','CVE','Package','Shipped','Fixed','Area','Title'); Rows = @($cveRows) }
        }

        New-TcpkXlsx -Path $OutFile -Sheets $sheets | Out-Null
        Write-TcpkInfo "Excel written: $OutFile ($($all.Count) findings, $(@($Hardening).Count) DLLs)"
    }
}
