function Show-TcpkFinding {
<#
.SYNOPSIS
    Render findings in the terminal, coloured by severity, with empty fields omitted.

.DESCRIPTION
    WHY THIS EXISTS. A [TcpkFinding] has 22 properties and a typical one populates about
    half. The default Format-List prints all 22, so a perfectly healthy finding shows ten
    consecutive blank rows (Impact and Cvss are filled at report time, the attribution and
    observation contracts are opt-in, AdjustmentLog and Preconditions are empty unless the
    rule went through the precondition layer). Ten blanks in a row reads as a broken object
    whatever the reason, and a bare "MEDIUM" carries no weight next to a bare "CRITICAL"
    when both are the same colour.

    This prints only what is populated, and colours the severity so the eye lands on the
    CRITICAL first. It does not replace anything: the object is untouched, and Format-List *
    still shows every field.

    COLOUR. Applied with Write-Host, which on PowerShell 5.1 still writes to the Information
    stream, so a host capturing with 6>&1 sees identical text. Colour is dropped
    automatically outside a console host, in background jobs, and when stdout is redirected.
    Set TCPK_NO_COLOR to force it off. See TCPK\Private\_Console.ps1.

.PARAMETER Finding
    Findings to render. Accepts pipeline input, an array, or the array Invoke-TcpkAudit
    returns. Deliberately NOT mandatory: a mandatory pipeline parameter that receives zero
    objects is never bound, so PowerShell prompts for it, which would hang a clean scan that
    found nothing.

.PARAMETER MinSeverity
    Show only findings at this severity or above.

.PARAMETER All
    Show every property including the empty ones, plus Timestamp and the reasoning trail.

.EXAMPLE
    Test-TcpkSignature -Path 'C:\App' | Show-TcpkFinding

.EXAMPLE
    Invoke-TcpkAudit -Target 'C:\App' -OutDir .\out | Show-TcpkFinding -MinSeverity HIGH

.OUTPUTS
    None. Writes to the host.
#>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)]
        [AllowNull()]
        [object[]]$Finding,

        [ValidateSet('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')]
        [string]$MinSeverity = 'INFO',

        [switch]$All
    )

    begin {
        $collected = New-Object 'System.Collections.Generic.List[object]'
    }

    process {
        # Invoke-TcpkAudit and Invoke-TcpkSweep both return `, $list.ToArray()`, so the
        # pipeline delivers ONE object[] rather than N findings. @() flattens either shape.
        foreach ($f in @($Finding)) {
            if ($null -ne $f) { $collected.Add($f) }
        }
    }

    end {
        $floor = Get-TcpkSevOrder $MinSeverity
        $items = @($collected | Where-Object { (Get-TcpkSevOrder "$($_.Severity)") -ge $floor })

        if ($items.Count -eq 0) {
            Write-TcpkColourLine '  no findings at or above this severity' 'DarkGray'
            return
        }

        # Worst first. Sort-Object on a calculated rank, not on the severity string, which
        # would order them alphabetically (CRITICAL, HIGH, INFO, LOW, MEDIUM).
        $items = @($items | Sort-Object -Property @{ Expression = { Get-TcpkSevOrder "$($_.Severity)" }; Descending = $true }, RuleId)

        $tally = Get-TcpkSeverityTally -Findings $items
        Write-TcpkColourLine '' ''
        Write-TcpkColourLine ("  {0} finding(s)   {1}" -f $items.Count, $tally) 'White'
        Write-TcpkColourLine ('  ' + ('-' * 76)) 'DarkGray'

        foreach ($f in $items) {
            $sev  = "$($f.Severity)"
            $col  = Get-TcpkSeverityColour $sev
            $conf = "$($f.Confidence)"

            # One Write-Host per COMPLETE line. Splitting the header into a coloured badge
            # plus a plain remainder would emit two InformationRecords, which any host
            # capturing with 6>&1 receives as two separate log lines.
            Write-TcpkColourLine '' ''
            Write-TcpkColourLine ("  [{0}] {1}  {2}" -f $sev.PadRight(8), $conf.PadRight(19), "$($f.RuleId)") $col
            Write-TcpkColourLine ("    {0}" -f "$($f.Title)") 'White'

            $rows = New-Object 'System.Collections.Generic.List[object]'
            _TcpkAddRow $rows 'Module'   "$($f.Module)"
            # Trimmed: Resolve-TcpkFindings appends its aggregation note to whatever the rule
            # set, and on a rule that set nothing that leaves a leading space.
            _TcpkAddRow $rows 'Detail'   ("$($f.Description)").Trim()
            _TcpkAddRow $rows 'File'     "$($f.File)"
            _TcpkAddRow $rows 'Evidence' "$($f.Evidence)"

            # The default array renderer truncates to {a, b, c, d...} with no count, which
            # is worse than useless on an aggregate covering ten files.
            $aff = @($f.Affected | Where-Object { $_ })
            if ($aff.Count -gt 0) {
                if ($aff.Count -le 3 -or $All) {
                    _TcpkAddRow $rows 'Affected' ($aff -join '; ')
                } else {
                    _TcpkAddRow $rows 'Affected' ("{0} total: {1} (+{2} more, use -All)" -f $aff.Count, (($aff[0..2]) -join '; '), ($aff.Count - 3))
                }
            }

            _TcpkAddRow $rows 'CWE'  (@($f.Cwe | Where-Object { $_ }) -join ', ')
            _TcpkAddRow $rows 'Fix'  "$($f.Fix)"

            if ($All) {
                _TcpkAddRow $rows 'Impact'      "$($f.Impact)"
                _TcpkAddRow $rows 'CVSS'        "$($f.Cvss)"
                _TcpkAddRow $rows 'Attribution' "$($f.AttributionBasis)"
                _TcpkAddRow $rows 'Subject'     "$($f.Subject)"
                _TcpkAddRow $rows 'Dimension'   "$($f.Dimension)"
                _TcpkAddRow $rows 'ObsValue'    "$($f.ObsValue)"
                _TcpkAddRow $rows 'Basis'       "$($f.Basis)"
                _TcpkAddRow $rows 'Timestamp'   "$($f.Timestamp)"
            }

            foreach ($r in $rows) {
                Write-TcpkColourLine ("    {0}  {1}" -f ("$($r.Label)").PadRight(9), "$($r.Value)") 'Gray'
            }

            # The reasoning trail is the part that says why a severity moved. Always worth
            # showing when it exists, because a silently demoted finding is as misleading as
            # a false positive.
            foreach ($e in @($f.AdjustmentLog | Where-Object { $_ })) {
                Write-TcpkColourLine ("    trail      {0}" -f "$e") 'DarkGray'
            }
            foreach ($p in @($f.Preconditions | Where-Object { $_ })) {
                Write-TcpkColourLine ("    precond    {0}" -f "$p") 'DarkGray'
            }
        }
        Write-TcpkColourLine '' ''
    }
}
