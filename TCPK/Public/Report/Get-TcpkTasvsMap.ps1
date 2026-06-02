function Get-TcpkTasvsMap {
<#
.SYNOPSIS
    Map TCPK findings / rule IDs to OWASP TASVS controls and the OWASP Desktop App
    Security Top 10.

.DESCRIPTION
    A pure lookup (same model as the MITRE ATT&CK mapping) that resolves a RuleId to
    its OWASP TASVS category and Desktop App Security Top 10 item, so reports and
    coverage matrices can be aligned to those standards.

    Three modes:
      - pipe in findings (or pass -Findings)  -> one row per finding with TASVS + Top 10
      - pass -RuleId                          -> the mapping for that single rule
      - no args                               -> dump the full rule-regex -> control table

.PARAMETER Findings
    TcpkFinding objects (e.g. from Invoke-TcpkAudit / Get-Tcpk*). Accepts pipeline.

.PARAMETER RuleId
    A single RuleId to resolve.

.OUTPUTS
    [pscustomobject]
#>
    [CmdletBinding(DefaultParameterSetName='Table')]
    param(
        [Parameter(ParameterSetName='Findings', ValueFromPipeline)]
        [object[]]$Findings,
        [Parameter(ParameterSetName='Rule')]
        [string]$RuleId
    )
    begin {
        function _Split($rid) {
            $all = @(Get-TcpkTasvsControl -RuleId $rid)
            [pscustomobject]@{
                Tasvs        = ($all | Where-Object { $_ -like 'TASVS-*' }) -join '; '
                DesktopTop10 = ($all | Where-Object { $_ -like 'DA*' })    -join '; '
            }
        }
    }
    process {
        if ($PSCmdlet.ParameterSetName -eq 'Findings' -and $Findings) {
            foreach ($f in $Findings) {
                $m = _Split $f.RuleId
                [pscustomobject]@{
                    RuleId       = $f.RuleId
                    Severity     = $f.Severity
                    Title        = $f.Title
                    Tasvs        = $m.Tasvs
                    DesktopTop10 = $m.DesktopTop10
                }
            }
        }
    }
    end {
        if ($PSCmdlet.ParameterSetName -eq 'Rule') {
            $m = _Split $RuleId
            [pscustomobject]@{ RuleId = $RuleId; Tasvs = $m.Tasvs; DesktopTop10 = $m.DesktopTop10 }
        }
        elseif ($PSCmdlet.ParameterSetName -eq 'Table') {
            foreach ($e in $script:TcpkTasvsMap) {
                [pscustomobject]@{
                    RulePattern  = $e.rx
                    Tasvs        = ($e.tasvs -join '; ')
                    DesktopTop10 = ($e.da -join '; ')
                }
            }
        }
    }
}
