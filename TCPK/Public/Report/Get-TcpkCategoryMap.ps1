function Get-TcpkCategoryMap {
<#
.SYNOPSIS
    Map TCPK findings / rule IDs to a security category and a risk class.

.DESCRIPTION
    A pure lookup (same model as the MITRE ATT&CK mapping) that resolves a RuleId to its
    security category (area) and a risk-class item, so reports and coverage matrices can be
    aligned by topic.

    Three modes:
      - pipe in findings (or pass -Findings)  -> one row per finding with Category + risk
      - pass -RuleId                          -> the mapping for that single rule
      - no args                               -> dump the full rule-regex -> category table

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
            $all = @(Get-TcpkCategoryList -RuleId $rid)
            [pscustomobject]@{
                Category     = ($all | Where-Object { $_ -notmatch '^DA\d' }) -join '; '
                DesktopTop10 = ($all | Where-Object { $_ -match  '^DA\d' }) -join '; '
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
                    Category     = $m.Category
                    DesktopTop10 = $m.DesktopTop10
                }
            }
        }
    }
    end {
        if ($PSCmdlet.ParameterSetName -eq 'Rule') {
            $m = _Split $RuleId
            [pscustomobject]@{ RuleId = $RuleId; Category = $m.Category; DesktopTop10 = $m.DesktopTop10 }
        }
        elseif ($PSCmdlet.ParameterSetName -eq 'Table') {
            foreach ($e in $script:TcpkCategoryMap) {
                [pscustomobject]@{
                    RulePattern  = $e.rx
                    Category     = ($e.area -join '; ')
                    DesktopTop10 = ($e.da -join '; ')
                }
            }
        }
    }
}
