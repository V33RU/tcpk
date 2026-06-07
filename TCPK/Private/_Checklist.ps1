# Thick-client security test-plan correlation.
# Maps audit findings onto the 55-case manual methodology (Data\checklist\
# thick-client-checklist.json) to produce a per-case Auto Status. The tester sets
# the final Result (PASS/FAIL) -- a NO-FINDINGS auto-status is deliberately NOT a
# pass, because this is a manual methodology.

function Get-TcpkChecklistStatus {
    [CmdletBinding()]
    param([object[]]$Findings = @())

    $path = Join-Path $script:TcpkRoot 'Data\checklist\thick-client-checklist.json'
    if (-not (Test-Path -LiteralPath $path)) { return ,@() }
    $cases = $null
    try { $cases = (Get-Content -LiteralPath $path -Raw | ConvertFrom-Json).cases } catch { return ,@() }
    if (-not $cases) { return ,@() }

    # Real findings only: drop INFO, meta, and recon/attack-surface summary rows so a
    # case isn't marked REVIEW purely on informational noise.
    $real = @($Findings | Where-Object {
        $_ -and $_.RuleId -and
        $_.Severity -ne 'INFO' -and
        $_.Module -ne 'meta' -and
        $_.RuleId -notmatch '^(attacksurface|recon)\.'
    })

    $out = New-Object 'System.Collections.Generic.List[object]'
    foreach ($c in $cases) {
        $related = @()
        if ($c.rule) {
            $rx = $c.rule
            $related = @($real | Where-Object { $_.RuleId -match "(?i)$rx" })
        }
        $status =
            if ($c.coverage -eq 'GAP')      { 'MANUAL-ONLY' }
            elseif ($related.Count -gt 0)   { 'REVIEW' }
            else                            { 'NO FINDINGS' }

        $ruleIds = (@($related | ForEach-Object { $_.RuleId } | Sort-Object -Unique) -join ', ')

        $out.Add([pscustomobject]@{
            Id         = $c.id
            Name       = $c.name
            Type       = $c.type
            Coverage   = $c.coverage
            AutoStatus = $status
            Findings   = $related.Count
            RuleIds    = $ruleIds
            Result     = ''            # tester fills PASS / FAIL
            Manual     = $c.manual
        })
    }
    # leading comma so the array is not unrolled by the caller
    return ,($out.ToArray())
}
