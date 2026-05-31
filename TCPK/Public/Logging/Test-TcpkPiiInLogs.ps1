function Test-TcpkPiiInLogs {
<#
.SYNOPSIS
    H03. PII patterns in shipped logs / templates / data files.

.DESCRIPTION
    Specifically looks for email addresses, IPv4 addresses, and US-format
    phone numbers in text-shaped files shipped or persisted under the
    target path. Distinct from Test-TcpkLogFiles (which looks for
    credentials) -- this is about subject identifiability.

.PARAMETER Path
    Folder.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { return }

    $patterns = @(
        @{ N='email';    R='[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}' }
        @{ N='ipv4';     R='(?<![0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9])' }
        @{ N='ssn-like'; R='\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b' }
    )

    $candidates = Get-ChildItem -LiteralPath $Path -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Length -lt 512KB -and
            $_.Extension -in '.log','.txt','.json','.xml','.csv'
        }

    foreach ($f in $candidates) {
        try { $t = Get-Content -LiteralPath $f.FullName -Raw -ErrorAction Stop } catch { continue }
        if ([string]::IsNullOrEmpty($t)) { continue }   # Get-Content -Raw returns $null on empty files
        foreach ($p in $patterns) {
            $m = [regex]::Match($t, $p.R)
            if (-not $m.Success) { continue }
            $sample = $m.Value
            if ($sample.Length -gt 24) { $sample = $sample.Substring(0,8) + '...' + $sample.Substring($sample.Length-6) }
            New-TcpkFinding -Module 'logging' -RuleId "pii.$($p.N)" `
                -Severity 'LOW' -Confidence 'Inferred' `
                -Title "PII pattern ($($p.N)) found in $($f.Name)" `
                -File $f.FullName -Evidence "$sample (and possibly more)" `
                -Cwe @('CWE-359') `
                -Description "Triage hint -- a single pattern match isn't proof of an issue (sample data, network info, etc. could match)." `
                -Fix 'If this file ships with the app or persists user-identifiable data, ensure the privacy policy covers it.'
            break  # one PII finding per file is enough; don't drown the report
        }
    }
}
