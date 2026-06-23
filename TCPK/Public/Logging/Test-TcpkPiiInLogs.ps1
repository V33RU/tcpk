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

    # An IPv4 candidate is only reportable PII if every octet is <=255 AND it is a real
    # routable address. Reject octet>255 (e.g. 999.999.999.999), this-net / loopback /
    # multicast+reserved, RFC1918 private, link-local, and RFC5737 / benchmark doc ranges.
    $reportableIp = {
        param($ip)
        $o = $ip.Split('.'); if ($o.Count -ne 4) { return $false }
        foreach ($x in $o) { if (($x -as [int]) -eq $null -or [int]$x -gt 255) { return $false } }
        $a = [int]$o[0]; $b = [int]$o[1]; $c = [int]$o[2]
        if ($a -eq 0 -or $a -eq 127 -or $a -ge 224)           { return $false }
        if ($a -eq 10)                                        { return $false }
        if ($a -eq 192 -and $b -eq 168)                       { return $false }
        if ($a -eq 172 -and $b -ge 16 -and $b -le 31)         { return $false }
        if ($a -eq 169 -and $b -eq 254)                       { return $false }
        if ($a -eq 192 -and $b -eq 0   -and $c -eq 2)         { return $false }
        if ($a -eq 198 -and $b -eq 51  -and $c -eq 100)       { return $false }
        if ($a -eq 203 -and $b -eq 0   -and $c -eq 113)       { return $false }
        if ($a -eq 198 -and ($b -eq 18 -or $b -eq 19))        { return $false }
        return $true
    }

    $candidates = Get-ChildItem -LiteralPath $Path -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Extension -in '.log','.txt','.json','.xml','.csv'
        }

    foreach ($f in $candidates) {
        try { $t = Get-Content -LiteralPath $f.FullName -Raw -ErrorAction Stop } catch { continue }
        if ([string]::IsNullOrEmpty($t)) { continue }   # Get-Content -Raw returns $null on empty files
        foreach ($p in $patterns) {
            $sample = $null
            if ($p.N -eq 'ipv4') {
                foreach ($mm in [regex]::Matches($t, $p.R)) { if (& $reportableIp $mm.Value) { $sample = $mm.Value; break } }
            } else {
                $m = [regex]::Match($t, $p.R)
                if ($m.Success) { $sample = $m.Value }
            }
            if (-not $sample) { continue }
            # PII value shown in full (un-redacted)
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
