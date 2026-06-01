function Test-TcpkCallsites {
<#
.SYNOPSIS
    A11. Static reference scan for dangerous .NET API patterns.

.DESCRIPTION
    Uses Data\secrets.json (callsite_patterns section) to find references to:
    weak hashes (MD5/SHA1), AES ECB mode, non-crypto RNG (System.Random),
    insecure-temp-file patterns, custom cert validation callbacks.

    Framework files are skipped entirely (System.Security.Cryptography.* is
    expected to contain these names).

.PARAMETER Path
    File or directory.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $patterns = (Get-TcpkData).callsite_patterns

    foreach ($pe in Get-TcpkPeFiles -Path $Path) {
        if (Test-TcpkIsFrameworkFile $pe.Name) { continue }
        $text = Read-TcpkAllText -Path $pe.FullName
        if (-not $text) { continue }

        foreach ($p in $patterns) {
            $hits = @()
            foreach ($pat in $p.patterns) {
                if ($text.Contains($pat)) { $hits += $pat }
            }
            if ($hits.Count -eq 0) { continue }

            New-TcpkFinding -Module 'static' -RuleId "callsites.$($p.id)" `
                -Severity $p.severity -Confidence 'Inferred' `
                -Title "$($p.title) in $($pe.Name)" `
                -File $pe.FullName -Evidence ($hits -join ', ') `
                -Cwe ([string[]]$p.cwe) `
                -Description $p.description `
                -Fix 'Decompile the method (ILSpy / dnSpy) to confirm whether this is a real bug or a safe context.'
        }
    }
}
