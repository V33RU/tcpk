function Test-TcpkEndpoints {
<#
.SYNOPSIS
    A09 - URL extraction + dev / qe / staging classifier.

.DESCRIPTION
    Pulls every http(s) URL out of files under the target path (UTF-8 and
    UTF-16LE views, deduplicated) and emits a HIGH finding for any URL that
    contains a non-production marker from Data\secrets.json.

.PARAMETER Path
    File or directory.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $markers = (Get-TcpkData).non_prod_markers
    $rx = [regex]::new('https?://[A-Za-z0-9./?_=&%:#@~+\-]+')

    $files = if ((Get-Item -LiteralPath $Path).PSIsContainer) {
        Get-ChildItem -LiteralPath $Path -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension -in '.dll','.exe','.json','.xml','.config','.yaml','.yml' }
    } else {
        Get-Item -LiteralPath $Path
    }

    $all = @{}
    foreach ($f in $files) {
        if (Test-TcpkIsFrameworkFile $f.Name) { continue }
        if ($f.Length -gt 32MB) { continue }
        $views = Read-TcpkStringViews -Path $f.FullName
        if (-not $views) { continue }
        foreach ($view in @($views.Utf8, $views.Utf16Le)) {
            foreach ($m in $rx.Matches($view)) {
                if (-not $all.ContainsKey($m.Value)) { $all[$m.Value] = $f.FullName }
            }
        }
    }

    foreach ($u in ($all.Keys | Sort-Object)) {
        $low = $u.ToLowerInvariant()
        $hit = $markers | Where-Object { $low.Contains($_) } | Select-Object -First 1
        if ($hit) {
            New-TcpkFinding -Module 'static' -RuleId 'endpoints.non-production' `
                -Severity 'HIGH' -Confidence 'Confirmed' `
                -Title "Non-production URL (marker='$hit')" `
                -File $all[$u] -Evidence $u `
                -Cwe @('CWE-1188','CWE-489') `
                -Fix 'Repoint to prod; add a build-time guard that fails the release on dev/qe/staging URL substrings.'
        }
    }
}
