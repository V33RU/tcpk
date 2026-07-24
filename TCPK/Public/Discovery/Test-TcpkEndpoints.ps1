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

    $markers  = (Get-TcpkData).non_prod_markers
    $loopback = (Get-TcpkData).loopback_markers
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
        # Host portion only (scheme://HOST[:port]/...), so a loopback HOST is judged local
        # even if the PATH happens to contain '/dev/' etc.
        $urlHost = ''
        $hm = [regex]::Match($low, '^https?://([^/?#]+)')
        if ($hm.Success) { $urlHost = $hm.Groups[1].Value }

        # Loopback / local-bind host (localhost, 127.0.0.1, 0.0.0.0, ::1) is NORMAL for a
        # thick client -- local IPC, an embedded HTTP server, a bundled local service. It is
        # NOT a leaked non-production endpoint, so it is INFO (recon context), not a HIGH
        # finding. The real "is the local server exposed?" question is answered by
        # Test-TcpkSelfHostedServer / electron.local-server (bind address + CORS).
        $lb = $null
        foreach ($m in @($loopback)) { if ($urlHost -and $urlHost.Contains($m)) { $lb = $m; break } }
        if ($lb) {
            New-TcpkFinding -Module 'static' -RuleId 'endpoints.loopback' `
                -Severity 'INFO' -Confidence 'Confirmed' `
                -Title "Local/loopback endpoint referenced ($urlHost)" `
                -File $all[$u] -Evidence $u `
                -Cwe @('CWE-489') `
                -Description 'The app references a loopback / local-bind endpoint. This is normal for local IPC, an embedded HTTP server, or a bundled local service -- not a leaked non-production URL. Confirm it is an intended local service and not a debug-only endpoint left enabled; if it is a server, check its bind address (Test-TcpkSelfHostedServer / electron.local-server).' `
                -Fix 'No action if it is an intended local service. Ensure any embedded server binds 127.0.0.1 (not 0.0.0.0) and requires auth if it proxies anything sensitive.'
            continue
        }

        # A genuine EXTERNAL non-production endpoint (dev / qe / staging / test hostname) that
        # was shipped -- an infrastructure-disclosure / attack-surface issue.
        $hit = $markers | Where-Object { $low.Contains($_) } | Select-Object -First 1
        if ($hit) {
            New-TcpkFinding -Module 'static' -RuleId 'endpoints.non-production' `
                -Severity 'MEDIUM' -Confidence 'Confirmed' `
                -Title "Non-production URL (marker='$hit')" `
                -File $all[$u] -Evidence $u `
                -Cwe @('CWE-1188','CWE-489') `
                -Description 'A shipped URL points at a development / QA / staging host. This discloses internal infrastructure and the client may talk to a less-hardened backend. Not a direct compromise on its own -- hence Medium.' `
                -Fix 'Repoint to prod; add a build-time guard that fails the release on dev/qe/staging URL substrings.'
        }
    }
}
