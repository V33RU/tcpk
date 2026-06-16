function Test-TcpkPlaintextConfigs {
<#
.SYNOPSIS
    D03. Token-shaped strings in small config files under the path.

.DESCRIPTION
    Targeted scan over *.json / *.xml / *.config / *.ini / *.txt / *.settings
    / *.user files below 512 KB. Pattern set is narrower and more
    config-shaped than Test-TcpkSecrets (which scans all binaries with
    secret regex rules). Used by the Phase 4 audit on per-user state
    directories where settings live.

.PARAMETER Path
    Folder.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { return }

    $tokenRx = @(
        @{ N='JWT';            R='eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}' },
        @{ N='AzureSharedKey'; R='AccountKey=[A-Za-z0-9+/=]{40,}' },
        @{ N='password=';      R='(?i)password\s*["'']?\s*[:=]\s*["'']?[^"''<\s>]{4,}' },
        @{ N='token=';         R='(?i)\btoken\s*["'']?\s*[:=]\s*["'']?[A-Za-z0-9._\-]{16,}' },
        @{ N='apikey=';        R='(?i)apikey\s*["'']?\s*[:=]\s*["'']?[A-Za-z0-9._\-]{16,}' },
        @{ N='Bearer';         R='Bearer\s+[A-Za-z0-9._\-]{20,}' },
        @{ N='client_secret=';  R='(?i)client_secret\s*["'']?\s*[:=]' },
        @{ N='AuthHeader';     R='(?i)"Authorization"\s*:\s*"[^"]{8,}' },
        @{ N='ConnPassword=';  R='(?i);\s*Password\s*=\s*[^;]{4,}' }
    )

    $candidateExts = @('.json','.xml','.config','.ini','.txt','.settings','.user','.dat')
    $scan = Get-ChildItem -LiteralPath $Path -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Length -lt 512KB -and $_.Extension -in $candidateExts }

    # Placeholder / template values are not real secrets -- skip them so we do not fire HIGH on
    # password=REDACTED, ${PASSWORD}, <your-key>, %TOKEN%, changeme, example, etc.
    $placeholderRx = '(?i)(redact|example|sample|dummy|placeholder|changeme|change[_-]?this|your[_-]?|xxxx+|\btodo\b|\bfixme\b|\bnull\b|\bnone\b|<[^>]*>|\$\{[^}]*\}|%[A-Za-z0-9_]+%)'
    foreach ($f in $scan) {
        try { $t = Get-Content -LiteralPath $f.FullName -Raw -ErrorAction Stop } catch { continue }
        foreach ($r in $tokenRx) {
            if ($t -match $r.R) {
                $hit = $matches[0]
                if ($hit -match $placeholderRx) { continue }   # template/placeholder, not a real secret
                if ($hit.Length -gt 30) { $hit = $hit.Substring(0,18) + '...(len=' + $hit.Length + ')' }
                New-TcpkFinding -Module 'creds' -RuleId "config.$($r.N)" `
                    -Severity 'HIGH' -Confidence 'Confirmed' `
                    -Title "Token-shaped string in $($f.Name)" `
                    -File $f.FullName -Evidence $hit `
                    -Cwe @('CWE-256','CWE-312') `
                    -Fix 'Move the secret to DPAPI / Credential Manager / a remote secret store; never check it in.'
                break   # one secret finding per file is enough; do not drown the report
            }
        }
    }
}
