function Test-TcpkTokenCaches {
<#
.SYNOPSIS
    D05. MSAL / ADAL / custom OAuth token cache files.

.DESCRIPTION
    Looks for token cache filenames the common Microsoft authentication
    libraries use at well-known per-user paths, plus any file under -Path
    whose name matches those patterns. Each find is INFO -- the caches are
    DPAPI-protected by default, but a CurrentUser-decryptable cache is still
    an exfiltration target for local-user malware.

.PARAMETER Path
    Optional. Folder to also scan in addition to the well-known paths.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([string]$Path)

    if (-not (Assert-TcpkWindows 'Test-TcpkTokenCaches')) { return }

    $wellKnown = @(
        "$env:LOCALAPPDATA\.IdentityService\msal.cache",
        "$env:LOCALAPPDATA\.IdentityService\AzureAuth.json",
        "$env:USERPROFILE\.azure\msal_token_cache.json",
        "$env:USERPROFILE\.azure\msal_token_cache.bin",
        "$env:USERPROFILE\.azure\AzureRmContext.json"
    )
    foreach ($p in $wellKnown) {
        if (Test-Path -LiteralPath $p) {
            $info = Get-Item -LiteralPath $p
            New-TcpkFinding -Module 'creds' -RuleId 'token-cache.well-known' `
                -Severity 'INFO' -Confidence 'Confirmed' `
                -Title "Auth token cache present: $($info.Name)" `
                -File $info.FullName -Evidence "size=$($info.Length) modified=$($info.LastWriteTime)" `
                -Cwe @('CWE-522','CWE-256')
        }
    }

    if ($Path -and (Test-Path -LiteralPath $Path -PathType Container)) {
        $patterns = @('msal*.cache','*token*cache*','msal*.bin','AzureRmContext*','adal*.cache')
        foreach ($pat in $patterns) {
            foreach ($f in (Get-ChildItem -LiteralPath $Path -Recurse -File -Filter $pat -ErrorAction SilentlyContinue)) {
                New-TcpkFinding -Module 'creds' -RuleId 'token-cache.under-path' `
                    -Severity 'INFO' -Confidence 'Confirmed' `
                    -Title "Auth token cache under target path: $($f.Name)" `
                    -File $f.FullName -Evidence "size=$($f.Length)" `
                    -Cwe @('CWE-522','CWE-256')
            }
        }
    }
}
