function Test-TcpkTokenCaches {
<#
.SYNOPSIS
    D05. MSAL / ADAL / custom OAuth token cache files.

.DESCRIPTION
    Looks under -Path for files whose names match the token-cache patterns the
    common Microsoft authentication libraries use. Each find is INFO -- the
    caches are DPAPI-protected by default, but a CurrentUser-decryptable cache
    is still an exfiltration target for local-user malware.

    KNOWN GAP. This scans ONLY the supplied path. The well-known per-user
    locations that MSAL and ADAL actually write to --
    %LOCALAPPDATA%\.IdentityService\ and %USERPROFILE%\.azure\ -- are not
    scanned, because they sit outside the target install directory. Those
    caches belong to the audited application (it chose the auth library), so
    excluding them is a false negative, not a scoping win: for an MSAL-based
    thick client this check will find nothing. Restoring them requires
    attributing a cache to the target rather than reporting every cache on the
    machine. Tracked as F10.

.PARAMETER Path
    Folder to scan. Only this path is scanned; see KNOWN GAP above.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([string]$Path)

    if (-not (Assert-TcpkWindows 'Test-TcpkTokenCaches')) { return }

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
