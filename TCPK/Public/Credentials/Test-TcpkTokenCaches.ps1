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

    # ---- well-known cloud-tool token caches on the current user's profile ----------
    # Every DevOps- or cloud-console-adjacent thick client we audit ships next to at
    # least one of these caches. Distinct from the under-path scan above: these live
    # in the operator's HOME directory. Files are typically DPAPI-encrypted per user,
    # but the plaintext-JSON AWS SSO cache is not, and every entry here is a
    # local-malware exfiltration target that lives outside a normal audit's -Path.
    # NB $homeDir (not $home) - $home is a PowerShell automatic variable and
    # reassigning it inside a function shadows the built-in for anything downstream.
    $homeDir      = $env:USERPROFILE
    $appData      = $env:APPDATA
    $localAppData = $env:LOCALAPPDATA
    if (-not $homeDir) { return }

    $wellKnown = @(
        @{ RuleId = 'creds.aws-sso-cache';               Sev = 'HIGH'
           Glob   = (Join-Path $homeDir '.aws\sso\cache\*.json')
           Title  = 'AWS SSO cache tokens (plaintext JSON)'
           Cwe    = @('CWE-522','CWE-256','CWE-312')
           Desc   = ('~\.aws\sso\cache holds the unexpired accessToken and refreshToken issued by ' +
                    'aws sso login as plaintext JSON. Any process running as the user reads it and ' +
                    'inherits every AWS role the operator can assume via SSO. Not DPAPI-protected.') }
        @{ RuleId = 'creds.aws-credentials-file';        Sev = 'HIGH'
           Glob   = (Join-Path $homeDir '.aws\credentials')
           Title  = 'AWS static credentials file'
           Cwe    = @('CWE-798','CWE-522')
           Desc   = ('~\.aws\credentials stores long-lived aws_access_key_id + ' +
                    'aws_secret_access_key entries as plaintext INI. Same threat model as SSO cache ' +
                    'but the credentials do not expire on their own.') }
        @{ RuleId = 'creds.azure-cli-token-cache';       Sev = 'MEDIUM'
           Glob   = (Join-Path $appData '.azure\msal_token_cache.bin')
           Title  = 'Azure CLI MSAL token cache'
           Cwe    = @('CWE-522','CWE-256')
           Desc   = ('%APPDATA%\.azure\msal_token_cache.bin is the token cache az uses for the ' +
                    'signed-in operator. DPAPI-encrypted per user, but any process running as that ' +
                    'user calls CryptUnprotectData and reads it. Combined with token-cache.under-path ' +
                    'this is the local-token-theft surface for a company operator.') }
        @{ RuleId = 'creds.azure-cli-service-principal'; Sev = 'HIGH'
           Glob   = (Join-Path $appData '.azure\azureProfile.json')
           Title  = 'Azure CLI service-principal profile'
           Cwe    = @('CWE-522','CWE-798')
           Desc   = ('%APPDATA%\.azure\azureProfile.json can carry service-principal client ids and ' +
                    'tenant details; the paired *.pfx or secret file under the same directory is the ' +
                    'live credential. Report reader should check for a companion pem / pfx.') }
        @{ RuleId = 'creds.gcloud-adc';                   Sev = 'HIGH'
           Glob   = (Join-Path $appData 'gcloud\application_default_credentials.json')
           Title  = 'gcloud application-default credentials'
           Cwe    = @('CWE-798','CWE-522')
           Desc   = ('%APPDATA%\gcloud\application_default_credentials.json stores a service-account ' +
                    'JSON key or a refresh_token. Any process running as the user reads it and ' +
                    'authenticates to every GCP resource the account is granted.') }
        @{ RuleId = 'creds.gcloud-access-tokens-db';      Sev = 'HIGH'
           Glob   = (Join-Path $appData 'gcloud\access_tokens.db')
           Title  = 'gcloud access-token SQLite cache'
           Cwe    = @('CWE-522','CWE-256')
           Desc   = ('%APPDATA%\gcloud\access_tokens.db caches OAuth tokens for all gcloud accounts on ' +
                    'the box. SQLite plaintext.') }
        @{ RuleId = 'creds.vscode-secret-storage';        Sev = 'MEDIUM'
           Glob   = (Join-Path $appData 'Code\User\globalStorage\storage.json')
           Title  = 'VS Code secret storage'
           Cwe    = @('CWE-522','CWE-256')
           Desc   = ('%APPDATA%\Code\User\globalStorage\storage.json is a Chromium storage.json for ' +
                    'the VS Code renderer. Extensions save auth tokens (GitHub Copilot, Azure account, ' +
                    'AWS toolkit) via SecretStorage which the DPAPI-backed KeyMaster protects, but ' +
                    'the local-user threat model still holds and the file itself is worth inventorying.') }
        @{ RuleId = 'creds.cursor-secret-storage';        Sev = 'MEDIUM'
           Glob   = (Join-Path $appData 'Cursor\User\globalStorage\storage.json')
           Title  = 'Cursor secret storage'
           Cwe    = @('CWE-522','CWE-256')
           Desc   = ('%APPDATA%\Cursor\User\globalStorage\storage.json is the Cursor renderer store; ' +
                    'same shape as VS Code, worth inventorying.') }
        @{ RuleId = 'creds.gh-cli-hosts';                 Sev = 'HIGH'
           Glob   = (Join-Path $appData 'GitHub CLI\hosts.yml')
           Title  = 'GitHub CLI hosts.yml (gh auth token)'
           Cwe    = @('CWE-798','CWE-522')
           Desc   = ('%APPDATA%\GitHub CLI\hosts.yml holds the oauth_token gh uses. Plaintext YAML.') }
    )

    foreach ($e in $wellKnown) {
        # Get-ChildItem with a Glob is tolerant; a missing directory just returns nothing.
        $hits = @()
        try { $hits = @(Get-ChildItem -Path $e.Glob -File -ErrorAction SilentlyContinue) } catch { }
        foreach ($f in $hits) {
            New-TcpkFinding -Module 'creds' -RuleId $e.RuleId `
                -Severity $e.Sev -Confidence 'Confirmed' `
                -Title $e.Title `
                -File $f.FullName -Evidence "size=$($f.Length) bytes; mtime=$($f.LastWriteTime.ToString('u'))" `
                -Cwe $e.Cwe `
                -Description $e.Desc `
                -Fix 'Prefer short-lived credentials issued at process start via a broker (aws-vault, aws-sso-util-cli, gcloud impersonation, GitHub CLI device flow) rather than long-lived files on disk. If the file must persist, restrict its DACL to the operator SID only.'
        }
    }
}
