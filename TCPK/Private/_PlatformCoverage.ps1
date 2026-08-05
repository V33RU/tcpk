# CAP6 - Platform-aware coverage derivation.
#
# A rule that hunts for a fixed list of filenames is blind everywhere that list
# does not point.  Coverage must be derived from the platform model, not
# hardcoded.
#
# This service provides:
#   - A store catalog: for each platform class, which stores exist, which are
#     protected by the platform, and which are not.
#   - Get-TcpkDerivedSearchSurface: returns the FULL set of stores a rule must
#     inspect for a given platform and store class.  Un-protected stores must
#     be inspected with AT LEAST the same diligence as protected ones.
#   - Coverage tracking: every skip or exclusion is logged.  An exclusion that
#     removes a store capable of holding secrets must be justified, not assumed.
#   - Assert-TcpkCoverageComplete: for every unprotected store that was not
#     inspected, emit an UNTESTED precondition (CAP5) so the finding set records
#     the gap rather than implying a clean surface.
#
# A rule that reports on a protected store must ALSO have inspected the
# corresponding unprotected stores for the same class of data, or declare UNTESTED.
# The generalisation: adding a new runtime extends every rule's reach automatically.

$script:TcpkStoreCatalog = [ordered]@{
    # Each entry: platform-class -> store-class -> @( store-descriptor, ... )
    # store-descriptor fields:
    #   Name        - identifier used in exclusion/coverage logs
    #   Protected   - bool: platform provides encryption/access-control for this store
    #   ProtectedBy - description of the protection mechanism (for report transparency)
    #   RelPaths    - paths relative to the per-profile data directory (EMPTY = no FS path; API-only)
    #   Notes       - extra context for report or operator

    'electron' = @{
        'credential' = @(
            [pscustomobject]@{ Name='os-crypt-cookies';    Protected=$true;  ProtectedBy='DPAPI (Windows) / Keychain (macOS) via os_crypt'; RelPaths=@('Cookies','Network\Cookies'); Notes='Session/auth cookies; DPAPI-encrypted values have v10/v11 prefix' }
            [pscustomobject]@{ Name='os-crypt-local-state';Protected=$true;  ProtectedBy='DPAPI via os_crypt'; RelPaths=@('Local State'); Notes='Contains the DPAPI-wrapped AES key used for v10/v11 cookie encryption' }
            [pscustomobject]@{ Name='local-storage-leveldb';Protected=$false; ProtectedBy='none'; RelPaths=@('Local Storage\leveldb'); Notes='Unencrypted key-value store; tokens and credentials land here in many Electron apps' }
            [pscustomobject]@{ Name='session-storage';      Protected=$false; ProtectedBy='none'; RelPaths=@('Session Storage'); Notes='Chromium session storage; not encrypted' }
            [pscustomobject]@{ Name='indexeddb';            Protected=$false; ProtectedBy='none'; RelPaths=@('IndexedDB'); Notes='IndexedDB blobs; not encrypted' }
            [pscustomobject]@{ Name='extension-state';      Protected=$false; ProtectedBy='none'; RelPaths=@('Extension State'); Notes='Extension key-value store; not encrypted' }
            [pscustomobject]@{ Name='web-data';             Protected=$false; ProtectedBy='none'; RelPaths=@('Web Data'); Notes='Chromium Web Data SQLite: autofill, payment methods' }
        )
        'cookie' = @(
            [pscustomobject]@{ Name='os-crypt-cookies';    Protected=$true;  ProtectedBy='DPAPI / Keychain'; RelPaths=@('Cookies','Network\Cookies'); Notes='' }
            [pscustomobject]@{ Name='local-storage-leveldb';Protected=$false; ProtectedBy='none'; RelPaths=@('Local Storage\leveldb'); Notes='Apps that mirror session state into localStorage' }
        )
        'config' = @(
            [pscustomobject]@{ Name='local-state';         Protected=$false; ProtectedBy='none'; RelPaths=@('Local State'); Notes='Plain JSON; DPAPI key blob is base64 in this file' }
            [pscustomobject]@{ Name='preferences';         Protected=$false; ProtectedBy='none'; RelPaths=@('Preferences'); Notes='Electron app preferences; may contain API endpoints and tokens' }
        )
    }

    'dotnet' = @{
        'credential' = @(
            [pscustomobject]@{ Name='credential-manager';  Protected=$true;  ProtectedBy='DPAPI via CredMan API'; RelPaths=@(); Notes='Windows Credential Manager; only accessible via API, no filesystem path' }
            [pscustomobject]@{ Name='dpapi-file-blobs';    Protected=$true;  ProtectedBy='DPAPI'; RelPaths=@('%LOCALAPPDATA%','%APPDATA%'); Notes='Files containing DPAPI-encrypted blobs; may be located anywhere in profile' }
            [pscustomobject]@{ Name='appdata-plaintext';   Protected=$false; ProtectedBy='none'; RelPaths=@('%APPDATA%','%LOCALAPPDATA%','%PROGRAMDATA%'); Notes='Unprotected plaintext config/cache files under profile directories' }
            [pscustomobject]@{ Name='isolated-storage';    Protected=$false; ProtectedBy='none'; RelPaths=@('%LOCALAPPDATA%\IsolatedStorage'); Notes='.NET IsolatedStorage: not encrypted; often overlooked' }
        )
        'config' = @(
            [pscustomobject]@{ Name='appconfig';           Protected=$false; ProtectedBy='none'; RelPaths=@(); Notes='app.config / appsettings.json; often contains connection strings and API keys' }
            [pscustomobject]@{ Name='user-secrets-file';   Protected=$false; ProtectedBy='NTFS ACL (user only)'; RelPaths=@('%APPDATA%\Microsoft\UserSecrets'); Notes='ASP.NET user secrets; ACL-protected but not encrypted' }
        )
    }

    'native-win32' = @{
        'credential' = @(
            [pscustomobject]@{ Name='credential-manager';  Protected=$true;  ProtectedBy='DPAPI via CredMan API'; RelPaths=@(); Notes='' }
            [pscustomobject]@{ Name='registry-dpapi';      Protected=$true;  ProtectedBy='DPAPI'; RelPaths=@(); Notes='Registry values encrypted with DPAPI; HKCU or HKLM' }
            [pscustomobject]@{ Name='registry-plaintext';  Protected=$false; ProtectedBy='none'; RelPaths=@(); Notes='Registry values stored in plain REG_SZ or REG_BINARY without DPAPI' }
            [pscustomobject]@{ Name='appdata-plaintext';   Protected=$false; ProtectedBy='none'; RelPaths=@('%APPDATA%','%LOCALAPPDATA%','%PROGRAMDATA%'); Notes='' }
            [pscustomobject]@{ Name='temp-files';          Protected=$false; ProtectedBy='none'; RelPaths=@('%TEMP%','%TMP%'); Notes='Temp directory; often writable by all users; credentials sometimes spill here' }
        )
        'config' = @(
            [pscustomobject]@{ Name='ini-files';           Protected=$false; ProtectedBy='none'; RelPaths=@('%PROGRAMDATA%','%APPDATA%'); Notes='Legacy INI configuration; never encrypted' }
            [pscustomobject]@{ Name='registry-plaintext';  Protected=$false; ProtectedBy='none'; RelPaths=@(); Notes='' }
        )
    }

    'java' = @{
        'credential' = @(
            [pscustomobject]@{ Name='keystore-jks';        Protected=$true;  ProtectedBy='password-encrypted JKS/PKCS12'; RelPaths=@(); Notes='Java KeyStore; protected by password but password often hardcoded' }
            [pscustomobject]@{ Name='properties-files';    Protected=$false; ProtectedBy='none'; RelPaths=@(); Notes='application.properties / application.yml: credentials in plain text' }
            [pscustomobject]@{ Name='appdata-plaintext';   Protected=$false; ProtectedBy='none'; RelPaths=@('%APPDATA%','%LOCALAPPDATA%'); Notes='' }
        )
    }

    'python' = @{
        'credential' = @(
            [pscustomobject]@{ Name='keyring-backend';     Protected=$true;  ProtectedBy='OS keyring (DPAPI / Keychain / SecretService)'; RelPaths=@(); Notes='Python keyring library; backend-dependent protection' }
            [pscustomobject]@{ Name='dotenv-file';         Protected=$false; ProtectedBy='none'; RelPaths=@(); Notes='.env files; loaded by python-dotenv; plaintext' }
            [pscustomobject]@{ Name='config-files';        Protected=$false; ProtectedBy='none'; RelPaths=@('%APPDATA%','%LOCALAPPDATA%'); Notes='config.ini, settings.cfg; plaintext' }
        )
    }

    'unknown' = @{
        'credential' = @(
            [pscustomobject]@{ Name='filesystem-scan';     Protected=$false; ProtectedBy='unknown'; RelPaths=@(); Notes='Platform unknown; assume unprotected and report UNTESTED for all stores' }
        )
        'config' = @(
            [pscustomobject]@{ Name='filesystem-scan';     Protected=$false; ProtectedBy='unknown'; RelPaths=@(); Notes='' }
        )
    }
}

# --------------------------------------------------------------------------

function Get-TcpkDerivedSearchSurface {
<#
.SYNOPSIS
    CAP6 - Derive the full set of stores a rule must inspect.

.DESCRIPTION
    Returns every store descriptor for the given platform class and store class.
    Un-protected stores are labeled .Protected=$false and must be inspected with
    at least the same diligence as protected ones.

    The caller marks .Inspected=$true on each descriptor it actually reads.
    Assert-TcpkCoverageComplete then checks for gaps.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$PlatformClass,
        [Parameter(Mandatory)][ValidateSet('credential','cookie','session','config','token')][string]$StoreClass,
        [string]$BaseDir = ''
    )

    $catalog = $script:TcpkStoreCatalog
    $platformKey = if ($catalog.ContainsKey($PlatformClass)) { $PlatformClass } else { 'unknown' }
    $entries     = if ($catalog[$platformKey].ContainsKey($StoreClass)) {
        $catalog[$platformKey][$StoreClass]
    } else {
        $catalog['unknown']['credential']   # sensible fallback
    }
    if (-not $entries) { return @() }

    $result = foreach ($e in $entries) {
        $resolvedPaths = if ($BaseDir -and $e.RelPaths) {
            @($e.RelPaths | ForEach-Object { Join-Path $BaseDir $_ })
        } elseif ($e.RelPaths) {
            @($e.RelPaths)
        } else {
            @()
        }
        # Return a mutable clone so the caller can set .Inspected
        [pscustomobject]@{
            StoreName   = $e.Name
            Protected   = $e.Protected
            ProtectedBy = $e.ProtectedBy
            Paths       = $resolvedPaths
            Notes       = $e.Notes
            Inspected   = $false   # caller sets this to $true when it reads the store
        }
    }
    return @($result)
}

function New-TcpkCoverageExclusion {
<#
.SYNOPSIS
    Create a logged exclusion record.

    Every skip or exclusion filter must call this.  The returned object is
    passed to Format-TcpkCoverageLog so the report shows exactly what was
    excluded and why.  An exclusion that removes a store capable of holding
    secrets has to be justified, not assumed.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Location,   # path, store name, or pattern that was skipped
        [Parameter(Mandatory)][string]$Reason,     # why it was excluded
        [string]$RuleId   = '',
        [string]$Capacity = 'unknown'              # can-hold: credential / cookie / config / unknown
    )
    [pscustomobject]@{
        Location  = $Location
        Reason    = $Reason
        RuleId    = $RuleId
        Capacity  = $Capacity
        Timestamp = [datetime]::UtcNow.ToString('o')
    }
}

function Assert-TcpkCoverageComplete {
<#
.SYNOPSIS
    CAP6 - Return UNTESTED preconditions for every unprotected store that was not inspected.

.DESCRIPTION
    A rule that reported on a protected store must ALSO have inspected the
    unprotected stores for the same data class.  This function checks the
    surface derived from Get-TcpkDerivedSearchSurface and emits one UNTESTED
    precondition (compatible with Resolve-TcpkPreconditions / CAP5) per gap.

.PARAMETER Surface
    The array returned by Get-TcpkDerivedSearchSurface, after the caller has
    set .Inspected on stores it read.

.PARAMETER InspectedStoreNames
    Alternative to the .Inspected flag: explicit list of store names that were
    inspected (union with .Inspected).

.OUTPUTS
    [PSCustomObject[]] precondition objects ready for Resolve-TcpkPreconditions
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$Surface,
        [string[]]$InspectedStoreNames = @()
    )
    $inspectedSet = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)
    foreach ($n in $InspectedStoreNames) { [void]$inspectedSet.Add($n) }

    foreach ($s in $Surface) {
        $covered = $s.Inspected -or $inspectedSet.Contains($s.StoreName)
        if (-not $covered) {
            $protection = if ($s.Protected) { "protected ($($s.ProtectedBy))" } else { 'UNPROTECTED' }
            New-TcpkPrecondition -Name "store-$($s.StoreName)-inspected" -State 'UNTESTED' `
                -Evidence "Store '$($s.StoreName)' ($protection) was not inspected; coverage gap declared."
        }
    }
}

function Format-TcpkCoverageLog {
<#
.SYNOPSIS
    Format the search surface + exclusion list for inclusion in a report.

.DESCRIPTION
    Returns an array of human-readable strings.  Unprotected uninspected
    stores are flagged [NOT INSPECTED - UNPROTECTED] so they stand out.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object[]]$Surface,
        [object[]]$Exclusions = @()
    )
    $lines = foreach ($s in $Surface) {
        $status = if ($s.Inspected) { 'INSPECTED' } else { 'NOT INSPECTED' }
        $prot   = if ($s.Protected) { "protected ($($s.ProtectedBy))" } else { 'UNPROTECTED' }
        $flag   = if (-not $s.Inspected -and -not $s.Protected) { ' *COVERAGE GAP*' } else { '' }
        "[$status] $($s.StoreName) ($prot)$flag"
    }
    if ($Exclusions) {
        $lines += ''
        $lines += 'Exclusions (all must be justified):'
        $lines += @($Exclusions | ForEach-Object {
            $cap = if ($_.Capacity -ne 'unknown') { "; can-hold=$($_.Capacity)" } else { '' }
            "  EXCLUDED: $($_.Location) -- $($_.Reason)$cap [rule: $($_.RuleId)]"
        })
    }
    $lines
}
