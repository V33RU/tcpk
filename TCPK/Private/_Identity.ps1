# Application-identity helpers for OS-integration / registry checks.
#
# Problem: every app stores data in the registry, but WHERE varies per app and the
# key name does not always contain the product name. Apps key data under product
# codes (GUIDs), CLSIDs, ProgIDs, the vendor name, or a brand name different from
# the package name. Searching for one hand-typed substring misses most of it.
#
# Get-TcpkIdentityTerms derives a SET of search terms from the app's own identity
# (MSIX manifest Identity/DisplayName/PublisherDisplayName, main-exe ProductName/
# CompanyName, exe base name, install-folder leaf). The registry checks then search
# for ALL of those terms across more locations.

# Generic tokens that would match a huge swath of the registry and create noise.
# A term is dropped only if it EQUALS one of these (a longer phrase that merely
# contains one, e.g. "Acme Corp", is kept).
$script:TcpkIdentityStopwords = @(
    'microsoft','windows','corporation','corp','inc','incorporated','llc','ltd',
    'limited','company','co','gmbh','software','technologies','technology','systems',
    'solutions','app','application','the','and','llp','plc','group','labs','services'
)

# Derive deduplicated, noise-filtered identity search terms for a target.
# -Path  : the expanded package directory (or a file inside it / the target exe).
# -Extra : caller-supplied terms (e.g. an explicit -PackageName) - always included.
# Returns string[] ordered most-specific (longest) first. Never throws.
function Get-TcpkIdentityTerms {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [string[]]$Extra
    )

    $raw = New-Object 'System.Collections.Generic.List[string]'
    foreach ($e in $Extra) { if ($e) { $raw.Add($e) } }

    # Resolve the directory that holds the app (manifest + exes live here).
    $dir = $Path
    try {
        $it = Get-Item -LiteralPath $Path -ErrorAction Stop
        if (-not $it.PSIsContainer) { $dir = Split-Path -Parent $Path }
    } catch { }

    # --- MSIX manifest identity ---
    $mainExe = $null
    $manifest = $null
    try { $manifest = Read-TcpkAppxManifest -ExpandedPath $dir } catch { }
    if ($manifest) {
        try {
            $nsm      = Get-TcpkAppxNsMgr -Manifest $manifest
            $idNode   = $manifest.DocumentElement.SelectSingleNode('//d:Identity', $nsm)
            $propName = $manifest.DocumentElement.SelectSingleNode('//d:Properties/d:DisplayName', $nsm)
            $propPub  = $manifest.DocumentElement.SelectSingleNode('//d:Properties/d:PublisherDisplayName', $nsm)
            $appNode  = $manifest.DocumentElement.SelectSingleNode('//d:Applications/d:Application', $nsm)
            if ($idNode) {
                $raw.Add($idNode.GetAttribute('Name'))
                $pub = $idNode.GetAttribute('Publisher')
                if ($pub -match 'CN=([^,]+)') { $raw.Add($matches[1]) }   # CN value only
            }
            if ($propName -and $propName.InnerText) { $raw.Add($propName.InnerText) }
            if ($propPub  -and $propPub.InnerText)  { $raw.Add($propPub.InnerText) }
            if ($appNode) {
                $exeAttr = $appNode.GetAttribute('Executable')
                if ($exeAttr) { $mainExe = $exeAttr }
            }
        } catch { }
    }

    # --- main executable (manifest-declared, else largest non-helper .exe) ---
    $mainExePath = $null
    if ($mainExe) {
        $cand = Join-Path $dir $mainExe
        if (Test-Path -LiteralPath $cand) { $mainExePath = $cand }
    }
    if (-not $mainExePath) {
        $exes = @(Get-ChildItem -LiteralPath $dir -Recurse -File -ErrorAction SilentlyContinue |
                  Where-Object { $_.Extension -ieq '.exe' })
        $primary = $exes |
            Where-Object { $_.BaseName -notmatch '(?i)(setup|install|uninstall|update|crashpad|helper|vc_redist|squirrel)' } |
            Sort-Object Length -Descending | Select-Object -First 1
        if (-not $primary -and $exes.Count) { $primary = $exes | Sort-Object Length -Descending | Select-Object -First 1 }
        if ($primary) { $mainExePath = $primary.FullName }
    }
    if ($mainExePath) {
        $raw.Add([IO.Path]::GetFileNameWithoutExtension($mainExePath))
        try {
            $vi = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($mainExePath)
            if ($vi.ProductName) { $raw.Add($vi.ProductName) }
            if ($vi.CompanyName) { $raw.Add($vi.CompanyName) }
        } catch { }
    }

    # --- install-folder / target leaf (often the product or package folder name) ---
    $raw.Add((Split-Path -Leaf $Path))

    # --- clean: strip non-ASCII (target metadata can carry (R)/(TM)/accents),
    #     collapse whitespace, drop short / pure-generic, dedupe (case-insensitive) ---
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $out  = New-Object 'System.Collections.Generic.List[string]'
    foreach ($t in $raw) {
        if (-not $t) { continue }
        $clean = ($t -replace '[^\x20-\x7E]',' ')   # keep printable ASCII only
        $clean = ($clean -replace '\s+',' ').Trim()
        if ($clean.Length -lt 3) { continue }
        if ($script:TcpkIdentityStopwords -contains $clean.ToLowerInvariant()) { continue }
        if ($seen.Add($clean)) { $out.Add($clean) }
    }
    return @($out | Sort-Object { $_.Length } -Descending)
}

# Case-insensitive "does $Text contain any of $Terms" test. Substring, not -like,
# so callers do not have to wrap terms in wildcards. Never throws.
function Test-TcpkTermMatch {
    [CmdletBinding()]
    param([AllowNull()][string]$Text, [string[]]$Terms)
    if (-not $Text) { return $false }
    foreach ($t in $Terms) {
        if (-not $t) { continue }
        if ($Text.IndexOf($t, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) { return $true }
    }
    return $false
}

# Normalize a -NameLike term set: drop blanks and the legacy '*' wildcard sentinel.
# Returns string[] (possibly empty). Use for the survey-style checks.
function Get-TcpkNameTerms {
    [CmdletBinding()] param([AllowNull()][string[]]$NameLike)
    @($NameLike | Where-Object { $_ -and $_ -ne '*' })
}

# Inclusion predicate for name-filtered surveys. Returns $true when $Text should be
# INCLUDED given the term set. An empty set (or the legacy '*' sentinel) means
# "no filter -> include everything" (survey mode); otherwise include only when any
# term matches as a case-insensitive substring.
function Test-TcpkNameInclude {
    [CmdletBinding()]
    param([AllowNull()][string]$Text, [AllowNull()][string[]]$Terms)
    $t = Get-TcpkNameTerms -NameLike $Terms
    if (-not $t.Count) { return $true }
    return (Test-TcpkTermMatch -Text $Text -Terms $t)
}

# The registry roots an app's own config typically lives under, keyed by the
# vendor / product NAME. Includes Software\Classes (== HKCR) so ProgIDs and
# file-association keys that embed the product name are covered.
function Get-TcpkRegistrySearchRoots {
    [CmdletBinding()] param([switch]$MachineOnly)
    $roots = @(
        'HKLM:\SOFTWARE',
        'HKLM:\SOFTWARE\WOW6432Node',
        'HKLM:\SOFTWARE\Classes',
        'HKLM:\SOFTWARE\WOW6432Node\Classes'
    )
    if (-not $MachineOnly) {
        $roots += @(
            'HKCU:\SOFTWARE',
            'HKCU:\SOFTWARE\Classes'
        )
    }
    $roots
}

# Discover the app's Uninstall / ARP entries. These are keyed by a product-code
# GUID (not the product name), so we match on the DisplayName / Publisher VALUES.
# Surfaces the product code + install location, which are themselves strong search
# terms for the rest of the registry. Returns a List of pscustomobject. Never throws.
function Get-TcpkUninstallMatches {
    [CmdletBinding()] param([Parameter(Mandatory)][string[]]$Terms)
    $roots = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
    )
    $out = New-Object 'System.Collections.Generic.List[object]'
    foreach ($r in $roots) {
        if (-not (Test-Path $r)) { continue }
        foreach ($k in (Get-ChildItem -Path $r -ErrorAction SilentlyContinue)) {
            $p = $null
            try { $p = Get-ItemProperty -LiteralPath $k.PSPath -ErrorAction Stop } catch { continue }
            $dn   = "$($p.DisplayName)"
            $pubn = "$($p.Publisher)"
            if ((Test-TcpkTermMatch -Text $dn -Terms $Terms) -or
                (Test-TcpkTermMatch -Text $pubn -Terms $Terms) -or
                (Test-TcpkTermMatch -Text $k.PSChildName -Terms $Terms)) {
                $out.Add([pscustomobject]@{
                    KeyPath         = ($k.PSPath -replace 'Microsoft\.PowerShell\.Core\\Registry::','')
                    ProductCode     = $k.PSChildName
                    DisplayName     = $dn
                    Publisher       = $pubn
                    DisplayVersion  = "$($p.DisplayVersion)"
                    InstallLocation = "$($p.InstallLocation)"
                })
            }
        }
    }
    return $out
}
