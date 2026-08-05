# C9 - Parse structured artifacts structurally, not by substring.
#
# A token's meaning depends on WHERE it sits in the structure it belongs to.
# Substring matching over a structured artifact produces claims the artifact
# does not make.
#
# Observed: a CSP was reported as weakening defence against injected script
# because a keyword appeared somewhere in it, while the directive governing
# script was fully restrictive and the keyword applied only to a directive
# that cannot execute code.
#
# Rule: for any artifact with a defined grammar, parse it into its model and
# evaluate the SPECIFIC ELEMENT the claim is about. If no parser exists, the
# evidence is provenance-level "string-match" (C3) and cannot support a claim
# about semantics. The finding must name WHICH ELEMENT carried the weakness.

# Artifact type registry: what parsers are available and the max provenance level
# they produce. Rules check Get-TcpkArtifactParseLevel before making semantic claims.
$script:TcpkArtifactParsers = [ordered]@{
    'csp'              = @{ Available=$true;  MaxProvenance='structural-parse'; Description='Content-Security-Policy HTTP header' }
    'permissions-policy' = @{ Available=$true;  MaxProvenance='structural-parse'; Description='Permissions-Policy / Feature-Policy HTTP header' }
    'manifest-json'    = @{ Available=$true;  MaxProvenance='structural-parse'; Description='Chrome extension or Electron app manifest.json' }
    'info-plist'       = @{ Available=$true;  MaxProvenance='structural-parse'; Description='Apple Info.plist (iOS/macOS)' }
    'xml-manifest'     = @{ Available=$true;  MaxProvenance='structural-parse'; Description='Windows application manifest (.manifest / .exe.manifest)' }
    'json-policy'      = @{ Available=$true;  MaxProvenance='structural-parse'; Description='JSON-format policy or config file (generic)' }
    'sddl'             = @{ Available=$false; MaxProvenance='string-match'; Description='Security Descriptor Definition Language (ACLs); no parser in this build' }
    'yaml-config'      = @{ Available=$false; MaxProvenance='string-match'; Description='YAML configuration; no parser in this build' }
    'unknown'          = @{ Available=$false; MaxProvenance='string-match'; Description='Unknown or unstructured format' }
}

function Get-TcpkArtifactParseLevel {
<#
.SYNOPSIS
    C9 - Return the maximum provenance level available for an artifact type.

.DESCRIPTION
    Rules call this before making a semantic claim about a structured artifact.
    If ParseAvailable is $false, the evidence is 'string-match' (C3) only and
    cannot support claims about semantics or specific structural elements.
#>
    [CmdletBinding()]
    param([string]$ArtifactType)
    $key = if ($script:TcpkArtifactParsers.ContainsKey("$ArtifactType".ToLower())) { "$ArtifactType".ToLower() } else { 'unknown' }
    $info = $script:TcpkArtifactParsers[$key]
    return [pscustomobject]@{
        ArtifactType    = $key
        ParseAvailable  = $info.Available
        MaxProvenance   = $info.MaxProvenance
        Description     = $info.Description
    }
}

function Assert-TcpkStructuredClaim {
<#
.SYNOPSIS
    C9 - Gate a semantic claim about a structured artifact.

.DESCRIPTION
    A claim about a structured artifact must:
    1. Have a parser available for the artifact type (else provenance is string-match only)
    2. Name the SPECIFIC ELEMENT the weakness is in (e.g. which CSP directive)
    If either condition fails, the claim cannot be made at semantic strength.

.OUTPUTS
    PSCustomObject {Valid, ProvenanceLevel, ClaimElement, Warning}
    When Valid=$false the caller must downgrade to string provenance or drop the claim.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ArtifactType,
        [Parameter(Mandatory)][string]$ClaimElement,   # the specific element the claim is about
        [string]$Evidence = ''
    )
    $parseInfo = Get-TcpkArtifactParseLevel -ArtifactType $ArtifactType
    if (-not $parseInfo.ParseAvailable) {
        return [pscustomobject]@{
            Valid          = $false
            ProvenanceLevel = 'string-match'
            ClaimElement   = $ClaimElement
            Warning        = "No structural parser for '$($parseInfo.ArtifactType)'; evidence is string-match only and cannot support a semantic claim about '$ClaimElement'. C3: string provenance supports 'REFERENCES X', not 'CALLS X' or 'WEAKENS X'."
        }
    }
    if (-not $ClaimElement) {
        return [pscustomobject]@{
            Valid          = $false
            ProvenanceLevel = $parseInfo.MaxProvenance
            ClaimElement   = ''
            Warning        = "Claim about '$($parseInfo.ArtifactType)' does not name a specific element. C9: the finding must identify which element of the structured artifact is weak."
        }
    }
    return [pscustomobject]@{
        Valid          = $true
        ProvenanceLevel = $parseInfo.MaxProvenance
        ClaimElement   = $ClaimElement
        Warning        = ''
    }
}

# ---------------------------------------------------------------------------
# CSP parser
# ---------------------------------------------------------------------------

# CSP fetch-directive fallback chain (W3C spec).
# Most fetch directives fall back to default-src.
# Directives marked @() do NOT fall back to default-src.
$script:TcpkCspFallback = [ordered]@{
    'script-src'             = @('default-src')
    'script-src-elem'        = @('script-src','default-src')
    'script-src-attr'        = @('script-src','default-src')
    'style-src'              = @('default-src')
    'style-src-elem'         = @('style-src','default-src')
    'style-src-attr'         = @('style-src','default-src')
    'img-src'                = @('default-src')
    'connect-src'            = @('default-src')
    'font-src'               = @('default-src')
    'media-src'              = @('default-src')
    'object-src'             = @('default-src')
    'frame-src'              = @('child-src','default-src')
    'worker-src'             = @('child-src','default-src')
    'child-src'              = @('default-src')
    'manifest-src'           = @('default-src')
    # Directives that do NOT inherit from default-src:
    'form-action'            = @()
    'frame-ancestors'        = @()
    'navigate-to'            = @()
    'base-uri'               = @()
    'report-uri'             = @()
    'sandbox'                = @()
    'upgrade-insecure-requests' = @()
    'block-all-mixed-content'   = @()
}

# Tokens that make a fetch directive permissive (allow untrusted content).
# Note: 'unsafe-inline' in style-src allows injected CSS but NOT script execution.
# Use this list only when evaluating script-execution-capable directives.
$script:TcpkCspPermissiveTokens = @(
    "'unsafe-inline'",
    "'unsafe-eval'",
    "'unsafe-hashes'",
    "http:",
    "https:",
    "*",
    "data:"
)

# Directives that are capable of executing script in the browser context.
$script:TcpkCspScriptCapableDirs = @('script-src','script-src-elem','script-src-attr','worker-src','default-src')

function ConvertTo-TcpkCspModel {
<#
.SYNOPSIS
    C9 - Parse a CSP header value into a structured directive model.

.DESCRIPTION
    Returns an ordered hashtable: directive-name -> [string[]] values.
    All names and values are lowercased for consistent comparison.
    Malformed tokens are skipped.

.EXAMPLE
    $m = ConvertTo-TcpkCspModel "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'"
    # $m['script-src'] -> @("'self'")
    # $m['style-src']  -> @("'unsafe-inline'")
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$HeaderValue)
    $model = [ordered]@{}
    foreach ($rawDir in ($HeaderValue -split ';')) {
        $d = $rawDir.Trim()
        if (-not $d) { continue }
        $tokens = @($d -split '\s+' | Where-Object { $_ })
        if (-not $tokens) { continue }
        $name   = $tokens[0].ToLower()
        $values = if ($tokens.Count -gt 1) {
            @($tokens[1..($tokens.Count-1)] | ForEach-Object { $_.ToLower() })
        } else { @() }
        if (-not $model.ContainsKey($name)) { $model[$name] = $values }  # first-wins (RFC)
    }
    return $model
}

function _TcpkCspEffectiveValues {
    param([hashtable]$CspModel, [string]$Directive)
    $dir = $Directive.ToLower()
    if ($CspModel.ContainsKey($dir)) {
        return [pscustomobject]@{ Values=$CspModel[$dir]; ResolvedFrom=$dir; NoRestriction=$false }
    }
    $chain = if ($script:TcpkCspFallback.ContainsKey($dir)) { $script:TcpkCspFallback[$dir] } else { @('default-src') }
    foreach ($fb in $chain) {
        if ($CspModel.ContainsKey($fb)) {
            return [pscustomobject]@{ Values=$CspModel[$fb]; ResolvedFrom=$fb; NoRestriction=$false }
        }
    }
    return [pscustomobject]@{ Values=@(); ResolvedFrom='(none)'; NoRestriction=$true }
}

function Test-TcpkCspDirectivePermissive {
<#
.SYNOPSIS
    C9 - Evaluate whether a SPECIFIC CSP directive allows untrusted content.

.DESCRIPTION
    Resolves the effective source list for $Directive, following the W3C
    fallback chain.  Only evaluates the directive asked about -- a keyword in
    style-src does NOT affect the permissiveness of script-src.

    Returns PSCustomObject {Permissive, DirectiveName, ResolvedFrom,
    PermissiveTokens, Reason}.

.EXAMPLE
    $m = ConvertTo-TcpkCspModel "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'"
    Test-TcpkCspDirectivePermissive -CspModel $m -Directive 'script-src'
    # Permissive=$false  (script-src 'self' is restrictive)
    Test-TcpkCspDirectivePermissive -CspModel $m -Directive 'style-src'
    # Permissive=$true   ('unsafe-inline' in style-src) -- but style cannot execute code
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$CspModel,
        [Parameter(Mandatory)][string]$Directive
    )
    $eff = _TcpkCspEffectiveValues -CspModel $CspModel -Directive $Directive
    if ($eff.NoRestriction) {
        return [pscustomobject]@{
            Permissive       = $true
            DirectiveName    = $Directive
            ResolvedFrom     = '(none)'
            PermissiveTokens = @()
            Reason           = "No '$Directive' directive and no applicable default-src; no restriction on '$Directive' sources"
        }
    }
    $values = @($eff.Values)
    $found  = @($values | Where-Object { $_ -in $script:TcpkCspPermissiveTokens })
    if ($found) {
        return [pscustomobject]@{
            Permissive       = $true
            DirectiveName    = $Directive
            ResolvedFrom     = $eff.ResolvedFrom
            PermissiveTokens = $found
            Reason           = "Directive '$Directive' (resolved from '$($eff.ResolvedFrom)') contains permissive token(s): $($found -join ', ')"
        }
    }
    return [pscustomobject]@{
        Permissive       = $false
        DirectiveName    = $Directive
        ResolvedFrom     = $eff.ResolvedFrom
        PermissiveTokens = @()
        Reason           = "Directive '$Directive' (resolved from '$($eff.ResolvedFrom)') is restrictive. Effective values: $($values -join ' ')"
    }
}

function Test-TcpkCspScriptExecutionPermissive {
<#
.SYNOPSIS
    C9 - Evaluate whether a CSP permits untrusted SCRIPT EXECUTION specifically.

.DESCRIPTION
    Evaluates script-src (and script-src-elem, script-src-attr, worker-src) with
    fallback to default-src.  A keyword in a non-script directive (style-src,
    img-src, etc.) does NOT count.

    Returns PSCustomObject {Permissive, WeakDirective, ResolvedFrom, Reason}.
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$CspModel)

    foreach ($dir in $script:TcpkCspScriptCapableDirs) {
        $r = Test-TcpkCspDirectivePermissive -CspModel $CspModel -Directive $dir
        if ($r.Permissive) {
            return [pscustomobject]@{
                Permissive    = $true
                WeakDirective = $dir
                ResolvedFrom  = $r.ResolvedFrom
                Reason        = $r.Reason
            }
        }
    }
    return [pscustomobject]@{
        Permissive    = $false
        WeakDirective = ''
        ResolvedFrom  = ''
        Reason        = "All script-execution-capable directives (script-src, worker-src, default-src) are restrictive"
    }
}
