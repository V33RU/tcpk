# CAP3 - Evidence provenance.
#
# The same token means different things depending on where it was found.
# A symbol in an import table, a string in a binary, and text in documentation
# are three different strengths of evidence.  Rules that claim "this binary CALLS X"
# need a structural or dynamic basis; a string match supports only "references X".
#
# Provenance strength (ascending):
#   prose-doc        (1) - from documentation, comments, changelogs, licence text
#   string-match     (2) - regex / text scan of binary or config content
#   dynamic          (3) - observed at runtime: loaded module, Frida hook, network capture
#   structural-parse (4) - read from a binary structure: PE import/export/delay-import
#                          table, manifest XML, PE header field, JVM class constant pool
#
# Claim requirements (minimum provenance strength):
#   exists / documents  (1) - any provenance
#   references          (2) - string-match or stronger
#   calls / ships       (3) - dynamic or structural-parse

$script:TcpkProvenanceStrength = @{
    'prose-doc'        = 1
    'string-match'     = 2
    'dynamic'          = 3
    'structural-parse' = 4
}

$script:TcpkClaimMinStrength = @{
    'exists'     = 1
    'documents'  = 1
    'references' = 2
    'calls'      = 3
    'ships'      = 3
}

function New-TcpkEvidenceItem {
<#
.SYNOPSIS
    CAP3 - Create a provenance-tagged evidence item.

.PARAMETER Value
    The observed token, symbol, value, or path.

.PARAMETER Provenance
    How the value was obtained.
    structural-parse | dynamic | string-match | prose-doc

.PARAMETER Source
    Where it was found (file, store, process, field name).
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Value,
        [Parameter(Mandatory)][ValidateSet('structural-parse','dynamic','string-match','prose-doc')]
        [string]$Provenance,
        [Parameter(Mandatory)][string]$Source
    )
    return [pscustomobject]@{
        Value      = $Value
        Provenance = $Provenance
        Source     = $Source
        Strength   = $script:TcpkProvenanceStrength[$Provenance]
    }
}

function Assert-TcpkClaimSupported {
<#
.SYNOPSIS
    CAP3 - Verify that a set of evidence items supports a given claim level.

.DESCRIPTION
    Returns $true when at least one item's provenance meets the minimum strength
    for the claim.  A claim of 'calls' requires structural-parse or dynamic.
    A claim of 'references' accepts string-match or stronger.

.PARAMETER Claim
    The claim being made: exists | documents | references | calls | ships

.PARAMETER Items
    Evidence items from New-TcpkEvidenceItem.

.OUTPUTS
    [PSCustomObject] { Supported; MinRequired; BestProvenance; Explanation }
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('exists','documents','references','calls','ships')]
        [string]$Claim,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Items
    )

    $minStrength = $script:TcpkClaimMinStrength[$Claim]
    $best = ($Items | Where-Object { $_ } | Measure-Object -Property Strength -Maximum).Maximum
    $bestProv = if ($null -eq $best) { 'none' } else {
        ($script:TcpkProvenanceStrength.GetEnumerator() | Where-Object { $_.Value -eq [int]$best } |
            Select-Object -First 1).Key
    }
    $supported = ([int]$best -ge $minStrength)
    $minProv   = ($script:TcpkProvenanceStrength.GetEnumerator() | Where-Object { $_.Value -eq $minStrength } |
        Select-Object -First 1).Key

    $expl = if ($supported) {
        "CAP3: claim '$Claim' supported by $bestProv evidence"
    } else {
        "CAP3: claim '$Claim' requires $minProv or stronger; best available is $bestProv -- downgrade claim to 'references' or supply structural/dynamic evidence"
    }

    return [pscustomobject]@{
        Supported      = $supported
        MinRequired    = $minProv
        BestProvenance = $bestProv
        Explanation    = $expl
    }
}

function Format-TcpkEvidenceItems {
<#
.SYNOPSIS
    CAP3 - Render provenance-tagged evidence items to a single Evidence string.

.DESCRIPTION
    Groups items by provenance and renders each group so reviewers can see
    exactly how every piece of evidence was obtained.  String-match items are
    labelled differently from import-table items so the strength is visible.

.OUTPUTS
    [string] suitable for [TcpkFinding].Evidence
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Items)

    if (-not $Items) { return '' }
    $groups = $Items | Where-Object { $_ } | Group-Object Provenance
    $parts  = foreach ($g in ($groups | Sort-Object { $script:TcpkProvenanceStrength[$_.Name] } -Descending)) {
        $vals = ($g.Group | ForEach-Object { "$($_.Value) [$($_.Source)]" }) -join '; '
        "$($g.Name): $vals"
    }
    return $parts -join ' | '
}
