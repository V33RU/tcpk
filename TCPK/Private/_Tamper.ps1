#requires -Version 5.1
# Parameter tampering: which values are worth mutating, what to mutate them to, and how to
# read the result without fooling yourself.
#
# The mutation primitive already existed. Set-TcpkRequestId writes any single path segment,
# query param, header, cookie or JSON leaf despite its name, and Invoke-TcpkIdorProbe already
# synthesises an arbitrary kind:key location. What was missing is the other half: IDOR asks
# "does someone else's id return their data", tampering asks "did the server HONOUR a value it
# should have recomputed or refused". Different question, different admission gate, different
# verdict.
#
# Get-TcpkIdLocations admits id-SHAPED values, which is the wrong filter here. A price of
# 49.99, a quantity of 1 and a role of "user" are none of them id-shaped, and they are exactly
# what a tamperer edits.

# Value classes worth mutating, in the order they are tested. Each entry is:
#   KeyRx    the parameter NAME pattern that suggests this class
#   ValueRx  the parameter VALUE pattern the class requires
#   Mutate   scriptblock turning the observed value into the tampered one
#   Why      what a server honouring the mutation would be getting wrong
$script:TcpkTamperClasses = @(
    @{ Class = 'price'
       KeyRx = '(?i)(price|amount|total|cost|fee|charge|balance|subtotal|discount)'
       ValueRx = '^\d+(\.\d+)?$'
       Mutate = { param($v) '0.01' }
       Why = 'the server took a client-supplied price instead of recomputing it from the catalogue' }
    @{ Class = 'qty'
       KeyRx = '(?i)(qty|quantity|count|items|units|stock)'
       ValueRx = '^-?\d+$'
       Mutate = { param($v) '-1' }
       Why = 'a negative quantity can invert a total or a stock decrement' }
    @{ Class = 'bool'
       KeyRx = '(?i)(admin|premium|verified|approved|enabled|paid|active|trial|is[_-]?[a-z]+)'
       ValueRx = '(?i)^(true|false|0|1|yes|no)$'
       Mutate = { param($v) if ("$v" -imatch '^(true|1|yes)$') { 'false' } else { 'true' } }
       Why = 'a privilege or entitlement flag was trusted from the request' }
    @{ Class = 'role'
       KeyRx = '(?i)(role|group|tier|plan|level|usertype|account[_-]?type|permission)'
       ValueRx = '(?i)^[a-z][a-z0-9_-]{2,24}$'
       Mutate = { param($v) 'admin' }
       Why = 'the role came from the request rather than from the session' }
    @{ Class = 'limit'
       KeyRx = '(?i)(limit|per[_-]?page|page[_-]?size|max|top|rows|take)'
       ValueRx = '^\d+$'
       Mutate = { param($v) '100000' }
       Why = 'an unbounded page size is a cheap denial of service and a bulk extraction primitive' }
)

function Get-TcpkTamperMutation {
<#
.SYNOPSIS
    The tampered value for one class, or $null when the value does not fit the class.
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Class, [AllowEmptyString()][string]$Value)
    foreach ($c in $script:TcpkTamperClasses) {
        if ($c.Class -ne $Class) { continue }
        if ($Value -notmatch $c.ValueRx) { return $null }
        $new = & $c.Mutate $Value
        # A mutation that lands on the original proves nothing: the request would be identical
        # and any "accepted" verdict would be measuring the baseline against itself.
        if ("$new" -eq "$Value") { return $null }
        return "$new"
    }
    return $null
}

function Get-TcpkTamperLocations {
<#
.SYNOPSIS
    Value-shaped parameters worth tampering with, as {Kind; Key; Value; Class; Mutated; Why}.

.DESCRIPTION
    Sibling of Get-TcpkIdLocations, admitting on VALUE CLASS rather than on id shape. Covers
    query parameters, JSON body leaves and form fields. Path segments are deliberately excluded:
    a price does not live in a path segment, and mutating one usually just produces a 404 that
    reads like a rejection.

    Cookies and headers are excluded for the same reason plus a sharper one. A tampered cookie
    is indistinguishable from a broken session, so an "accepted" verdict there is unsafe.
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][hashtable]$Spec)

    $locs = New-Object System.Collections.Generic.List[object]

    $add = {
        param($kind, $key, $value)
        foreach ($c in $script:TcpkTamperClasses) {
            if ("$key" -notmatch $c.KeyRx) { continue }
            $m = Get-TcpkTamperMutation -Class $c.Class -Value "$value"
            if (-not $m) { continue }
            $locs.Add(@{ Kind = $kind; Key = $key; Value = "$value"; Class = $c.Class; Mutated = $m; Why = $c.Why })
            break   # first matching class only, so one parameter yields one test
        }
    }

    if ($Spec.Query) {
        foreach ($k in @($Spec.Query.Keys)) { & $add 'query' $k $Spec.Query[$k] }
    }

    if ($Spec.Body -and $Spec.Body.Length -gt 0) {
        $text = ''
        try { $text = [Text.Encoding]::UTF8.GetString($Spec.Body) } catch { $text = '' }
        if ($Spec.ContentType -match 'json' -or ($text.TrimStart().StartsWith('{'))) {
            try {
                $obj = $text | ConvertFrom-Json
                foreach ($leaf in (Get-TcpkTamperJsonLeaves -Node $obj -PathPrefix '$')) {
                    & $add 'json' $leaf.Key $leaf.Value
                }
            } catch { }
        } elseif ($Spec.ContentType -match 'x-www-form-urlencoded' -or $text -match '^[^=&]+=[^&]*(&|$)') {
            foreach ($pair in ($text -split '&')) {
                $kv = $pair -split '=', 2
                if ($kv.Count -eq 2) {
                    $k = [uri]::UnescapeDataString($kv[0])
                    $v = [uri]::UnescapeDataString($kv[1])
                    & $add 'form' $k $v
                }
            }
        }
    }

    return $locs.ToArray()
}

function Get-TcpkTamperJsonLeaves {
<#
.SYNOPSIS
    Flatten a parsed JSON object to {Key; Value} leaves with dotted paths.
#>
    [CmdletBinding()]
    param($Node, [string]$PathPrefix = '$', [int]$Depth = 0)
    $out = New-Object System.Collections.Generic.List[object]
    if ($null -eq $Node -or $Depth -gt 8) { return $out }
    if ($Node -is [System.Management.Automation.PSCustomObject]) {
        foreach ($p in $Node.PSObject.Properties) {
            $child = $p.Value
            if ($child -is [System.Management.Automation.PSCustomObject]) {
                foreach ($l in (Get-TcpkTamperJsonLeaves -Node $child -PathPrefix "$PathPrefix.$($p.Name)" -Depth ($Depth + 1))) { $out.Add($l) }
            } elseif ($child -is [System.Array]) {
                continue   # array index mutation is a different problem; out of scope here
            } else {
                $out.Add(@{ Key = "$PathPrefix.$($p.Name)"; Value = "$child" })
            }
        }
    }
    return $out
}

function Get-TcpkTamperVerdict {
<#
.SYNOPSIS
    Read three responses and return 'accepted', 'rejected' or 'not-conclusive'.

.DESCRIPTION
    The verdict needs three observations, not two. Baseline is what success looks like. Tampered
    is the question. Bogus is a value no correct server should ever accept, and it is what makes
    the answer defensible: without it, an endpoint that returns 200 to literally anything reads
    as "tampering accepted" on every parameter.

    This is the same failure the vertical authorization matrix had. When the accept reference and
    the reject reference are indistinguishable, the honest answer is NOT CONCLUSIVE, and saying
    so is the whole point of running the control.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Baseline,
        [Parameter(Mandatory)][hashtable]$Tampered,
        [Parameter(Mandatory)][hashtable]$Bogus,
        [switch]$FuzzyBodyMatch
    )
    if ($Baseline.Status -eq 0 -or $Tampered.Status -eq 0 -or $Bogus.Status -eq 0) { return 'not-conclusive' }
    # The control never fired: the endpoint answers a garbage value exactly as it answers a good
    # one, so nothing this endpoint returns can distinguish accepted from rejected.
    if ($Bogus.Hash -eq $Baseline.Hash) { return 'not-conclusive' }

    $ok = Test-TcpkResponseAccepted -Candidate $Tampered -AcceptRef $Baseline -RejectRef $Bogus -FuzzyBodyMatch:$FuzzyBodyMatch
    if ($ok) { return 'accepted' }
    if ($Tampered.Hash -eq $Bogus.Hash) { return 'rejected' }
    return 'not-conclusive'
}
