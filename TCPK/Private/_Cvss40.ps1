# Official CVSS v4.0 base-score engine.
#
# Faithful PowerShell port of the FIRST.org reference calculator
# (cvss_score.js / cvss_lookup.js / max_severity.js / max_composed.js;
# BSD-2-Clause, Copyright FIRST, Red Hat, and contributors).
#
# Honesty note: a CVSS v4.0 base score is NOT a closed-form formula - it is
# derived from a 270-entry macrovector lookup table plus a severity-distance
# interpolation. This engine reproduces that algorithm exactly, so the number
# is DERIVED from the vector, never guessed. The lookup table ships verbatim in
# Data\cvss\cvss40-lookup.json (generated from the upstream source, unmodified).

$script:TcpkCvss40Lookup = $null   # lazy-loaded macrovector -> base score

# --- metric level weights (index of each value; lower = more severe) ---
$script:TcpkCvss40Levels = @{
    AV = @{ N = 0.0; A = 0.1; L = 0.2; P = 0.3 }
    PR = @{ N = 0.0; L = 0.1; H = 0.2 }
    UI = @{ N = 0.0; P = 0.1; A = 0.2 }
    AC = @{ L = 0.0; H = 0.1 }
    AT = @{ N = 0.0; P = 0.1 }
    VC = @{ H = 0.0; L = 0.1; N = 0.2 }
    VI = @{ H = 0.0; L = 0.1; N = 0.2 }
    VA = @{ H = 0.0; L = 0.1; N = 0.2 }
    SC = @{ H = 0.1; L = 0.2; N = 0.3 }
    SI = @{ S = 0.0; H = 0.1; L = 0.2; N = 0.3 }
    SA = @{ S = 0.0; H = 0.1; L = 0.2; N = 0.3 }
    CR = @{ H = 0.0; M = 0.1; L = 0.2 }
    IR = @{ H = 0.0; M = 0.1; L = 0.2 }
    AR = @{ H = 0.0; M = 0.1; L = 0.2 }
}

# --- maxSeverity (distance depth +1 per EQ) ---
$script:TcpkCvss40MaxSeverity = @{
    eq1 = @{ '0' = 1; '1' = 4; '2' = 5 }
    eq2 = @{ '0' = 1; '1' = 2 }
    eq3eq6 = @{ '0' = @{ '0' = 7; '1' = 6 }; '1' = @{ '0' = 8; '1' = 8 }; '2' = @{ '1' = 10 } }
    eq4 = @{ '0' = 6; '1' = 5; '2' = 4 }
    eq5 = @{ '0' = 1; '1' = 1; '2' = 1 }
}

# --- maxComposed (highest-severity vector fragment(s) per EQ level) ---
$script:TcpkCvss40MaxComposed = @{
    eq1 = @{
        '0' = @('AV:N/PR:N/UI:N/')
        '1' = @('AV:A/PR:N/UI:N/', 'AV:N/PR:L/UI:N/', 'AV:N/PR:N/UI:P/')
        '2' = @('AV:P/PR:N/UI:N/', 'AV:A/PR:L/UI:P/')
    }
    eq2 = @{
        '0' = @('AC:L/AT:N/')
        '1' = @('AC:H/AT:N/', 'AC:L/AT:P/')
    }
    eq3 = @{
        '0' = @{
            '0' = @('VC:H/VI:H/VA:H/CR:H/IR:H/AR:H/')
            '1' = @('VC:H/VI:H/VA:L/CR:M/IR:M/AR:H/', 'VC:H/VI:H/VA:H/CR:M/IR:M/AR:M/')
        }
        '1' = @{
            '0' = @('VC:L/VI:H/VA:H/CR:H/IR:H/AR:H/', 'VC:H/VI:L/VA:H/CR:H/IR:H/AR:H/')
            '1' = @('VC:L/VI:H/VA:L/CR:H/IR:M/AR:H/', 'VC:L/VI:H/VA:H/CR:H/IR:M/AR:M/', 'VC:H/VI:L/VA:H/CR:M/IR:H/AR:M/', 'VC:H/VI:L/VA:L/CR:M/IR:H/AR:H/', 'VC:L/VI:L/VA:H/CR:H/IR:H/AR:M/')
        }
        '2' = @{
            '1' = @('VC:L/VI:L/VA:L/CR:H/IR:H/AR:H/')
        }
    }
    eq4 = @{
        '0' = @('SC:H/SI:S/SA:S/')
        '1' = @('SC:H/SI:H/SA:H/')
        '2' = @('SC:L/SI:L/SA:L/')
    }
    eq5 = @{
        '0' = @('E:A/')
        '1' = @('E:P/')
        '2' = @('E:U/')
    }
}

function Initialize-TcpkCvss40 {
    if ($null -ne $script:TcpkCvss40Lookup) { return $true }
    $p = Join-Path $script:TcpkRoot 'Data\cvss\cvss40-lookup.json'
    if (-not (Test-Path -LiteralPath $p)) { return $false }
    try {
        $json = Get-Content -LiteralPath $p -Raw | ConvertFrom-Json
        $ht = @{}
        foreach ($prop in $json.PSObject.Properties) { $ht[$prop.Name] = [double]$prop.Value }
        $script:TcpkCvss40Lookup = $ht
        return $true
    } catch { return $false }
}

# Parse "CVSS:4.0/AV:N/.../SA:N" into @{ AV='N'; ... }. Returns $null if not v4.0.
function ConvertFrom-TcpkCvss40Vector {
    [CmdletBinding()] param([Parameter(Mandatory)][AllowEmptyString()][string]$Vector)
    if ([string]::IsNullOrWhiteSpace($Vector)) { return $null }
    $parts = $Vector -split '/'
    if ($parts.Count -lt 2 -or $parts[0] -notmatch '^CVSS:4\.0$') { return $null }
    $m = @{}
    for ($i = 1; $i -lt $parts.Count; $i++) {
        $kv = $parts[$i] -split ':', 2
        if ($kv.Count -eq 2 -and $kv[0]) { $m[$kv[0]] = $kv[1] }
    }
    return $m
}

# JS m(): selected metric value, applying X-defaults + modified overrides.
function Get-TcpkCvss40M {
    param($Metrics, [string]$Name)
    $sel = if ($Metrics.ContainsKey($Name)) { $Metrics[$Name] } else { 'X' }
    if ($Name -eq 'E'  -and $sel -eq 'X') { return 'A' }
    if (($Name -eq 'CR' -or $Name -eq 'IR' -or $Name -eq 'AR') -and $sel -eq 'X') { return 'H' }
    $mn = 'M' + $Name
    if ($Metrics.ContainsKey($mn) -and $Metrics[$mn] -ne 'X') { return $Metrics[$mn] }
    return $sel
}

# JS extractValueMetric(): pull a metric value out of a composed max-vector fragment.
function Get-TcpkCvss40Extract {
    param([string]$Metric, [string]$Str)
    $i = $Str.IndexOf($Metric)
    if ($i -lt 0) { return $null }
    $rest = $Str.Substring($i + $Metric.Length + 1)
    $slash = $rest.IndexOf('/')
    if ($slash -gt 0) { return $rest.Substring(0, $slash) }
    return $rest
}

# JS macroVector(): the six EQ digits.
function Get-TcpkCvss40MacroVector {
    param($Metrics)
    $AV = Get-TcpkCvss40M $Metrics 'AV'; $PR = Get-TcpkCvss40M $Metrics 'PR'; $UI = Get-TcpkCvss40M $Metrics 'UI'
    $AC = Get-TcpkCvss40M $Metrics 'AC'; $AT = Get-TcpkCvss40M $Metrics 'AT'
    $VC = Get-TcpkCvss40M $Metrics 'VC'; $VI = Get-TcpkCvss40M $Metrics 'VI'; $VA = Get-TcpkCvss40M $Metrics 'VA'
    $SC = Get-TcpkCvss40M $Metrics 'SC'; $SI = Get-TcpkCvss40M $Metrics 'SI'; $SA = Get-TcpkCvss40M $Metrics 'SA'
    $E  = Get-TcpkCvss40M $Metrics 'E'
    $CR = Get-TcpkCvss40M $Metrics 'CR'; $IR = Get-TcpkCvss40M $Metrics 'IR'; $AR = Get-TcpkCvss40M $Metrics 'AR'
    $MSI = Get-TcpkCvss40M $Metrics 'MSI'; $MSA = Get-TcpkCvss40M $Metrics 'MSA'

    # EQ1
    if ($AV -eq 'N' -and $PR -eq 'N' -and $UI -eq 'N') { $eq1 = '0' }
    elseif (($AV -eq 'N' -or $PR -eq 'N' -or $UI -eq 'N') -and -not ($AV -eq 'N' -and $PR -eq 'N' -and $UI -eq 'N') -and $AV -ne 'P') { $eq1 = '1' }
    else { $eq1 = '2' }

    # EQ2
    if ($AC -eq 'L' -and $AT -eq 'N') { $eq2 = '0' } else { $eq2 = '1' }

    # EQ3
    if ($VC -eq 'H' -and $VI -eq 'H') { $eq3 = '0' }
    elseif ($VC -eq 'H' -or $VI -eq 'H' -or $VA -eq 'H') { $eq3 = '1' }
    else { $eq3 = '2' }

    # EQ4
    if ($MSI -eq 'S' -or $MSA -eq 'S') { $eq4 = '0' }
    elseif ($SC -eq 'H' -or $SI -eq 'H' -or $SA -eq 'H') { $eq4 = '1' }
    else { $eq4 = '2' }

    # EQ5
    if ($E -eq 'A') { $eq5 = '0' } elseif ($E -eq 'P') { $eq5 = '1' } else { $eq5 = '2' }

    # EQ6
    if (($CR -eq 'H' -and $VC -eq 'H') -or ($IR -eq 'H' -and $VI -eq 'H') -or ($AR -eq 'H' -and $VA -eq 'H')) { $eq6 = '0' } else { $eq6 = '1' }

    return ($eq1 + $eq2 + $eq3 + $eq4 + $eq5 + $eq6)
}

function Get-TcpkCvss40LevelDist {
    param([string]$Metric, [string]$ValSel, [string]$ValMax)
    $tab = $script:TcpkCvss40Levels[$Metric]
    $a = if ($tab.ContainsKey($ValSel)) { $tab[$ValSel] } else { 0.0 }
    $b = if ($ValMax -and $tab.ContainsKey($ValMax)) { $tab[$ValMax] } else { 0.0 }
    return ($a - $b)
}

# Main: compute the CVSS v4.0 base score for a vector string.
# Returns @{ Score=[double]; Rating=[string]; MacroVector=[string] } or $null if
# the vector is not parseable / the lookup table is unavailable.
function Get-TcpkCvss40Score {
    [CmdletBinding()] param([Parameter(Mandatory)][AllowEmptyString()][string]$Vector)
    if (-not (Initialize-TcpkCvss40)) { return $null }
    $sel = ConvertFrom-TcpkCvss40Vector -Vector $Vector
    if ($null -eq $sel) { return $null }
    $lookup = $script:TcpkCvss40Lookup
    $nan = [double]::NaN

    # all impacts None -> 0.0
    $allN = $true
    foreach ($mm in 'VC','VI','VA','SC','SI','SA') { if ((Get-TcpkCvss40M $sel $mm) -ne 'N') { $allN = $false; break } }
    if ($allN) { return [pscustomobject]@{ Score = 0.0; Rating = 'None'; MacroVector = (Get-TcpkCvss40MacroVector $sel) } }

    $mv = Get-TcpkCvss40MacroVector $sel
    if (-not $lookup.ContainsKey($mv)) { return $null }
    $value = $lookup[$mv]

    $eq1 = [int]$mv[0].ToString(); $eq2 = [int]$mv[1].ToString(); $eq3 = [int]$mv[2].ToString()
    $eq4 = [int]$mv[3].ToString(); $eq5 = [int]$mv[4].ToString(); $eq6 = [int]$mv[5].ToString()

    # next-lower macrovectors
    $eq1_low = "$($eq1+1)$eq2$eq3$eq4$eq5$eq6"
    $eq2_low = "$eq1$($eq2+1)$eq3$eq4$eq5$eq6"
    $eq4_low = "$eq1$eq2$eq3$($eq4+1)$eq5$eq6"
    $eq5_low = "$eq1$eq2$eq3$eq4$($eq5+1)$eq6"

    $score_eq1_low = if ($lookup.ContainsKey($eq1_low)) { $lookup[$eq1_low] } else { $nan }
    $score_eq2_low = if ($lookup.ContainsKey($eq2_low)) { $lookup[$eq2_low] } else { $nan }
    $score_eq4_low = if ($lookup.ContainsKey($eq4_low)) { $lookup[$eq4_low] } else { $nan }
    $score_eq5_low = if ($lookup.ContainsKey($eq5_low)) { $lookup[$eq5_low] } else { $nan }

    # eq3/eq6 are coupled
    if ($eq3 -eq 1 -and $eq6 -eq 1)      { $k = "$eq1$eq2$($eq3+1)$eq4$eq5$eq6"; $score_eq3eq6_low = if ($lookup.ContainsKey($k)) { $lookup[$k] } else { $nan } }
    elseif ($eq3 -eq 0 -and $eq6 -eq 1)  { $k = "$eq1$eq2$($eq3+1)$eq4$eq5$eq6"; $score_eq3eq6_low = if ($lookup.ContainsKey($k)) { $lookup[$k] } else { $nan } }
    elseif ($eq3 -eq 1 -and $eq6 -eq 0)  { $k = "$eq1$eq2$eq3$eq4$eq5$($eq6+1)"; $score_eq3eq6_low = if ($lookup.ContainsKey($k)) { $lookup[$k] } else { $nan } }
    elseif ($eq3 -eq 0 -and $eq6 -eq 0)  {
        $kl = "$eq1$eq2$eq3$eq4$eq5$($eq6+1)"; $kr = "$eq1$eq2$($eq3+1)$eq4$eq5$eq6"
        $sl = if ($lookup.ContainsKey($kl)) { $lookup[$kl] } else { $nan }
        $sr = if ($lookup.ContainsKey($kr)) { $lookup[$kr] } else { $nan }
        $score_eq3eq6_low = if ($sl -gt $sr) { $sl } else { $sr }
    }
    else { $k = "$eq1$eq2$($eq3+1)$eq4$eq5$($eq6+1)"; $score_eq3eq6_low = if ($lookup.ContainsKey($k)) { $lookup[$k] } else { $nan } }

    # build candidate max-vectors and pick the first with no negative severity distance
    $eq1m = $script:TcpkCvss40MaxComposed.eq1["$eq1"]
    $eq2m = $script:TcpkCvss40MaxComposed.eq2["$eq2"]
    $eq3m = $script:TcpkCvss40MaxComposed.eq3["$eq3"]["$eq6"]
    $eq4m = $script:TcpkCvss40MaxComposed.eq4["$eq4"]
    $eq5m = $script:TcpkCvss40MaxComposed.eq5["$eq5"]

    $dist = @{}
    $metrics14 = 'AV','PR','UI','AC','AT','VC','VI','VA','SC','SI','SA','CR','IR','AR'
    $found = $false
    foreach ($a in $eq1m) { foreach ($b in $eq2m) { foreach ($c in $eq3m) { foreach ($d in $eq4m) { foreach ($e in $eq5m) {
        $maxVec = "$a$b$c$d$e"
        $ok = $true
        $tmp = @{}
        foreach ($mt in $metrics14) {
            $dv = Get-TcpkCvss40LevelDist $mt (Get-TcpkCvss40M $sel $mt) (Get-TcpkCvss40Extract $mt $maxVec)
            $tmp[$mt] = $dv
            if ($dv -lt 0) { $ok = $false; break }
        }
        if ($ok) { $dist = $tmp; $found = $true; break }
    } if ($found) { break } } if ($found) { break } } if ($found) { break } } if ($found) { break } }

    $csd_eq1   = $dist['AV'] + $dist['PR'] + $dist['UI']
    $csd_eq2   = $dist['AC'] + $dist['AT']
    $csd_eq3e6 = $dist['VC'] + $dist['VI'] + $dist['VA'] + $dist['CR'] + $dist['IR'] + $dist['AR']
    $csd_eq4   = $dist['SC'] + $dist['SI'] + $dist['SA']

    $step = 0.1
    $ad_eq1   = $value - $score_eq1_low
    $ad_eq2   = $value - $score_eq2_low
    $ad_eq3e6 = $value - $score_eq3eq6_low
    $ad_eq4   = $value - $score_eq4_low
    $ad_eq5   = $value - $score_eq5_low

    $ms_eq1   = $script:TcpkCvss40MaxSeverity.eq1["$eq1"] * $step
    $ms_eq2   = $script:TcpkCvss40MaxSeverity.eq2["$eq2"] * $step
    $ms_eq3e6 = $script:TcpkCvss40MaxSeverity.eq3eq6["$eq3"]["$eq6"] * $step
    $ms_eq4   = $script:TcpkCvss40MaxSeverity.eq4["$eq4"] * $step

    $n = 0
    $ns_eq1 = 0.0; $ns_eq2 = 0.0; $ns_eq3e6 = 0.0; $ns_eq4 = 0.0; $ns_eq5 = 0.0
    if (-not [double]::IsNaN($ad_eq1))   { $n++; $ns_eq1   = $ad_eq1   * ($csd_eq1   / $ms_eq1) }
    if (-not [double]::IsNaN($ad_eq2))   { $n++; $ns_eq2   = $ad_eq2   * ($csd_eq2   / $ms_eq2) }
    if (-not [double]::IsNaN($ad_eq3e6)) { $n++; $ns_eq3e6 = $ad_eq3e6 * ($csd_eq3e6 / $ms_eq3e6) }
    if (-not [double]::IsNaN($ad_eq4))   { $n++; $ns_eq4   = $ad_eq4   * ($csd_eq4   / $ms_eq4) }
    if (-not [double]::IsNaN($ad_eq5))   { $n++; $ns_eq5   = 0.0 }   # eq5 percentage is always 0

    if ($n -eq 0) { $mean = 0.0 } else { $mean = ($ns_eq1 + $ns_eq2 + $ns_eq3e6 + $ns_eq4 + $ns_eq5) / $n }

    $value -= $mean
    if ($value -lt 0)  { $value = 0.0 }
    if ($value -gt 10) { $value = 10.0 }
    $score = [math]::Round($value, 1, [System.MidpointRounding]::AwayFromZero)

    $rating = Get-TcpkCvss40Rating $score
    return [pscustomobject]@{ Score = $score; Rating = $rating; MacroVector = $mv }
}

function Get-TcpkCvss40Rating {
    param([double]$Score)
    if     ($Score -ge 9.0) { 'Critical' }
    elseif ($Score -ge 7.0) { 'High' }
    elseif ($Score -ge 4.0) { 'Medium' }
    elseif ($Score -ge 0.1) { 'Low' }
    else                    { 'None' }
}
