# Library version-currency / end-of-life awareness (online, opt-in).
#
# WHY: CVE matching only answers "vulnerable to a KNOWN bug?". It does NOT answer "is this the
# current, supported version?". A library can have zero open CVEs yet sit on a branch that is
# about to stop receiving security fixes (e.g. OpenSSL 3.0.21 -- 0 CVEs, but branch 3.0 reaches
# EOL 2026-09-07 while 4.x / 3.5-LTS are current). The remediation for such a lib is NOT the
# historical fix-in version of some old CVE (3.0.8) -- it is "move to the latest supported release".
# This helper supplies the latest version + branch EOL so the audit can say that plainly.
#
# SOURCE: endoflife.date public API (per-product release cycles: cycle / latest / lts / eol).
# PRIVACY: sends only the public product slug in the URL; no target data. Opt-in (online path).

$script:TcpkEolApi = 'https://endoflife.date/api'

# Native lib basename (de-suffixed, lowercased) -> endoflife.date product slug. Only libraries the
# API actually covers are mapped; an unmapped lib returns $null (no lifecycle note, no guess).
$script:TcpkEolProduct = @{
    'openssl' = 'openssl'; 'libcrypto' = 'openssl'; 'libssl' = 'openssl'
    'sqlite'  = 'sqlite';  'sqlite3'   = 'sqlite';  'e_sqlite3' = 'sqlite'; 'winsqlite3' = 'sqlite'
}

function Get-TcpkEolProduct {
    [CmdletBinding()] param([string]$Name)
    $n = "$Name".ToLowerInvariant() -replace '\.(dll|so|dylib)$','' -replace '-\d.*$','' -replace '_x64$|-x64$|-x86$|32$|64$',''
    if ($script:TcpkEolProduct.ContainsKey($n)) { return $script:TcpkEolProduct[$n] }
    return $null
}

# NETWORK (opt-in). Return the lifecycle picture for one native library, or $null if the product
# is not covered / the query fails (fail-open: currency is advisory, never blocks the audit).
# Fields: Product, Shipped, Branch, BranchLatest, BranchEol (date or $null), LatestVersion,
#         LatestBranch, LtsBranch, LtsLatest, Status (eol|near-eol|outdated|current), EolInDays.
function Get-TcpkLibLifecycle {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string]$Version, [int]$TimeoutSec = 20, [int]$NearEolDays = 120)
    $slug = Get-TcpkEolProduct $Name; if (-not $slug) { return $null }
    $ver = "$Version"; if ($ver -notmatch '^\d+\.\d+') { return $null }
    $cycles = $null
    try { $cycles = Invoke-RestMethod -Uri "$script:TcpkEolApi/$slug.json" -TimeoutSec $TimeoutSec -ErrorAction Stop } catch {
        Write-Warning "endoflife.date lookup for $slug failed ($($_.Exception.Message)); skipping the currency note."
        return $null
    }
    $cycles = @($cycles); if (-not $cycles.Count) { return $null }

    # shipped branch = the cycle whose name prefixes the shipped version (3.0.21 -> cycle '3.0').
    $branch = $cycles | Where-Object { "$ver" -eq "$($_.cycle)" -or "$ver".StartsWith("$($_.cycle).") } |
              Sort-Object @{ E = { "$($_.cycle)".Length }; Descending = $true } | Select-Object -First 1

    $today = [datetime]::UtcNow.Date
    $parseEol = {
        param($c)
        if ($null -eq $c) { return $null }
        $e = $c.eol
        if ($e -is [bool]) { return $null }           # eol:false = still supported / no date
        if ("$e" -notmatch '^\d{4}-\d{2}-\d{2}') { return $null }
        try { return ([datetime]::ParseExact("$e".Substring(0,10), 'yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture)).Date } catch { return $null }
    }
    $branchEol = & $parseEol $branch
    # newest branch overall (endoflife lists newest first) and the current LTS.
    $latestCyc = $cycles[0]
    $ltsCyc    = $cycles | Where-Object { $_.lts -eq $true } | Select-Object -First 1

    # behind the latest patch of its own branch (e.g. sqlite 3.40.0 vs branch-latest 3.53.3), or a
    # newer branch exists entirely -> outdated even when the branch is not near EOL.
    $branchLatest = $(if ($branch) { "$($branch.latest)" } else { '' })
    $behindPatch  = ($branchLatest -and $ver -match '^\d+\.\d+' -and (Test-TcpkSemVerLt -A $ver -B $branchLatest))
    $newerBranch  = ($branch -and "$($branch.cycle)" -ne "$($latestCyc.cycle)")

    $status = 'current'; $eolInDays = $null
    if ($branchEol) { $eolInDays = [int]([math]::Floor(($branchEol - $today).TotalDays)) }
    if     ($branchEol -and $branchEol -lt $today)                 { $status = 'eol' }
    elseif ($null -ne $eolInDays -and $eolInDays -le $NearEolDays) { $status = 'near-eol' }
    elseif ($behindPatch -or $newerBranch)                        { $status = 'outdated' }

    [pscustomobject]@{
        Product = $slug; Shipped = $ver
        Branch = $(if ($branch) { "$($branch.cycle)" } else { $null })
        BranchLatest = $(if ($branch) { "$($branch.latest)" } else { $null })
        BranchEol = $(if ($branchEol) { $branchEol.ToString('yyyy-MM-dd') } else { $null })
        EolInDays = $eolInDays
        LatestVersion = "$($latestCyc.latest)"; LatestBranch = "$($latestCyc.cycle)"
        LtsBranch = $(if ($ltsCyc) { "$($ltsCyc.cycle)" } else { $null })
        LtsLatest = $(if ($ltsCyc) { "$($ltsCyc.latest)" } else { $null })
        Status = $status
    }
}

# Pretty product names for findings (fallback = the slug).
$script:TcpkEolDisplay = @{ 'openssl' = 'OpenSSL'; 'sqlite' = 'SQLite' }

# NETWORK (opt-in). Enumerate shipped native libs under $Path, look up each one's lifecycle, and
# emit a finding when it is NOT on the latest supported release. This is the currency answer that
# CVE matching cannot give: "0 known CVEs" is not "up to date". The fix points at the LATEST
# supported version (and the current LTS), never at the historical CVE fix-in version.
function Get-TcpkLibraryCurrency {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path, [switch]$IncludeCurrent)
    $dir = $Path
    try { if (-not (Get-Item -LiteralPath $Path).PSIsContainer) { $dir = Expand-TcpkMsix -Path $Path } } catch { }
    $seen = @{}
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($p in (Get-ChildItem -LiteralPath $dir -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.Extension -in '.dll', '.exe' })) {
        $prod = Get-TcpkEolProduct $p.Name; if (-not $prod) { continue }
        $fv = $null; try { $fv = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($p.FullName).FileVersion } catch { }
        if (-not $fv -or $fv -notmatch '^\d+\.\d+') { continue }
        $ver = (($fv -split '[.,]') | Select-Object -First 3) -join '.'
        $key = "$prod|$ver"; if ($seen.ContainsKey($key)) { continue }; $seen[$key] = $true
        $life = Get-TcpkLibLifecycle -Name $p.Name -Version $ver; if (-not $life) { continue }
        if ($life.Status -eq 'current' -and -not $IncludeCurrent) { continue }

        $disp = if ($script:TcpkEolDisplay.ContainsKey($prod)) { $script:TcpkEolDisplay[$prod] } else { $prod }
        $ltsTxt = if ($life.LtsLatest) { " or the current LTS $($life.LtsLatest) (branch $($life.LtsBranch))" } else { '' }
        $evidence = "shipped $ver; branch $($life.Branch) (latest patch $($life.BranchLatest)); " +
                    "branch EOL $(if ($life.BranchEol) { $life.BranchEol } else { 'n/a' }); " +
                    "newest release $($life.LatestVersion) (branch $($life.LatestBranch))" +
                    $(if ($life.LtsLatest) { "; current LTS $($life.LtsLatest) (branch $($life.LtsBranch))" } else { '' })
        $desc = "Zero known CVEs is not the same as up to date. $disp $ver has no open CVE today, but it is not on the latest supported release, so it will stop receiving security fixes and may be exposed to future CVEs before you notice."

        switch ($life.Status) {
            'eol' {
                $sev = 'MEDIUM'; $rule = 'nativelib.eol-branch'
                $title = "$disp $ver is on branch $($life.Branch), which is END-OF-LIFE ($($life.BranchEol)) -- no further security fixes"
            }
            'near-eol' {
                $sev = 'LOW'; $rule = 'nativelib.near-eol'
                $title = "$disp $ver branch $($life.Branch) nears end-of-life ($($life.BranchEol), $($life.EolInDays) days); latest is $($life.LatestVersion)"
            }
            default {
                $sev = 'INFO'; $rule = 'nativelib.outdated'
                $title = "$disp $ver is behind the latest release ($($life.LatestVersion))"
            }
        }
        $fix = "Upgrade $disp to the latest supported release $($life.LatestVersion)$ltsTxt. This is a version-currency issue, not a known CVE -- do NOT treat an old CVE fix-in version as the target; move to a supported branch" +
               $(if ($life.BranchEol) { " before $($life.BranchEol)." } else { '.' })
        $out.Add( (New-TcpkFinding -Module 'static' -RuleId $rule -Severity $sev -Confidence 'Confirmed' `
            -Title $title -File $p.Name -Evidence $evidence -Cwe @('CWE-1104') -Description $desc -Fix $fix) )
    }
    return @($out.ToArray())
}
