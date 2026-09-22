# Lightweight logger for in-progress audit output.
# Uses PowerShell's Information stream so callers can suppress with
# -InformationAction SilentlyContinue.

function Write-TcpkInfo {
    [CmdletBinding()] param([Parameter(Mandatory, Position=0)][string]$Message)
    Write-Information -MessageData "[TCPK] $Message" -InformationAction Continue
}

# Render an elapsed time at a resolution the operator can actually act on.
#
# The per-check line used to print ([int]$sw.Elapsed.TotalSeconds), so every check finishing
# in under half a second read "(   0s)" -- which is most of them -- while the real figure
# existed only as an unlabelled integer on the machine-format LOGX line the console was also
# printing. One line showed a useless duration, the other the useful one with no units.
#
# [math]::Floor for the minutes, NOT [int]: [int] on a double is Convert.ToInt32, which
# rounds to nearest, so 521s would render "9m41s" instead of "8m41s".
function Format-TcpkElapsed {
    [CmdletBinding()]
    param([Parameter(Mandatory)][TimeSpan]$Elapsed)
    $ms = $Elapsed.TotalMilliseconds
    if ($ms -lt 1000)  { return ("{0}ms" -f [int]$ms) }
    if ($ms -lt 60000) { return ("{0:0.0}s" -f $Elapsed.TotalSeconds) }
    return ("{0}m{1:00}s" -f [math]::Floor($Elapsed.TotalMinutes), $Elapsed.Seconds)
}

# Per-check severity tally, rendered "C1 H3 M12 L20 I11" with empty buckets omitted.
#
# A bare count is not triage information. 47 findings that are all INFO and one finding that
# is CRITICAL occupy the same column and read with the same weight, and until now the only
# severity view in the whole run was the end-of-run breakdown -- which arrives after every
# decision the operator would have made while watching the scan.
#
# INFO is counted deliberately. It is the most-emitted severity in the ruleset, so dropping
# it would make the tally visibly disagree with the count printed beside it.
function Get-TcpkSeverityTally {
    [CmdletBinding()]
    param([AllowNull()][object[]]$Findings)
    if (-not $Findings) { return '' }
    $n = @{ CRITICAL = 0; HIGH = 0; MEDIUM = 0; LOW = 0; INFO = 0 }
    foreach ($f in $Findings) {
        if (-not $f) { continue }
        $s = "$($f.Severity)"
        if ($n.ContainsKey($s)) { $n[$s] = $n[$s] + 1 }
    }
    $parts = New-Object 'System.Collections.Generic.List[string]'
    foreach ($p in @(@('C', 'CRITICAL'), @('H', 'HIGH'), @('M', 'MEDIUM'), @('L', 'LOW'), @('I', 'INFO'))) {
        if ($n[$p[1]] -gt 0) { $parts.Add(("{0}{1}" -f $p[0], $n[$p[1]])) }
    }
    return ($parts -join ' ')
}

function Write-TcpkStep {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position=0)][string]$Name,
        [Parameter(Position=1)][int]$Count
    )
    if ($PSBoundParameters.ContainsKey('Count')) {
        $msg = "{0,-40} {1,4} findings" -f $Name, $Count
    } else {
        $msg = "{0,-40}      (running)" -f $Name
    }
    Write-Information -MessageData "  $msg" -InformationAction Continue
}

function Write-TcpkBanner {
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Target)
    @"
TCPK -- Thick Client Pentest Kit
-----------------------------------------------------------
DISCLAIMER: For AUTHORIZED security testing only. By proceeding you
confirm you have explicit written authorization to test the named
target. ANY MISUSE IS SOLELY YOUR RESPONSIBILITY -- the author(s) and
community accept NO liability for misuse or damage. Provided "AS IS",
no warranty. See DISCLAIMER.txt. If you do not agree, stop now.
-----------------------------------------------------------

Target: $Target
PowerShell: $(Get-TcpkPsVersion)  Elevated: $(Test-TcpkIsAdmin)
"@ | ForEach-Object { Write-Information -MessageData $_ -InformationAction Continue }
}
