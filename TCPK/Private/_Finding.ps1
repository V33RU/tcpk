# New-TcpkFinding - factory for [TCPK.Finding].
# Private. Used by every check cmdlet.

$script:TcpkSeverityRank = @{
    INFO     = 0
    LOW      = 1
    MEDIUM   = 2
    HIGH     = 3
    CRITICAL = 4
}

$script:TcpkValidConfidence = @('Confirmed','Inferred','Unverified','Skipped')

function New-TcpkFinding {
    [CmdletBinding()]
    [OutputType([TcpkFinding])]
    param(
        [Parameter(Mandatory)][string] $Module,
        [Parameter(Mandatory)][string] $RuleId,
        [Parameter(Mandatory)]
        [ValidateSet('INFO','LOW','MEDIUM','HIGH','CRITICAL')]
        [string] $Severity,
        [Parameter(Mandatory)][string] $Title,

        [ValidateSet('Confirmed','Inferred','Unverified','Skipped')]
        [string] $Confidence = 'Confirmed',

        [string]   $Description,
        [string]   $File,
        [string]   $Evidence,
        [string[]] $Cwe = @(),
        [string]   $Fix
    )

    $f = [TcpkFinding]::new()
    $f.Module      = $Module
    $f.RuleId      = $RuleId
    $f.Severity    = $Severity
    $f.Confidence  = $Confidence
    $f.Title       = $Title
    $f.Description = $Description
    $f.File        = $File
    $f.Evidence    = $Evidence
    $f.Cwe         = $Cwe
    $f.Fix         = $Fix
    $f.Timestamp   = (Get-Date).ToUniversalTime().ToString('o')
    return $f
}

function Get-TcpkSeverityRank {
    param([Parameter(Mandatory)][string]$Severity)
    if ($script:TcpkSeverityRank.ContainsKey($Severity)) {
        return $script:TcpkSeverityRank[$Severity]
    }
    return -1
}

# Representative CVSS v3.1 base score per severity band (advisory; the analyst
# should compute an exact vector per finding). Returned as "score (rating)".
$script:TcpkCvssBand = @{
    CRITICAL = '9.8 (Critical)'
    HIGH     = '7.5 (High)'
    MEDIUM   = '5.3 (Medium)'
    LOW      = '3.1 (Low)'
    INFO     = '0.0 (Info)'
}
function Get-TcpkCvssBand {
    param([Parameter(Mandatory)][string]$Severity)
    if ($script:TcpkCvssBand.ContainsKey($Severity)) { return $script:TcpkCvssBand[$Severity] }
    return ''
}
