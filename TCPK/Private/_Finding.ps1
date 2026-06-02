# New-TcpkFinding - factory for [TCPK.Finding].
# Private. Used by every check cmdlet.

$script:TcpkSeverityRank = @{
    INFO     = 0
    LOW      = 1
    MEDIUM   = 2
    HIGH     = 3
    CRITICAL = 4
}

# Base confidence labels (deterministic checks) + the LLM-verifier labels.
# Invoke-TcpkLlmCodeJudgment writes the '(LLM)' variants, and findings round-trip
# through New-TcpkFinding when the GUI/report layer rebuilds them, so the factory
# must accept these too.
$script:TcpkValidConfidence = @('Confirmed','Inferred','Unverified','Skipped','Confirmed (LLM)','Likely-FP (LLM)','Uncertain (LLM)')

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

        [ValidateSet('Confirmed','Inferred','Unverified','Skipped','Confirmed (LLM)','Likely-FP (LLM)','Uncertain (LLM)')]
        [string] $Confidence = 'Confirmed',

        [string]   $Description,
        [string]   $File,
        [string]   $Evidence,
        [string[]] $Cwe = @(),
        [string]   $Impact,
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
    $f.Impact      = $Impact
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

# Representative CVSS v4.0 base score + vector per severity band (advisory; the
# analyst computes the exact vector per finding). TCPK standardized on CVSS v4.0
# only (v3.1 dropped). Returned as "score (Rating) CVSS:4.0/<vector>".
$script:TcpkCvssBand = @{
    CRITICAL = '9.3 (Critical) CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N'
    HIGH     = '8.7 (High) CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N'
    MEDIUM   = '6.3 (Medium) CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N'
    LOW      = '2.3 (Low) CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N'
    INFO     = 'N/A (Info)'
}
function Get-TcpkCvssBand {
    param([Parameter(Mandatory)][string]$Severity)
    if ($script:TcpkCvssBand.ContainsKey($Severity)) { return $script:TcpkCvssBand[$Severity] }
    return ''
}

# Per-finding impact: use the finding's explicit Impact if set, else a concise
# severity-derived default so every reported finding carries an impact statement.
$script:TcpkImpactBand = @{
    CRITICAL = 'Direct compromise: code execution, privilege escalation, or exposure of live credentials with little/no precondition.'
    HIGH     = 'Serious exposure: an attacker meeting a modest precondition can steal secrets, escalate, or bypass a security control.'
    MEDIUM   = 'Meaningful weakness that aids an attack chain or leaks sensitive information under some conditions.'
    LOW      = 'Minor hardening gap / information useful to an attacker; low standalone risk.'
    INFO     = 'Informational - triage context, not a vulnerability on its own.'
}
function Get-TcpkImpactText {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowNull()]$Finding)
    if ($Finding.Impact) { return $Finding.Impact }
    if ($Finding.Severity -and $script:TcpkImpactBand.ContainsKey($Finding.Severity)) { return $script:TcpkImpactBand[$Finding.Severity] }
    return ''
}
