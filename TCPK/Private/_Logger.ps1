# Lightweight logger for in-progress audit output.
# Uses PowerShell's Information stream so callers can suppress with
# -InformationAction SilentlyContinue.

function Write-TcpkInfo {
    [CmdletBinding()] param([Parameter(Mandatory, Position=0)][string]$Message)
    Write-Information -MessageData "[TCPK] $Message" -InformationAction Continue
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
