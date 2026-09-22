# Severity colour for the terminal.
#
# WHY Write-Host AND NOT ANSI. Windows PowerShell 5.1 never enables
# ENABLE_VIRTUAL_TERMINAL_PROCESSING on the console host, and it has no $PSStyle. The same
# ESC[91m that renders red in Windows Terminal (which runs the client under ConPTY, where VT
# is already on) renders as literal "<-[91m" text in a conhost window launched from TCPK.bat,
# and never works at all in the ISE. Enabling VT ourselves through SetConsoleMode is possible
# but it changes console state for the whole process for the sake of a colour, and it still
# leaves escape bytes in anything the operator redirects to a file.
#
# Write-Host has none of that. The host applies the colour and the string stays clean.
#
# WHY THIS DOES NOT BREAK THE GUI OR THE WEB WORKBENCH. On 5.1 Write-Host is NOT a bypass:
# it writes an InformationRecord whose MessageData is a HostInformationMessage, and that
# type's ToString() returns the bare message. Both hosts capture the audit with 6>&1 and
# stringify with "$_" (Start-TCPKGui.ps1, _WebUi.ps1), so a Write-Host line round-trips to
# them byte-identically to a Write-Information line. The colour rides along out of band in
# MessageData.ForegroundColor, which they ignore; the GUI re-derives its own colour from the
# text. Background jobs report $Host.Name = 'ServerRemoteHost', so they take the plain branch
# here anyway and never even get the colour attached.
#
# THE ONE RULE: ONE Write-Host CALL PER COMPLETE LINE.
# Splitting a line across two calls (the "label then value" idiom) emits TWO
# InformationRecords, which both hosts receive as two separate log lines. Do that to a line a
# host parses and its progress bar stops matching, silently. That is the exact failure
# ConsoleOutput.Tests.ps1 exists to prevent. Build the whole line, then colour it once.

# ConsoleColor per severity. DarkYellow reads as orange on the default palettes and keeps
# HIGH distinct from MEDIUM, which a plain Yellow/Yellow pair would not.
$script:TcpkSevColour = @{
    CRITICAL = 'Red'
    HIGH     = 'DarkYellow'
    MEDIUM   = 'Yellow'
    LOW      = 'Cyan'
    INFO     = 'DarkGray'
}

# Confidence splits three ways: proven, unproven, and argued-down. The ladder has 13 labels
# (see $script:TcpkValidConfidence in _Finding.ps1) and they group cleanly by prefix.
$script:TcpkConfColour = @{
    Proven   = 'Green'
    Unproven = 'Gray'
    Demoted  = 'DarkGray'
}

# Local severity rank. Deliberately NOT Get-TcpkSeverityRank: that one declares
# [Parameter(Mandatory)][string]$Severity, so an empty Severity throws at parameter binding
# and never reaches its own "return -1" fallback. Findings rebuilt from findings.json can
# carry '' when a row is malformed, and a display helper must never be the thing that throws.
$script:TcpkSevOrder = @{ CRITICAL = 4; HIGH = 3; MEDIUM = 2; LOW = 1; INFO = 0 }

function Get-TcpkSevOrder {
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyString()][string]$Severity)
    $s = "$Severity".ToUpperInvariant()
    if ($script:TcpkSevOrder.ContainsKey($s)) { return $script:TcpkSevOrder[$s] }
    return -1
}

# Can this host actually paint? Three ways to answer no, and all three must be checked:
#   - a background job / remote runspace reports 'ServerRemoteHost'
#   - the ISE and any embedded host are not ConsoleHost
#   - stdout redirected to a file or a pipe means the colour is meaningless and the caller
#     wants plain text (this is also what keeps the MCP server's JSON-RPC transport clean)
function Test-TcpkCanColour {
    [CmdletBinding()] param()
    if ($env:TCPK_NO_COLOR) { return $false }
    $hostName = ''
    try { $hostName = "$($Host.Name)" } catch { return $false }
    if ($hostName -ne 'ConsoleHost') { return $false }
    try { if ([Console]::IsOutputRedirected) { return $false } } catch { }
    return $true
}

function Get-TcpkSeverityColour {
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyString()][string]$Severity)
    $s = "$Severity".ToUpperInvariant()
    if ($script:TcpkSevColour.ContainsKey($s)) { return $script:TcpkSevColour[$s] }
    return 'Gray'
}

function Get-TcpkConfidenceColour {
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyString()][string]$Confidence)
    $c = "$Confidence"
    if ($c.StartsWith('Confirmed', [StringComparison]::OrdinalIgnoreCase)) { return $script:TcpkConfColour.Proven }
    if ($c.StartsWith('Likely-FP', [StringComparison]::OrdinalIgnoreCase) -or
        $c.StartsWith('Uncertain', [StringComparison]::OrdinalIgnoreCase)) { return $script:TcpkConfColour.Demoted }
    return $script:TcpkConfColour.Unproven
}

# Append a label/value row only when the value has content. This is the whole mechanism for
# "stop printing ten blank rows": the caller lists every field it might show and this drops
# the ones that are empty, so a finding that populates six fields prints six rows.
function _TcpkAddRow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)][object]$Rows,
        [Parameter(Mandatory, Position = 1)][string]$Label,
        [Parameter(Position = 2)][AllowNull()][AllowEmptyString()][string]$Value
    )
    if ([string]::IsNullOrWhiteSpace($Value)) { return }
    $Rows.Add([pscustomobject]@{ Label = $Label; Value = $Value })
}

# Emit one COMPLETE line, coloured when the host can take it and plain when it cannot.
# Never call this twice to build a single visual line; see the rule at the top of this file.
function Write-TcpkColourLine {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Line,
        [string]$Colour = ''
    )
    if ($Colour -and (Test-TcpkCanColour)) {
        try {
            Write-Host $Line -ForegroundColor $Colour
            return
        } catch { }
    }
    Write-Host $Line
}
