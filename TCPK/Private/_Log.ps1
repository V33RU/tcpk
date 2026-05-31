# Structured run-log sink. Captures every audit step with a level, component,
# message, and duration so the GUI 'Logs / Runtime' tab can show a verbose,
# colour-coded, timed trace + runtime analysis. Written to run.jsonl + run.log.

$script:TcpkRunLog = New-Object 'System.Collections.Generic.List[object]'

function Clear-TcpkRunLog {
    [CmdletBinding()] param()
    $script:TcpkRunLog.Clear()
}

function Write-TcpkLog {
    [CmdletBinding()]
    param(
        [ValidateSet('DEBUG','INFO','SUCCESS','WARN','ERROR')][string]$Level = 'INFO',
        [string]$Component = '',
        [string]$Message = '',
        [int]$DurationMs = -1
    )
    $now = Get-Date
    $entry = [pscustomobject]@{
        ts         = $now.ToUniversalTime().ToString('o')
        time       = $now.ToString('HH:mm:ss.fff')
        level      = $Level
        component  = $Component
        message    = $Message
        durationMs = $DurationMs
    }
    $script:TcpkRunLog.Add($entry)
    # Mirror to the Information stream (tagged) so a live consumer could route it.
    Write-Information -InformationAction Continue -MessageData ("LOGX`t{0}`t{1}`t{2}`t{3}`t{4}" -f $entry.time, $Level, $Component, $DurationMs, $Message)
    $entry
}

function Get-TcpkRunLog {
    [CmdletBinding()] param()
    , $script:TcpkRunLog.ToArray()
}

function Save-TcpkRunLog {
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Dir)
    if (-not (Test-Path -LiteralPath $Dir)) { New-Item -ItemType Directory -Path $Dir -Force | Out-Null }

    # JSONL -- one compact JSON object per line (avoids the PS 5.1 array-parse quirk on read).
    $jsonlPath = Join-Path $Dir 'run.jsonl'
    $lines = foreach ($e in $script:TcpkRunLog) { $e | ConvertTo-Json -Compress -Depth 4 }
    Set-Content -LiteralPath $jsonlPath -Value ($lines -join "`n") -Encoding UTF8

    # Human-readable text log.
    $txtPath = Join-Path $Dir 'run.log'
    $txt = foreach ($e in $script:TcpkRunLog) {
        $dur = if ($e.durationMs -ge 0) { "  ({0}ms)" -f $e.durationMs } else { '' }
        "{0}  {1,-7} {2,-34} {3}{4}" -f $e.time, $e.level, $e.component, $e.message, $dur
    }
    Set-Content -LiteralPath $txtPath -Value $txt -Encoding UTF8
}
