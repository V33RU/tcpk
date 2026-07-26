function Test-TcpkClipboardSecrets {
<#
.SYNOPSIS
    I05. Clipboard secret monitoring during a test session.

.DESCRIPTION
    Polls the Windows clipboard at a configurable interval for DurationSec
    seconds, applying the secrets.json regex rules to each text snapshot.
    Catches sensitive data that the target application places on the clipboard:
    passwords, API keys, connection strings, bearer tokens, etc.

    Non-modifying: reads the clipboard but never writes to it.
    Requires the calling shell to be STA (WinForms Clipboard API).
    Run this in one console while exercising the target in another.

.PARAMETER DurationSec
    How long to monitor (default 30 seconds).

.PARAMETER IntervalMs
    Polling interval in milliseconds (default 500).

.PARAMETER ProcessName
    Optional: only report if the foreground window belongs to this process
    when the clipboard changes (best-effort attribution).

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param(
        [int]$DurationSec = 30,
        [int]$IntervalMs  = 500,
        [string]$ProcessName
    )

    if (-not (Assert-TcpkWindows 'Test-TcpkClipboardSecrets')) { return }

    # WinForms clipboard needs STA; Add-Type for foreground-window attribution
    Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
    if (-not ('TCPK.ClipMon' -as [type])) {
        Add-Type -Namespace TCPK -Name ClipMon -MemberDefinition @'
[DllImport("user32.dll")] public static extern System.IntPtr GetForegroundWindow();
[DllImport("user32.dll")] public static extern int GetWindowThreadProcessId(System.IntPtr h, out int pid);
[DllImport("user32.dll")] public static extern int GetClipboardSequenceNumber();
'@ -ErrorAction SilentlyContinue
    }

    $rules = Get-TcpkSecretRegexRules
    $placeholder = '(?i)(&lt|&gt|&amp|<[a-z_ ]{2,}>|\bsnipped\b|\bplaceholder\b|\bexample\b|\byour[-_ ]|\bchange[-_ ]?me\b|\bdummy\b|\bsample\b|\bredacted\b|x{6,}|\.\.\.|\*{4,})'
    $seen = @{}
    $emitted = 0
    $snapshots = 0
    $lastSeq = -1

    try { $lastSeq = [TCPK.ClipMon]::GetClipboardSequenceNumber() } catch { }

    $deadline = (Get-Date).AddSeconds($DurationSec)
    Write-Information "[TCPK] Clipboard monitoring for ${DurationSec}s (Ctrl+C to stop early)..." -Tags 'TCPK'

    while ((Get-Date) -lt $deadline -and $emitted -lt 30) {
        Start-Sleep -Milliseconds $IntervalMs

        # check if clipboard changed
        $curSeq = 0
        try { $curSeq = [TCPK.ClipMon]::GetClipboardSequenceNumber() } catch { }
        if ($curSeq -eq $lastSeq -and $lastSeq -gt 0) { continue }
        $lastSeq = $curSeq

        $text = $null
        try {
            if ([System.Windows.Forms.Clipboard]::ContainsText()) {
                $text = [System.Windows.Forms.Clipboard]::GetText()
            }
        } catch { continue }
        if (-not $text -or $text.Length -lt 4) { continue }
        $snapshots++

        # optional foreground-process attribution
        $fgProc = ''
        try {
            $fgWnd = [TCPK.ClipMon]::GetForegroundWindow()
            if ($fgWnd -ne [IntPtr]::Zero) {
                $fgPid = 0
                [void][TCPK.ClipMon]::GetWindowThreadProcessId($fgWnd, [ref]$fgPid)
                if ($fgPid -gt 0) {
                    $pp = Get-Process -Id $fgPid -ErrorAction SilentlyContinue
                    if ($pp) { $fgProc = $pp.ProcessName }
                }
            }
        } catch { }

        if ($ProcessName -and $fgProc -and $fgProc -ne $ProcessName) { continue }

        foreach ($r in $rules) {
            foreach ($m in $r._RX.Matches($text)) {
                $val = $m.Value
                if ($val.Length -lt 6)       { continue }
                if ($val -match $placeholder) { continue }

                $key = "$($r.id)::$($val.Substring(0, [Math]::Min(40, $val.Length)))"
                if ($seen.ContainsKey($key)) { continue }
                $seen[$key] = $true

                $masked = if ($val.Length -gt 12) { $val.Substring(0, 6) + '***' + $val.Substring($val.Length - 3) } else { $val.Substring(0, 3) + '***' }
                $src = if ($fgProc) { " (fg=$fgProc)" } else { '' }
                $emitted++
                New-TcpkFinding -Module 'memory' -RuleId 'clipboard.secret-found' `
                    -Severity 'HIGH' -Confidence 'Confirmed' `
                    -Title "Clipboard contains $($r.id): $masked$src" `
                    -File "clipboard (seq $curSeq)" `
                    -Evidence "rule=$($r.id) length=$($val.Length) masked=$masked foreground=$fgProc" `
                    -Cwe @('CWE-200','CWE-312') `
                    -Description "The clipboard contained data matching the '$($r.id)' secret pattern. Sensitive data on the clipboard is readable by any process in the same user session and persists until overwritten. Clipboard history (Win+V) may retain it indefinitely." `
                    -Fix 'Do not place secrets on the clipboard. If copy is required, use a self-clearing clipboard write (clear after a timeout). Set the ExcludeClipboardContentFromMonitorProcessing flag on the clipboard data format.'
                if ($emitted -ge 30) { break }
            }
            if ($emitted -ge 30) { break }
        }
    }

    New-TcpkFinding -Module 'memory' -RuleId 'clipboard.scan-summary' `
        -Severity 'INFO' -Confidence 'Confirmed' `
        -Title "Clipboard monitor: $snapshots changes captured, $emitted secrets found in ${DurationSec}s" `
        -File 'clipboard' `
        -Evidence "duration=${DurationSec}s snapshots=$snapshots secrets=$emitted$(if ($ProcessName) { " filter=$ProcessName" })"
}
