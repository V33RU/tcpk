function Test-TcpkUiDataExposure {
<#
.SYNOPSIS
    E25. Sensitive values surfaced through the UI, and capture hardware the application can
    reach.

.DESCRIPTION
    Two questions about what the interface gives away, one live and one static.

    WINDOW TITLES. Test-TcpkWindowEnumeration already reads every top-level caption and
    emits it verbatim, but nothing has ever compared those captions against the secret rules
    the rest of the tool uses. A caption is the single least private string a process owns:
    any process in the session can read it with GetWindowText without any privilege at all,
    it appears in Alt-Tab and the taskbar, screen-sharing and recording software captures it
    by default, and it is written into crash and telemetry reports. A token, key or
    connection string in a title is readable by software that has no other access to the
    application.

    CAPTURE HARDWARE. Whether the binaries reference camera or microphone APIs. This is
    scope, not a defect: an application that can capture is one where an indicator, a
    consent prompt and a visible in-use state matter, and one where they do not exist is
    worth looking at. Whether an indicator is actually shown needs a driven scenario and is
    not claimed here.

    Rules:
      ui.secret-in-window-title   HIGH  A live window caption matches a secret rule.
      ui.capture-api-referenced   INFO  Camera or microphone capture APIs are referenced.

    The title check needs a running process. The capture check needs a path. Each half runs
    only if given what it needs, and neither reports the other's absence as a result.

.PARAMETER ProcessName
    Running process name (no .exe) whose window captions are read.

.PARAMETER Path
    Install directory, for the capture-API half.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param(
        [string]$ProcessName,
        [string]$Path
    )

    if (-not (Assert-TcpkWindows 'Test-TcpkUiDataExposure')) { return }

    # ---- live window captions vs the secret rules ----------------------------
    if ($ProcessName) {
        $procs = @(Get-Process -Name ($ProcessName -replace '\.exe$', '') -ErrorAction SilentlyContinue)
        if ($procs.Count -and ('TCPK.Win32' -as [type])) {
            $rules = $null
            try { $rules = Get-TcpkSecretRegexRules } catch { $rules = $null }
            # Same placeholder guard the other secret consumers use, so a caption reading
            # "Enter your API key" is not reported as an exposed API key.
            $placeholder = '(?i)(<[a-z_ ]{2,}>|\bplaceholder\b|\bexample\b|\byour[-_ ]|\bchange[-_ ]?me\b|\bdummy\b|\bsample\b|\bredacted\b|x{6,}|\.\.\.|\*{4,}|\benter\b|\bpaste\b)'

            if ($rules) {
                foreach ($p in $procs) {
                    $targetPid = $p.Id
                    $titles = New-Object 'System.Collections.Generic.List[string]'
                    $callback = [TCPK.Win32+EnumWindowsProc] {
                        param([IntPtr]$hWnd, [IntPtr]$lParam)
                        $procId = 0
                        [void][TCPK.Win32]::GetWindowThreadProcessId($hWnd, [ref]$procId)
                        if ($procId -eq $targetPid) {
                            $t = New-Object Text.StringBuilder 256
                            [void][TCPK.Win32]::GetWindowText($hWnd, $t, 256)
                            $s = $t.ToString()
                            if ($s -and $s.Length -ge 8) { $titles.Add($s) }
                        }
                        return $true
                    }
                    try { [void][TCPK.Win32]::EnumWindows($callback, [IntPtr]::Zero) } catch { }

                    foreach ($title in ($titles | Select-Object -Unique)) {
                        if ($title -match $placeholder) { continue }
                        foreach ($r in $rules) {
                            $rx = $null
                            try { $rx = $r._RX } catch { $rx = $null }
                            if (-not $rx) { continue }
                            $mm = $null
                            try { $mm = $rx.Match($title) } catch { continue }
                            if (-not $mm -or -not $mm.Success) { continue }

                            $sample = $mm.Value
                            if ($sample.Length -gt 12) {
                                $sample = $sample.Substring(0, 4) + '***' + $sample.Substring($sample.Length - 3, 3)
                            }
                            New-TcpkFinding -Module 'runtime' -RuleId 'ui.secret-in-window-title' `
                                -Severity 'HIGH' -Confidence 'Confirmed (dynamic)' `
                                -Title "Secret-shaped value in a window caption of $($p.Name)" `
                                -File "$($p.Name) (PID $($p.Id))" `
                                -Evidence ("rule=$($r.name); sample=$sample") `
                                -Cwe @('CWE-200', 'CWE-497') `
                                -Description ('A window caption matched a secret rule. A caption is the ' +
                                    'least protected string a process owns: any process in the same ' +
                                    'session reads it with GetWindowText and no privilege, it is shown in ' +
                                    'Alt-Tab and the taskbar, screen recording and conferencing software ' +
                                    'captures it by default, and it is copied into crash and telemetry ' +
                                    'reports. Anything here should be treated as already disclosed to ' +
                                    'every other program running as this user.') `
                                -Fix 'Keep credentials, tokens and connection strings out of window titles, including document titles built from a connection string or a URL carrying a key. Show a name or an identifier instead and hold the secret only in memory the UI does not render.'
                            break
                        }
                    }
                }
            }
        }
    }

    # ---- static: capture hardware the app can reach --------------------------
    if ($Path -and (Test-Path -LiteralPath $Path)) {
        $capture = @{
            'MediaCapture'      = 'camera/microphone (WinRT MediaCapture)'
            'avicap32'          = 'camera (legacy AVICap)'
            'IMFSourceReader'   = 'camera (Media Foundation)'
            'VideoCaptureDevice'= 'camera (DirectShow wrapper)'
            'waveInOpen'        = 'microphone (waveIn)'
            'IAudioClient'      = 'microphone (WASAPI)'
            'AudioGraph'        = 'microphone (WinRT AudioGraph)'
            'getUserMedia'      = 'camera/microphone (web content)'
            'desktopCapturer'   = 'screen capture (Electron)'
        }
        $found = New-Object 'System.Collections.Generic.List[string]'
        foreach ($pe in Get-TcpkPeFiles -Path $Path) {
            if (Test-TcpkIsFrameworkFile $pe.Name) { continue }
            $text = ''
            try { $text = Read-TcpkAllText -Path $pe.FullName } catch { $text = '' }
            if (-not $text) { continue }
            foreach ($k in $capture.Keys) {
                if ($text.Contains($k) -and -not $found.Contains($capture[$k])) { $found.Add($capture[$k]) }
            }
            if ($found.Count -ge 5) { break }
        }

        if ($found.Count) {
            New-TcpkFinding -Module 'runtime' -RuleId 'ui.capture-api-referenced' `
                -Severity 'INFO' -Confidence 'Confirmed' `
                -Title "Application can reach capture hardware: $(($found | Select-Object -Unique) -join ', ')" `
                -File $Path -Evidence (($found | Select-Object -Unique) -join '; ') `
                -Cwe @('CWE-359') `
                -Description ('The shipped binaries reference camera, microphone or screen-capture APIs. ' +
                    'This is scope rather than a defect: it says the product belongs in the category ' +
                    'where a visible in-use indicator, a consent prompt before first use, and a way for ' +
                    'the user to see and revoke access all matter. Whether those exist is a question for ' +
                    'a driven session with the app running and is not answered here.') `
                -Fix 'Confirm capture only starts after explicit consent, that an indicator is visible for as long as it runs, and that the app degrades cleanly when the user denies or revokes access rather than retrying silently.'
        }
    }
}
