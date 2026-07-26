function Test-TcpkWindowMessages {
<#
.SYNOPSIS
    E12b. Window-message attack surface (WM_COPYDATA injection + drop-files).

.DESCRIPTION
    For each top-level window owned by the target process, probes:
      1. WS_EX_ACCEPTFILES -- the window accepts drag-and-drop (DragAcceptFiles /
         WM_DROPFILES). An attacker in the same session can synthesize drop events.
      2. WM_COPYDATA       -- sends a benign zero-length COPYDATASTRUCT. If the
         send succeeds (returns non-zero), the window processes cross-process
         data without UIPI rejection. Attacker-controlled payload reaches the
         handler, which often trusts the content.
      3. ChangeWindowMessageFilter / ChangeWindowMessageFilterEx -- if the
         target lowered UIPI for specific messages, cross-integrity injection
         becomes possible. Detected via static callsite scan (already covered
         by callsites.uac-bypass-registry).

    Read-only probes. The WM_COPYDATA payload is empty (cbData=0, lpData=NULL).

.PARAMETER ProcessName
    Running process name (no .exe suffix).

.PARAMETER ProcessId
    Running process ID.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ParameterSetName='ByName')][string]$ProcessName,
        [Parameter(Mandatory, ParameterSetName='ById')][int]$ProcessId
    )

    if (-not (Assert-TcpkWindows 'Test-TcpkWindowMessages')) { return }
    $procs = if ($PSCmdlet.ParameterSetName -eq 'ByName') {
        Get-TcpkProcess -ProcessName $ProcessName
    } else {
        Get-TcpkProcess -ProcessId $ProcessId
    }
    if (-not $procs) { return }

    if (-not ('TCPK.WinMsg' -as [type])) {
        Add-Type -Namespace TCPK -Name WinMsg -MemberDefinition @'
[DllImport("user32.dll")] public static extern bool EnumWindows(EnumWndProc cb, System.IntPtr p);
[DllImport("user32.dll")] public static extern int GetWindowThreadProcessId(System.IntPtr h, out int pid);
[DllImport("user32.dll", CharSet=System.Runtime.InteropServices.CharSet.Unicode)]
public static extern int GetWindowText(System.IntPtr h, System.Text.StringBuilder sb, int n);
[DllImport("user32.dll", CharSet=System.Runtime.InteropServices.CharSet.Unicode)]
public static extern int GetClassName(System.IntPtr h, System.Text.StringBuilder sb, int n);
[DllImport("user32.dll")] public static extern int GetWindowLong(System.IntPtr h, int idx);
[DllImport("user32.dll", EntryPoint="SendMessageW")]
public static extern System.IntPtr SendMessage(System.IntPtr h, uint msg, System.IntPtr w, System.IntPtr l);
[DllImport("user32.dll")] public static extern bool IsWindowVisible(System.IntPtr h);

public delegate bool EnumWndProc(System.IntPtr h, System.IntPtr p);

// COPYDATASTRUCT for WM_COPYDATA (0x004A)
[System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
public struct COPYDATASTRUCT { public System.IntPtr dwData; public int cbData; public System.IntPtr lpData; }

public const int GWL_EXSTYLE = -20;
public const int WS_EX_ACCEPTFILES = 0x10;
public const uint WM_COPYDATA = 0x004A;

public static System.IntPtr SendCopyData(System.IntPtr hwnd) {
    var cds = new COPYDATASTRUCT();
    cds.dwData = System.IntPtr.Zero;
    cds.cbData = 0;
    cds.lpData = System.IntPtr.Zero;
    var pin = System.Runtime.InteropServices.GCHandle.Alloc(cds, System.Runtime.InteropServices.GCHandleType.Pinned);
    try { return SendMessage(hwnd, WM_COPYDATA, System.IntPtr.Zero, pin.AddrOfPinnedObject()); }
    finally { pin.Free(); }
}
'@ -ErrorAction SilentlyContinue
    }

    $dropCount = 0; $copyCount = 0

    foreach ($p in $procs) {
        $targetPid = $p.Id
        $windows = New-Object 'System.Collections.Generic.List[object]'
        $callback = [TCPK.WinMsg+EnumWndProc] {
            param([IntPtr]$hWnd, [IntPtr]$lParam)
            $procId = 0
            [void][TCPK.WinMsg]::GetWindowThreadProcessId($hWnd, [ref]$procId)
            if ($procId -eq $targetPid) {
                $title = New-Object Text.StringBuilder 256
                [void][TCPK.WinMsg]::GetWindowText($hWnd, $title, 256)
                $cls = New-Object Text.StringBuilder 256
                [void][TCPK.WinMsg]::GetClassName($hWnd, $cls, 256)
                $exStyle = [TCPK.WinMsg]::GetWindowLong($hWnd, [TCPK.WinMsg]::GWL_EXSTYLE)
                $vis = [TCPK.WinMsg]::IsWindowVisible($hWnd)
                $windows.Add([pscustomobject]@{
                    HWnd=$hWnd; Title=$title.ToString(); Class=$cls.ToString()
                    ExStyle=$exStyle; Visible=$vis
                })
            }
            return $true
        }
        [void][TCPK.WinMsg]::EnumWindows($callback, [IntPtr]::Zero)

        foreach ($w in $windows) {
            if (-not $w.Title -and -not $w.Class) { continue }
            $label = "class='$($w.Class)' title='$($w.Title)'"

            # 1. WS_EX_ACCEPTFILES (drag-drop surface)
            if ($w.ExStyle -band [TCPK.WinMsg]::WS_EX_ACCEPTFILES) {
                $dropCount++
                New-TcpkFinding -Module 'runtime' -RuleId 'window.accepts-drop-files' `
                    -Severity 'MEDIUM' -Confidence 'Confirmed' `
                    -Title "Window accepts drag-and-drop files: $label" `
                    -File "$($p.Name) (PID $targetPid)" `
                    -Evidence "WS_EX_ACCEPTFILES set (ExStyle=0x$($w.ExStyle.ToString('X')))" `
                    -Cwe @('CWE-829') `
                    -Description 'The window has WS_EX_ACCEPTFILES set. An attacker process in the same user session can synthesize WM_DROPFILES messages to inject arbitrary file paths into the handler, potentially triggering file-open or file-processing logic with attacker-chosen content.' `
                    -Fix 'Validate dropped file paths against the expected working directory. If drag-drop is not required, remove DragAcceptFiles / WS_EX_ACCEPTFILES.'
            }

            # 2. WM_COPYDATA (cross-process data injection)
            try {
                $result = [TCPK.WinMsg]::SendCopyData($w.HWnd)
                if ($result -ne [IntPtr]::Zero) {
                    $copyCount++
                    New-TcpkFinding -Module 'runtime' -RuleId 'window.accepts-wm-copydata' `
                        -Severity 'HIGH' -Confidence 'Confirmed' `
                        -Title "Window accepts WM_COPYDATA: $label" `
                        -File "$($p.Name) (PID $targetPid)" `
                        -Evidence "SendMessage(WM_COPYDATA) returned $($result.ToInt64()) (non-zero = processed)" `
                        -Cwe @('CWE-20','CWE-345') `
                        -Description 'The window processed a cross-process WM_COPYDATA message. Any process in the same session (or across integrity levels if UIPI is lowered) can send arbitrary byte payloads to this handler. If the handler parses the payload without validation (command strings, file paths, serialized objects), this is a direct injection vector.' `
                        -Fix 'Validate the WM_COPYDATA sender via GetWindowThreadProcessId and reject unknown callers. Parse the payload defensively (length checks, type validation). If IPC is not required, do not handle WM_COPYDATA.'
                }
            } catch { }
        }
    }

    # summary
    $total = @($procs | ForEach-Object { $_.Id }).Count
    New-TcpkFinding -Module 'runtime' -RuleId 'window.message-summary' `
        -Severity 'INFO' -Confidence 'Confirmed' `
        -Title "Window message probe: $dropCount drop-file + $copyCount WM_COPYDATA accepting windows" `
        -File (($procs | ForEach-Object { "$($_.Name) (PID $($_.Id))" }) -join '; ') `
        -Evidence "processes=$total drop=$dropCount copydata=$copyCount"
}
