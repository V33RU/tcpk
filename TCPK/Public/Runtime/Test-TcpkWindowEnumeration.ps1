function Test-TcpkWindowEnumeration {
<#
.SYNOPSIS
    E12. Top-level windows owned by the process (Shatter / UIA surface).

.DESCRIPTION
    Uses EnumWindows / GetWindowThreadProcessId via Add-Type to list every
    top-level window owned by the target. Each window with non-empty Class
    or Title is an attacker-input surface (window-message injection,
    UI-automation cross-priv).

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ParameterSetName='ByName')][string]$ProcessName,
        [Parameter(Mandatory, ParameterSetName='ById')][int]$ProcessId
    )

    if (-not (Assert-TcpkWindows 'Test-TcpkWindowEnumeration')) { return }
    $procs = if ($PSCmdlet.ParameterSetName -eq 'ByName') {
        Get-TcpkProcess -ProcessName $ProcessName
    } else {
        Get-TcpkProcess -ProcessId $ProcessId
    }
    if (-not $procs) { return }

    if (-not ('TCPK.Win32' -as [type])) {
        Add-Type -Namespace TCPK -Name Win32 -MemberDefinition @'
[DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, System.IntPtr lParam);
[DllImport("user32.dll")] public static extern int GetWindowThreadProcessId(System.IntPtr hWnd, out int lpdwProcessId);
[DllImport("user32.dll", CharSet=System.Runtime.InteropServices.CharSet.Unicode)] public static extern int GetWindowText(System.IntPtr hWnd, System.Text.StringBuilder lpString, int nMaxCount);
[DllImport("user32.dll", CharSet=System.Runtime.InteropServices.CharSet.Unicode)] public static extern int GetClassName(System.IntPtr hWnd, System.Text.StringBuilder lpClassName, int nMaxCount);
public delegate bool EnumWindowsProc(System.IntPtr hWnd, System.IntPtr lParam);
'@ -ErrorAction SilentlyContinue
    }

    foreach ($p in $procs) {
        # Use $targetPid -- avoid shadowing the $PID automatic variable.
        $targetPid = $p.Id
        $windows = New-Object 'System.Collections.Generic.List[object]'
        $callback = [TCPK.Win32+EnumWindowsProc] {
            param([IntPtr]$hWnd, [IntPtr]$lParam)
            $procId = 0
            [void][TCPK.Win32]::GetWindowThreadProcessId($hWnd, [ref]$procId)
            if ($procId -eq $targetPid) {
                $title = New-Object Text.StringBuilder 256
                [void][TCPK.Win32]::GetWindowText($hWnd, $title, 256)
                $cls = New-Object Text.StringBuilder 256
                [void][TCPK.Win32]::GetClassName($hWnd, $cls, 256)
                $windows.Add([pscustomobject]@{ HWnd=$hWnd; Title=$title.ToString(); Class=$cls.ToString() })
            }
            return $true
        }
        [void][TCPK.Win32]::EnumWindows($callback, [IntPtr]::Zero)

        foreach ($w in $windows) {
            if (-not $w.Title -and -not $w.Class) { continue }
            New-TcpkFinding -Module 'runtime' -RuleId 'window.exists' `
                -Severity 'INFO' -Confidence 'Confirmed' `
                -Title "Window: class='$($w.Class)' title='$($w.Title)'" `
                -File "$($p.Name) (PID $($p.Id))" `
                -Evidence "HWND=$($w.HWnd)" `
                -Cwe @('CWE-732') `
                -Description 'UI-automation / Shatter attack surface. If the window accepts WM_COPYDATA or messages, audit the handler.'
        }
    }
}
