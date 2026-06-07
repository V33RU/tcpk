#requires -Version 5.1
# Capture the TCPK GUI main window to a PNG (for the README screenshot).
# Uses PrintWindow (renders the window even if partially occluded); falls back to a
# foreground screen-grab. No computer-use / approval needed.
param(
    [string]$Gui = 'C:\Users\admin\Desktop\TCPK\Start-TCPKGui.ps1',
    [string]$Out = 'C:\Users\admin\Desktop\TCPK\assets\tcpk-gui-new.png'
)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing

$sig = @'
using System;
using System.Runtime.InteropServices;
public class WinCap {
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
    [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int n);
    [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr h, IntPtr hdc, uint flags);
    public struct RECT { public int Left, Top, Right, Bottom; }
}
'@
Add-Type -TypeDefinition $sig

# kill stale GUI instances, launch a fresh one
Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" |
    Where-Object { $_.CommandLine -like '*Start-TCPKGui.ps1*' } |
    ForEach-Object { try { Stop-Process -Id $_.ProcessId -Force } catch {} }
Start-Sleep -Seconds 1

$o = Join-Path $env:TEMP 'tcpk-gui-cap-out.txt'
$e = Join-Path $env:TEMP 'tcpk-gui-cap-err.txt'
$p = Start-Process powershell.exe -PassThru -RedirectStandardOutput $o -RedirectStandardError $e -ArgumentList '-STA','-NoProfile','-ExecutionPolicy','Bypass','-File',"`"$Gui`""
$hwnd = [IntPtr]::Zero
$sw = [System.Diagnostics.Stopwatch]::StartNew()
while ($sw.Elapsed.TotalSeconds -lt 40) {
    Start-Sleep -Milliseconds 700
    if ($p.HasExited) { throw "GUI exited early (code $($p.ExitCode)). stderr: $(Get-Content $e -Raw -ErrorAction SilentlyContinue)" }
    $p.Refresh()
    $h = $p.MainWindowHandle
    if ($h -eq [IntPtr]::Zero) { continue }
    # Wait until the window has FINISHED building: full title + full size (it starts as a
    # small ~423x400 splash with title 'Authorized use only', then grows to 1200x800).
    if ("$($p.MainWindowTitle)" -notlike '*Thick Client Pentest Kit*') { continue }
    $rr = New-Object WinCap+RECT
    [void][WinCap]::GetWindowRect($h, [ref]$rr)
    if (($rr.Right - $rr.Left) -ge 1100 -and ($rr.Bottom - $rr.Top) -ge 700) { $hwnd = $h; break }
}
if ($hwnd -eq [IntPtr]::Zero) { throw "window never reached full size after 40s" }
Write-Host "hwnd=$hwnd title='$($p.MainWindowTitle)'"
Start-Sleep -Seconds 2   # let it finish painting all tabs/controls

[void][WinCap]::ShowWindow($hwnd, 5)       # SW_SHOW
[void][WinCap]::SetForegroundWindow($hwnd)
Start-Sleep -Milliseconds 1000

$r = New-Object WinCap+RECT
[void][WinCap]::GetWindowRect($hwnd, [ref]$r)
$w = $r.Right - $r.Left; $h = $r.Bottom - $r.Top
Write-Host "rect: ${w}x${h} at ($($r.Left),$($r.Top))"

$bmp = New-Object System.Drawing.Bitmap($w, $h)
$g   = [System.Drawing.Graphics]::FromImage($bmp)
$hdc = $g.GetHdc()
$ok  = [WinCap]::PrintWindow($hwnd, $hdc, 2)   # PW_RENDERFULLCONTENT
$g.ReleaseHdc($hdc)

# detect an all-black PrintWindow result -> fall back to screen grab
$probe = $bmp.GetPixel([int]($w/2), 12)
if (-not $ok -or ($probe.R -lt 5 -and $probe.G -lt 5 -and $probe.B -lt 5)) {
    Write-Host "PrintWindow weak (ok=$ok probe=$($probe.R),$($probe.G),$($probe.B)); using CopyFromScreen"
    $g.CopyFromScreen($r.Left, $r.Top, 0, 0, (New-Object System.Drawing.Size($w, $h)))
}

$dir = Split-Path $Out -Parent
if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
$bmp.Save($Out, [System.Drawing.Imaging.ImageFormat]::Png)
$g.Dispose(); $bmp.Dispose()
Write-Host "SAVED $Out ($((Get-Item $Out).Length) bytes, ${w}x${h})"
