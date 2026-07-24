# Launch-and-observe helpers for Invoke-TcpkAudit -LaunchTarget. These EXECUTE the target
# binary so the bucket-E live-process checks have something to observe when the app is not
# already running; gated by the caller (-LaunchTarget + -Acknowledge) and lab/authorized-use
# only. Read-only observation once launched; the launched process is stopped at the end.

# Resolve the target's main executable: the MSIX-manifest-declared Executable, else the
# largest non-helper .exe under the dir. Mirrors the selection in Get-TcpkIdentityTerms.
function Get-TcpkMainExePath {
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Dir)
    if (-not (Test-Path -LiteralPath $Dir)) { return $null }
    $manifest = $null
    try { $manifest = Read-TcpkAppxManifest -ExpandedPath $Dir } catch { }
    if ($manifest) {
        try {
            $nsm = Get-TcpkAppxNsMgr -Manifest $manifest
            $appNode = $manifest.DocumentElement.SelectSingleNode('//d:Applications/d:Application', $nsm)
            if ($appNode) {
                $exeAttr = $appNode.GetAttribute('Executable')
                if ($exeAttr) { $cand = Join-Path $Dir $exeAttr; if (Test-Path -LiteralPath $cand) { return $cand } }
            }
        } catch { }
    }
    $exes = @(Get-ChildItem -LiteralPath $Dir -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.Extension -ieq '.exe' })
    $primary = $exes |
        Where-Object { $_.BaseName -notmatch '(?i)(setup|install|uninstall|update|crashpad|helper|vc_redist|squirrel)' } |
        Sort-Object Length -Descending | Select-Object -First 1
    if (-not $primary -and $exes.Count) { $primary = $exes | Sort-Object Length -Descending | Select-Object -First 1 }
    if ($primary) { return $primary.FullName }
    return $null
}

# Launch the exe minimized in its own working directory and wait up to $WaitSec for it to
# initialize (load modules, bind ports, spawn children). Returns the Process object, or $null
# if it would not start or exited immediately. Never throws.
function Start-TcpkTargetProcess {
    [CmdletBinding()] param([Parameter(Mandatory)][string]$ExePath, [int]$WaitSec = 6)
    if (-not (Test-Path -LiteralPath $ExePath)) { return $null }
    $proc = $null
    try {
        $wd = Split-Path -Parent $ExePath
        $proc = Start-Process -FilePath $ExePath -WorkingDirectory $wd -WindowStyle Minimized -PassThru -ErrorAction Stop
    } catch { return $null }
    if (-not $proc) { return $null }
    $deadline = (Get-Date).AddSeconds([Math]::Max(1, $WaitSec))
    while ((Get-Date) -lt $deadline) {
        try { if ($proc.HasExited) { break } } catch { break }
        Start-Sleep -Milliseconds 250
    }
    try { if ($proc.HasExited) { return $null } } catch { return $null }
    return $proc
}

# Best-effort stop of a TCPK-launched process and its direct children. Never throws.
function Stop-TcpkTargetProcess {
    [CmdletBinding()] param($Proc)
    if (-not $Proc) { return }
    $id = $null; try { $id = $Proc.Id } catch { }
    if (-not $id) { return }
    try {
        Get-CimInstance Win32_Process -Filter "ParentProcessId=$id" -ErrorAction SilentlyContinue |
            ForEach-Object { try { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue } catch { } }
    } catch { }
    try { Stop-Process -Id $id -Force -ErrorAction SilentlyContinue } catch { }
}
