# Target expansion: accept more distribution formats directly. The audit scans a folder
# of files; if the target is a sealed container, unwrap it once to a temp dir and scan
# that. MSIX was already handled (Expand-TcpkMsix); this adds MSI and ZIP.
#
#   directory            -> scanned as-is
#   .msix/.appx/...       -> Expand-TcpkMsix (existing)
#   .msi                  -> msiexec /a administrative install (extract, no system install)
#   .zip                  -> safe entry-by-entry extraction (zip-slip guarded)
#   anything else (.exe)  -> scanned as a single file
#
# Always degrades gracefully: on any extraction failure it returns the original path so
# the audit still runs (just against the unopened file).

function Expand-TcpkTarget {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return $Path }
    $item = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
    if (-not $item -or $item.PSIsContainer) { return $Path }   # already a folder (or gone)

    $ext = $item.Extension.ToLowerInvariant()
    try {
        switch -Regex ($ext) {
            '^\.(msix|appx|msixbundle|appxbundle)$' { return (Expand-TcpkMsix -Path $Path) }
            '^\.msi$'                               { return (Expand-TcpkMsiFile -Path $Path) }
            '^\.zip$'                               { return (Expand-TcpkZipFile -Path $Path) }
            default                                 { return $Path }
        }
    } catch {
        Write-Warning "Expand-TcpkTarget: could not unwrap $($item.Name) ($($_.Exception.Message)); scanning it as-is."
        return $Path
    }
}

# Extract an .msi via an administrative install (msiexec /a). This copies the packaged
# files into TARGETDIR WITHOUT installing, registering, or modifying the system. NOTE:
# /a can still run an MSI's custom actions -- extract untrusted installers in a VM.
#
# The wait is BOUNDED and polled, for two reasons specific to this call:
#
#  1. Windows Installer serialises on the global _MSIExecute mutex. Any other MSI
#     transaction in progress anywhere on the box -- Windows Update, a background
#     product repair, another admin's install -- blocks this one until it finishes,
#     with no bound of our own.
#  2. /a executes the package's custom actions, which are arbitrary vendor code with
#     no timeout at all. On an untrusted installer that is exactly the code most
#     likely to misbehave.
#
# This runs from Invoke-TcpkAudit BEFORE the check loop starts, so at this point no
# per-check budget is armed and no heartbeat has been emitted. A plain -Wait here
# therefore hangs the audit at its very first step with a blank screen -- the worst
# possible place, because there is nothing on screen yet to suggest where it stopped.
$script:TcpkMsiExtractSec = 300

function Expand-TcpkMsiFile {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    $full = (Resolve-Path -LiteralPath $Path).Path
    $dest = Join-Path ([IO.Path]::GetTempPath()) ('tcpk-msi-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $dest -Force | Out-Null
    Write-TcpkInfo "Extracting MSI via 'msiexec /a' (administrative install -- no system changes): $(Split-Path $full -Leaf) -> $dest"
    $argStr = "/a `"$full`" /qn TARGETDIR=`"$dest`""
    $p = Start-Process -FilePath 'msiexec.exe' -ArgumentList $argStr -PassThru -WindowStyle Hidden -ErrorAction Stop

    # Poll in 1s slices instead of one blocking WaitForExit($ms) so the heartbeat can
    # report progress. A long MSI then says so, rather than looking like a dead tool.
    Reset-TcpkHeartbeat
    $waited = 0
    while (-not $p.HasExited -and $waited -lt $script:TcpkMsiExtractSec) {
        [void]$p.WaitForExit(1000)
        $waited++
        Write-TcpkHeartbeat -Component 'msi-extract' -Index $waited -Total $script:TcpkMsiExtractSec -Current (Split-Path $full -Leaf)
    }

    if (-not $p.HasExited) {
        Write-Warning "msiexec /a still running after ${script:TcpkMsiExtractSec}s (blocked on the _MSIExecute mutex, or a custom action is hung); killing it and scanning the .msi as-is."
        try { $p.Kill() } catch { }
        try { Add-TcpkScanSkip -Kind 'BudgetStopped' -ItemPath "msiexec /a $(Split-Path $full -Leaf) (timed out after $script:TcpkMsiExtractSec s)" } catch { }
        return $Path
    }
    if ($p.ExitCode -ne 0) {
        Write-Warning "msiexec /a returned exit $($p.ExitCode); scanning the .msi as-is."
        return $Path
    }
    return $dest
}

# Extract a .zip to a temp dir, entry-by-entry, with a path-containment guard so a
# malicious archive entry (zip-slip) cannot write outside the extraction root.
function Expand-TcpkZipFile {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
    $full = (Resolve-Path -LiteralPath $Path).Path
    $dest = Join-Path ([IO.Path]::GetTempPath()) ('tcpk-zip-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $dest -Force | Out-Null
    $root = (Resolve-Path -LiteralPath $dest).Path.TrimEnd([IO.Path]::DirectorySeparatorChar)
    Write-TcpkInfo "Extracting ZIP -> $dest"
    $zip = [System.IO.Compression.ZipFile]::OpenRead($full)
    try {
        foreach ($e in $zip.Entries) {
            if ([string]::IsNullOrEmpty($e.Name)) { continue }   # directory entry
            $target = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($dest, $e.FullName))
            if (-not $target.StartsWith($root + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
                Write-Warning "ZIP entry escapes the extraction root (zip-slip), skipped: $($e.FullName)"
                continue
            }
            $dir = Split-Path -Parent $target
            if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
            [System.IO.Compression.ZipFileExtensions]::ExtractToFile($e, $target, $true)
        }
    } finally {
        $zip.Dispose()
    }
    return $dest
}
