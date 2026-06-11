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
function Expand-TcpkMsiFile {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    $full = (Resolve-Path -LiteralPath $Path).Path
    $dest = Join-Path ([IO.Path]::GetTempPath()) ('tcpk-msi-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $dest -Force | Out-Null
    Write-TcpkInfo "Extracting MSI via 'msiexec /a' (administrative install -- no system changes): $(Split-Path $full -Leaf) -> $dest"
    $argStr = "/a `"$full`" /qn TARGETDIR=`"$dest`""
    $p = Start-Process -FilePath 'msiexec.exe' -ArgumentList $argStr -Wait -PassThru -WindowStyle Hidden -ErrorAction Stop
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
