# Ensure the parent directory of a file path exists before writing to it.
# Defensive: report writers call this so a long scan is never lost to a
# missing / vanished output directory.

function Confirm-TcpkParentDir {
    [CmdletBinding()] param([Parameter(Mandatory)][string]$FilePath)
    $dir = Split-Path -Parent $FilePath
    if ($dir -and -not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force -ErrorAction SilentlyContinue | Out-Null
    }
}
