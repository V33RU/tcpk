#requires -Version 5.1
# EVERY path TCPK creates lives under the tool folder. Nothing is written to %TEMP%,
# %LOCALAPPDATA%, %APPDATA%, %ProgramData%, or a CWD-relative path.
#
# WHY. TCPK is a portable toolkit carried to client sites on a stick or a copied folder.
# What it produces is engagement data: extracted application code, decompiled sources,
# captured traffic, memory dumps. Windows does NOT clear %TEMP% on reboot, so anything
# written there outlives the engagement and survives deleting TCPK itself. Keeping every
# artifact under the tool folder means the operator removes one directory and nothing is
# left on a machine they do not own.
#
# The layout under <tool folder>\work\ :
#     out\        audit reports
#     extract\    msix / msi / zip / asar / single-file / pyinstaller carves
#     capture\    pcap, intercept flows, hook and tamper logs
#     dump\       process memory dumps
#     trace\      ETW / logman .etl sessions
#     vulndb\     offline CVE snapshot
#     run\        pause flags and short-lived scratch
#
# There is deliberately NO fallback to %TEMP%. A silent fallback is how engagement data
# ends up somewhere the operator did not choose, which is the exact failure this exists to
# prevent. If the tool folder is not writable the caller is told, and may pass an explicit
# override, but TCPK never picks an outside path on its own.

# Session override, set by Set-TcpkWorkRoot. $null means "derive from the tool folder".
$script:TcpkWorkRootOverride = $null

# Repo/tool root: TCPK.psm1 sets $script:TcpkRoot to <tool folder>\TCPK, so the tool
# folder is its parent. Falls back to this file's grandparent if the module variable is
# not set (a private file dot-sourced directly, which the tests do).
function Get-TcpkToolRoot {
    [CmdletBinding()] param()
    if ($script:TcpkRoot) { return (Split-Path $script:TcpkRoot -Parent) }
    return (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent)
}

# Point the work root somewhere else for this session. The documented escape hatch for a
# read-only tool folder (Program Files, a locked share, a mounted ISO). Explicit only:
# nothing calls this automatically.
function Set-TcpkWorkRoot {
    [CmdletBinding()] param([Parameter(Mandatory)][AllowEmptyString()][string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { $script:TcpkWorkRootOverride = $null; return }
    $script:TcpkWorkRootOverride = $Path
}

# Resolve (and create) a work directory, returning its full path.
#
# -Kind   one of the subfolders above. Anything else is rejected rather than silently
#         creating a stray directory.
# -Leaf   optional child under that subfolder, e.g. a per-target extraction folder.
#
# Throws when the directory cannot be created. That is deliberate: the caller either
# handles it and reports a Skipped finding, or the run fails loudly. It never returns a
# path outside the tool folder.
function Get-TcpkWorkDir {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('out', 'extract', 'capture', 'dump', 'trace', 'vulndb', 'run')]
        [string]$Kind,
        [string]$Leaf,
        [switch]$NoCreate
    )

    $base = if ($script:TcpkWorkRootOverride) { $script:TcpkWorkRootOverride }
            else { Join-Path (Get-TcpkToolRoot) 'work' }

    $dir = Join-Path $base $Kind
    if ($Leaf) {
        # Defence in depth: a caller-supplied leaf must not climb out of the work root.
        $safeLeaf = ($Leaf -replace '[\\/]+', '_') -replace '[<>:"|?*]', '_'
        $safeLeaf = $safeLeaf.Trim('. ')
        if ($safeLeaf) { $dir = Join-Path $dir $safeLeaf }
    }

    if ($NoCreate) { return $dir }

    if (-not (Test-Path -LiteralPath $dir)) {
        try {
            New-Item -ItemType Directory -Path $dir -Force -ErrorAction Stop | Out-Null
        } catch {
            throw ("TCPK could not create its work directory '$dir': $($_.Exception.Message). " +
                   "Every artifact TCPK produces is written under the tool folder so it travels " +
                   "with the tool and leaves nothing behind on the target machine. If the tool " +
                   "folder is read-only, copy TCPK somewhere writable, or redirect the work root " +
                   "explicitly with Set-TcpkWorkRoot -Path <dir>. TCPK will not fall back to a " +
                   "temp or profile path on its own.")
        }
    }
    return (Resolve-Path -LiteralPath $dir).Path
}

# Convenience: a unique file path inside a work directory. Same guarantees as above.
function New-TcpkWorkPath {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('out', 'extract', 'capture', 'dump', 'trace', 'vulndb', 'run')]
        [string]$Kind,
        [string]$Prefix = 'tcpk',
        [string]$Extension = ''
    )
    $dir  = Get-TcpkWorkDir -Kind $Kind
    $name = "$Prefix-" + [guid]::NewGuid().ToString('N')
    # No ternary here: Windows PowerShell 5.1 is a supported host and does not parse it.
    if ($Extension) {
        if ($Extension.StartsWith('.')) { $name += $Extension } else { $name += ".$Extension" }
    }
    return (Join-Path $dir $name)
}
