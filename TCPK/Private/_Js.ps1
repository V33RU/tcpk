# JavaScript text helpers for the Electron / web-bundle checks.
#
# Get-TcpkJsCodeOnly strips JS comments BEFORE config-flag detection, so a flag that
# only appears in a comment ("// we deliberately avoid webSecurity:false") no longer
# fires a finding -- the false-positive class found reviewing a real Electron app.
# URL-safe: '//' inside http:// / https:// / ws:// (preceded by ':') is NOT treated
# as a comment and is preserved, so config on the same line as a URL is not lost.
function Get-TcpkJsCodeOnly {
    [CmdletBinding()]
    param([string]$Js)
    if (-not $Js) { return '' }
    $s = [regex]::Replace($Js, '/\*[\s\S]*?\*/', ' ')          # block comments  /* ... */
    $s = [regex]::Replace($s, '(?m)(?<![:/])//[^\r\n]*', ' ')   # line comments // (but not '://')
    return $s
}

# True if a webPreferences / BrowserWindow / BrowserView / webContents context appears
# in the window of code immediately BEFORE $Index -- used to tell a real renderer-config
# flag from a bare 'key: false' in prose or an unrelated options object.
function Test-TcpkWebPrefsContext {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Code, [Parameter(Mandatory)][int]$Index, [int]$Window = 500)
    if ($Index -le 0) { return $false }
    $start = [Math]::Max(0, $Index - $Window)
    $ctx = $Code.Substring($start, $Index - $start)
    return [regex]::IsMatch($ctx, '(?i)(webPreferences|new\s+BrowserWindow|new\s+BrowserView|webContents)')
}

# True if a PE is the bundled Chromium / Electron runtime (the app's main .exe) or a
# Chromium-shipped GPU / vendor binary. String-scanning these for APP-behaviour heuristics
# is a false-positive factory: the Chromium binary embeds EVERY recognized CLI flag
# (--no-sandbox, --inspect-brk), every cookie attribute (SameSite=None), DNS APIs, and the
# entire CA OCSP/CRL/AIA URL list from its root store -- none of which are the app author's
# code. The developer's real logic lives in resources\app.asar (JS), which is scanned
# separately. Detection: a known Chromium/GPU vendor binary NAME, or a Chromium runtime
# SIGNATURE in the extracted strings (resource-pak names / Chromium+Electron markers) that
# will not appear in ordinary first-party application binaries.
function Test-TcpkIsChromiumRuntime {
    [CmdletBinding()]
    param([string]$Name, [string]$Text)
    if ($Name) {
        $known = @('libglesv2.dll', 'libegl.dll', 'vk_swiftshader.dll', 'libvk_swiftshader.dll',
                   'vulkan-1.dll', 'd3dcompiler_47.dll', 'dxcompiler.dll', 'dxil.dll', 'ffmpeg.dll',
                   'swiftshader.dll', 'chrome_elf.dll', 'electron.exe')
        if ($known -contains $Name.ToLowerInvariant()) { return $true }
    }
    if ($Text) {
        if ($Text -match 'v8_context_snapshot|chrome_100_percent|chrome_200_percent|icudtl\.dat') { return $true }
        if (($Text -match 'Chromium') -and ($Text -match 'Electron')) { return $true }
    }
    return $false
}

# Extract the bundled Electron / Chromium / Node version from an Electron app's MAIN exe.
# On Windows the Electron framework is statically linked into the main .exe, so the version
# markers ("Chrome/<v>", "Electron/<v>", "node.js/v<v>") live in that binary -- NOT in any
# deps.json. This is the single most CVE-relevant version in an Electron app and is otherwise
# invisible to the SBOM/CVE pass. Returns $null for a non-Electron target.
# Used by Test-TcpkElectron (electron.outdated-runtime) and Get-TcpkCveMatches (OSV electron@ver).
function Get-TcpkRuntimeVersions {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    $dir = $Path
    try { if (-not (Get-Item -LiteralPath $Path).PSIsContainer) { $dir = Split-Path -Parent $Path } } catch { return $null }

    # An Electron root contains app.asar and/or the Chromium resource paks / v8 snapshot.
    $marker = Get-ChildItem -LiteralPath $dir -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -eq 'app.asar' -or $_.Name -eq 'v8_context_snapshot.bin' -or $_.Name -like 'chrome_*.pak' } |
        Select-Object -First 1
    if (-not $marker) { return $null }
    $eroot = Split-Path -Parent $marker.FullName
    if ((Split-Path -Leaf $eroot) -ieq 'resources') { $eroot = Split-Path -Parent $eroot }

    # main exe = the largest non-Uninstall .exe at the Electron root (the framework is linked in)
    $exe = Get-ChildItem -LiteralPath $eroot -File -Filter '*.exe' -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notmatch '^(?i:Uninstall)' } | Sort-Object Length -Descending | Select-Object -First 1
    if (-not $exe) { return $null }
    if ($exe.Length -gt 800MB) { return $null }   # guard: do not slurp a pathologically large file

    $txt = ''
    try { $txt = [IO.File]::ReadAllText($exe.FullName, [Text.Encoding]::GetEncoding('ISO-8859-1')) } catch { return $null }
    if (-not $txt) { return $null }

    $chrome   = ([regex]::Match($txt, 'Chrome/(\d+\.\d+\.\d+\.\d+)')).Groups[1].Value
    $electron = ([regex]::Match($txt, 'Electron/(\d+\.\d+\.\d+)')).Groups[1].Value
    $node     = ([regex]::Match($txt, '(?i)node\.js/v?(\d+\.\d+\.\d+)')).Groups[1].Value
    if (-not ($chrome -or $electron)) { return $null }

    [pscustomobject]@{ Electron = $electron; Chromium = $chrome; Node = $node; File = $exe.FullName }
}

# Integer major version from a dotted version string ('146.0.7680.179' -> 146). $null if unparseable.
function Get-TcpkVersionMajor {
    [CmdletBinding()] param([string]$Version)
    if ("$Version" -match '^\s*(\d+)') { return [int]$matches[1] }
    return $null
}
