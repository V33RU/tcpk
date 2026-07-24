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

# Extract main-process IPC handler bodies from Electron JS. For each
# ipcMain.handle/handleOnce/on(channel, callback) it returns the channel, the
# callback parameter names, the "payload" params (everything after the first,
# which is the IpcMainEvent), and the callback body text (brace-matched, or the
# arrow expression). This is what lets the caller correlate a RENDERER-supplied
# argument with a dangerous sink inside the same handler -- the top Electron RCE
# class (ipcMain.handle('run', (e, cmd) => exec(cmd))). Body capped for safety on
# minified bundles. Pure string parsing; feed it Get-TcpkJsCodeOnly output.
function Get-TcpkJsHandlerBodies {
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Code, [int]$BodyCap = 4000)
    $out = New-Object System.Collections.Generic.List[object]
    if (-not $Code) { return $out }
    $n = $Code.Length
    foreach ($m in [regex]::Matches($Code, '(?i)ipcMain\s*\.\s*(handle|handleOnce|on)\s*\(')) {
        $j = $m.Index + $m.Length            # first char after '('
        # --- arg 1: channel, up to the top-level comma ---
        $depth = 0; $chan = New-Object System.Text.StringBuilder
        while ($j -lt $n) {
            $c = $Code[$j]
            if ($c -eq '(' -or $c -eq '[' -or $c -eq '{') { $depth++ }
            elseif ($c -eq ')' -or $c -eq ']' -or $c -eq '}') { if ($depth -le 0) { break }; $depth-- }
            elseif ($c -eq ',' -and $depth -le 0) { $j++; break }
            [void]$chan.Append($c); $j++
        }
        $channel = $chan.ToString().Trim().Trim('''"')
        while ($j -lt $n -and [char]::IsWhiteSpace($Code[$j])) { $j++ }
        if ($j + 5 -le $n -and $Code.Substring($j, 5) -ieq 'async') { $j += 5; while ($j -lt $n -and [char]::IsWhiteSpace($Code[$j])) { $j++ } }

        # --- arg 2: callback params ---
        $params = @()
        if ($j + 8 -le $n -and $Code.Substring($j, 8) -ieq 'function') {
            $j += 8; while ($j -lt $n -and $Code[$j] -ne '(') { $j++ }
        }
        if ($j -lt $n -and $Code[$j] -eq '(') {
            $ps = $j; $pd = 0
            while ($j -lt $n) { $c = $Code[$j]; if ($c -eq '(') { $pd++ } elseif ($c -eq ')') { $pd--; if ($pd -le 0) { break } }; $j++ }
            $inner = $Code.Substring($ps + 1, [Math]::Max(0, $j - $ps - 1))
            $params = @($inner -split ',' | ForEach-Object { (($_ -replace '[=:{].*$', '') -replace '[^\w$]', '').Trim() } | Where-Object { $_ })
            $j++
        } else {
            $idm = [regex]::Match($Code.Substring($j, [Math]::Min(40, $n - $j)), '^\s*([A-Za-z_$][\w$]*)')
            if ($idm.Success) { $params = @($idm.Groups[1].Value); $j += $idm.Length }
        }
        while ($j -lt $n -and [char]::IsWhiteSpace($Code[$j])) { $j++ }
        if ($j + 1 -lt $n -and $Code[$j] -eq '=' -and $Code[$j + 1] -eq '>') { $j += 2; while ($j -lt $n -and [char]::IsWhiteSpace($Code[$j])) { $j++ } }

        # --- body: brace block, or arrow expression up to the handle-call close paren ---
        $body = ''
        if ($j -lt $n -and $Code[$j] -eq '{') {
            $bs = $j; $bd = 0
            while ($j -lt $n -and ($j - $bs) -lt $BodyCap) { $c = $Code[$j]; if ($c -eq '{') { $bd++ } elseif ($c -eq '}') { $bd--; if ($bd -le 0) { $j++; break } }; $j++ }
            $body = $Code.Substring($bs, [Math]::Min($BodyCap, [Math]::Min($j, $n) - $bs))
        } else {
            $bs = $j; $bd = 0
            while ($j -lt $n -and ($j - $bs) -lt $BodyCap) { $c = $Code[$j]; if ($c -eq '(' -or $c -eq '[' -or $c -eq '{') { $bd++ } elseif ($c -eq ']' -or $c -eq '}') { $bd-- } elseif ($c -eq ')') { if ($bd -le 0) { break }; $bd-- }; $j++ }
            $body = $Code.Substring($bs, [Math]::Min($BodyCap, [Math]::Min($j, $n) - $bs))
        }
        $payload = @(if ($params.Count -gt 1) { $params[1..($params.Count - 1)] })
        $out.Add([pscustomobject]@{ Channel = $channel; Params = $params; Payload = $payload; Body = $body })
    }
    return $out
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
        # The Electron MAIN exe embeds version markers ("Electron/42.4.1", "Chrome/148.0.7778.265")
        # but not the literal word "Chromium" -- so the app-named main .exe (which IS the Electron
        # runtime, not first-party code) is caught here.
        if ($Text -match 'Electron/\d+\.\d+\.\d+')                       { return $true }
        if ($Text -match 'Chrome/\d+\.\d+\.\d+\.\d+' -and $Text -match '(?i)node\.js/v?\d') { return $true }
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
