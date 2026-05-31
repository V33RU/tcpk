function Test-TcpkElectron {
<#
.SYNOPSIS
    A24. Electron / Chromium-embedded insecure configuration.

.DESCRIPTION
    If the app is Electron / CEF / NW.js, the renderer security model matters.
    Dangerous settings give web content Node.js / OS access (RCE from any XSS).
    This locates app.asar (or loose JS) and scans for the insecure flags.

    Findings:
      nodeIntegration:true            renderer can require('child_process') -> RCE
      contextIsolation:false          preload + page share context (prototype pollution -> RCE)
      webSecurity:false               same-origin policy disabled
      allowRunningInsecureContent     mixed-content / downgrade
      sandbox:false                   renderer not sandboxed
      enableRemoteModule:true         legacy remote module exposed

.PARAMETER Path
    File or directory.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $dir = $Path
    try { if (-not (Get-Item -LiteralPath $Path).PSIsContainer) { $dir = Split-Path -Parent $Path } } catch { return }

    # is this an Electron/CEF/NW.js app?
    $isElectron = $false
    foreach ($marker in 'electron.exe','libcef.dll','nw.exe','ffmpeg.dll') {
        if (Get-ChildItem -LiteralPath $dir -Recurse -File -Filter $marker -ErrorAction SilentlyContinue | Select-Object -First 1) { $isElectron = $true; break }
    }
    $asars = @(Get-ChildItem -LiteralPath $dir -Recurse -File -Filter '*.asar' -ErrorAction SilentlyContinue)
    if ($asars.Count) { $isElectron = $true }
    if (-not $isElectron) { return }   # not an Electron-family app -> nothing to check

    $bad = @{
        'nodeIntegration'              = @{ rx = 'nodeIntegration["'']?\s*:\s*true';                sev='CRITICAL'; desc='Renderer has full Node.js access; any XSS becomes RCE.' }
        'contextIsolation'             = @{ rx = 'contextIsolation["'']?\s*:\s*false';              sev='HIGH';     desc='Preload and page JS share a context; enables prototype-pollution -> RCE.' }
        'webSecurity'                  = @{ rx = 'webSecurity["'']?\s*:\s*false';                   sev='HIGH';     desc='Same-origin policy disabled in the renderer.' }
        'allowRunningInsecureContent'  = @{ rx = 'allowRunningInsecureContent["'']?\s*:\s*true';    sev='MEDIUM';   desc='Mixed/insecure content allowed (downgrade).' }
        'sandbox'                      = @{ rx = 'sandbox["'']?\s*:\s*false';                       sev='MEDIUM';   desc='Renderer process not sandboxed.' }
        'enableRemoteModule'           = @{ rx = 'enableRemoteModule["'']?\s*:\s*true';             sev='HIGH';     desc='Legacy remote module exposed to the renderer.' }
    }

    # search targets: every .asar (JS is plaintext inside) + loose main/preload JS
    $targets = @()
    $targets += $asars
    $targets += @(Get-ChildItem -LiteralPath $dir -Recurse -File -Include 'main.js','preload.js','index.js','app.js' -ErrorAction SilentlyContinue)

    foreach ($t in ($targets | Select-Object -Unique)) {
        $blob = ''
        try { $blob = [Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes($t.FullName)) } catch { continue }
        if (-not $blob) { continue }
        foreach ($k in $bad.Keys) {
            if ([regex]::IsMatch($blob, $bad[$k].rx)) {
                New-TcpkFinding -Module 'static' -RuleId "electron.$k" `
                    -Severity $bad[$k].sev -Confidence 'Confirmed' `
                    -Title "Electron insecure setting: $k in $($t.Name)" `
                    -File $t.FullName -Evidence ([regex]::Match($blob, $bad[$k].rx).Value) -Cwe @('CWE-1188','CWE-94') `
                    -Description ($bad[$k].desc + ' Confirm no untrusted/remote content is ever loaded into this renderer.') `
                    -Fix 'Set nodeIntegration:false, contextIsolation:true, sandbox:true, webSecurity:true; expose only a minimal preload API via contextBridge.'
            }
        }
    }
}
