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

    # search targets: every .asar (JS is plaintext inside) + loose main/preload JS.
    # NB: Get-ChildItem -Include is SILENTLY IGNORED with -LiteralPath (it would return
    # EVERY file and we'd scan PNGs/configs for Electron flags). Filter by name explicitly.
    $jsNames = @('main.js','preload.js','index.js','app.js')
    $targets = @()
    $targets += $asars
    $targets += @(Get-ChildItem -LiteralPath $dir -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -in $jsNames })

    foreach ($t in ($targets | Select-Object -Unique)) {
        $blob = ''
        try { $blob = [Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes($t.FullName)) } catch { continue }
        if (-not $blob) { continue }
        # Strip JS comments first so a flag that only appears in a comment (e.g.
        # "// we avoid webSecurity:false") does NOT fire -- a real false-positive class.
        $code = Get-TcpkJsCodeOnly $blob
        if (-not $code) { continue }
        foreach ($k in $bad.Keys) {
            $m = [regex]::Match($code, $bad[$k].rx)
            if (-not $m.Success) { continue }
            # Confirmed only inside a webPreferences/BrowserWindow context; a bare flag
            # elsewhere (prose, a string, or a dynamically-built options object) -> Inferred.
            $inCtx = Test-TcpkWebPrefsContext -Code $code -Index $m.Index
            $conf  = if ($inCtx) { 'Confirmed' } else { 'Inferred' }
            $note  = if ($inCtx) { ' Confirm no untrusted/remote content is ever loaded into this renderer.' }
                     else { ' NOTE: matched outside an obvious webPreferences block (possible string/prose or a dynamically-built options object) -- review.' }
            New-TcpkFinding -Module 'static' -RuleId "electron.$k" `
                -Severity $bad[$k].sev -Confidence $conf `
                -Title "Electron insecure setting: $k in $($t.Name)" `
                -File $t.FullName -Evidence $m.Value -Cwe @('CWE-1188','CWE-94') `
                -Description ($bad[$k].desc + $note) `
                -Fix 'Set nodeIntegration:false, contextIsolation:true, sandbox:true, webSecurity:true; expose only a minimal preload API via contextBridge.'
        }

        # --- preload / contextBridge exposure analysis (G2) ---
        # With contextIsolation on, the real renderer<->main trust boundary is what the
        # preload exposes via contextBridge.exposeInMainWorld. Inventory it, and flag the
        # over-broad shapes that hand the renderer general IPC or Node power.
        $br = [regex]::Matches($code, 'contextBridge\.exposeInMainWorld\(\s*[''"]?([A-Za-z_$][\w$]*)')
        if ($br.Count) {
            $names = (@($br | ForEach-Object { $_.Groups[1].Value }) | Select-Object -Unique) -join ', '
            New-TcpkFinding -Module 'static' -RuleId 'electron.bridge-surface' `
                -Severity 'INFO' -Confidence 'Confirmed' `
                -Title "Electron contextBridge surface in $($t.Name)" `
                -File $t.FullName -Evidence "exposeInMainWorld: $names" -Cwe @('CWE-749') `
                -Description 'These contextBridge APIs are exposed from preload into the renderer -- the main renderer-to-main trust boundary. Each exposed function should call a FIXED IPC channel; it must not forward a caller-supplied channel or hand back Node/Electron primitives.' `
                -Fix 'Expose only narrow, purpose-built functions bound to fixed channels.'

            # raw ipcRenderer (or an unwrapped send/invoke/on method) handed to the renderer
            if ([regex]::IsMatch($code, 'exposeInMainWorld\([^,]{0,60},\s*ipcRenderer\s*[\),]') -or
                [regex]::IsMatch($code, '[:=]\s*ipcRenderer\.(send|invoke|sendSync|on|postMessage)\b\s*(?![\(.])')) {
                New-TcpkFinding -Module 'static' -RuleId 'electron.bridge-exposes-ipcRenderer' `
                    -Severity 'CRITICAL' -Confidence 'Confirmed' `
                    -Title "Electron preload exposes ipcRenderer to the renderer in $($t.Name)" `
                    -File $t.FullName -Evidence ([regex]::Match($code, 'exposeInMainWorld\([^,]{0,60},\s*ipcRenderer|[:=]\s*ipcRenderer\.(send|invoke|sendSync|on|postMessage)').Value) -Cwe @('CWE-749','CWE-94') `
                    -Description 'The preload hands the renderer the raw ipcRenderer object (or an unwrapped send/invoke method). The renderer can then call ANY IPC channel -- contextIsolation is defeated and any XSS becomes main-process control.' `
                    -Fix 'Never expose ipcRenderer. Expose individual functions that each invoke a single fixed channel.'
            }
            # generic passthrough: forwards a caller-supplied channel variable to IPC
            if ([regex]::IsMatch($code, 'ipcRenderer\.(invoke|send|sendSync)\(\s*(channel|chan|ch|name|topic|evt|event|msg|key)\b')) {
                New-TcpkFinding -Module 'static' -RuleId 'electron.bridge-generic-ipc' `
                    -Severity 'HIGH' -Confidence 'Inferred' `
                    -Title "Electron preload forwards a caller-supplied IPC channel in $($t.Name)" `
                    -File $t.FullName -Evidence ([regex]::Match($code, 'ipcRenderer\.(invoke|send|sendSync)\(\s*(channel|chan|ch|name|topic|evt|event|msg|key)\b').Value) -Cwe @('CWE-749') `
                    -Description 'An exposed bridge function forwards a channel name chosen by the renderer to ipcRenderer.invoke/send, so the renderer can reach any IPC handler -- not just the intended one.' `
                    -Fix 'Bind each exposed function to a single fixed channel; if dispatch is unavoidable, validate the channel against an explicit allow-list.'
            }
            # Node / Electron primitive exposed directly
            if ([regex]::IsMatch($code, 'exposeInMainWorld\([^,]+,\s*(require\(\s*[''"](fs|child_process|os|path|electron|net|http|https|vm)[''"]\s*\)|shell\b|process\b|require\b)')) {
                New-TcpkFinding -Module 'static' -RuleId 'electron.bridge-exposes-node' `
                    -Severity 'CRITICAL' -Confidence 'Confirmed' `
                    -Title "Electron preload exposes a Node/Electron primitive to the renderer in $($t.Name)" `
                    -File $t.FullName -Evidence ([regex]::Match($code, 'exposeInMainWorld\([^,]+,\s*(require\([^)]+\)|shell|process|require)').Value) -Cwe @('CWE-749','CWE-94') `
                    -Description 'The preload exposes a Node module (fs/child_process/...), shell, process, or require directly to the renderer. Web content can then touch the filesystem / spawn processes -- full RCE from any XSS.' `
                    -Fix 'Do not expose Node/Electron primitives; wrap only the specific, validated operations the UI needs.'
            }
        }

        # --- G7: deep-link / file-association / argv session-override surface ---
        # Custom URI schemes, file-type handlers and command-line overrides are how the
        # OUTSIDE world drives a desktop app: a crafted deep link, a malicious project/
        # document file, or a forwarded second-instance argument can redirect the session
        # or inject credentials -- without the user typing anything.
        $proto = [regex]::Match($code, 'setAsDefaultProtocolClient\(\s*[''"]?([A-Za-z][\w+.\-]*)')
        if ($proto.Success) {
            New-TcpkFinding -Module 'static' -RuleId 'electron.custom-protocol' `
                -Severity 'LOW' -Confidence 'Confirmed' `
                -Title "Electron registers a custom URI scheme ($($proto.Groups[1].Value)://) in $($t.Name)" `
                -File $t.FullName -Evidence $proto.Value -Cwe @('CWE-939','CWE-20') `
                -Description "The app registers itself as handler for a custom URI scheme, so any web page or document can deep-link into it. Treat the deep-link URL as untrusted: it must not choose a navigation target, host, or file path unchecked." `
                -Fix 'Validate and canonicalize every deep-link URL through an allow-list; never route it straight into loadURL / connection settings / a file open.'
        }
        if ([regex]::IsMatch($code, '(?i)shell[\\/]{1,2}open[\\/]{1,2}command')) {
            New-TcpkFinding -Module 'static' -RuleId 'electron.file-assoc-handler' `
                -Severity 'LOW' -Confidence 'Confirmed' `
                -Title "App registers a file-type open handler in $($t.Name)" `
                -File $t.FullName -Evidence 'writes a Classes\...\shell\open\command handler' -Cwe @('CWE-20') `
                -Description 'The app registers a shell open-command handler for a file type, so double-clicking such a file launches the app with that file. Opened files must be untrusted: a project/document file can carry attacker-controlled settings or archive contents.' `
                -Fix 'Validate the opened file before trusting it; never auto-apply embedded connection settings/credentials without explicit user confirmation.'
        }
        if ([regex]::IsMatch($code, '(?i)(process\.argv|commandLine|\bargv\b)') -and
            [regex]::IsMatch($code, '(?i)--(token|password|secret|api-?key|host|server|proxy|endpoint|url)\b')) {
            $flags = (@([regex]::Matches($code, '(?i)--(token|password|secret|api-?key|host|server|proxy|endpoint|url)\b') | ForEach-Object { $_.Value.ToLower() }) | Select-Object -Unique) -join ' '
            $deeplinkable = [regex]::IsMatch($code, '(?i)(second-instance|setAsDefaultProtocolClient|open-url)')
            $dnote = if ($deeplinkable) { ' These overrides are reachable via a forwarded second-instance argument, a deep link, or a file-association launch -- without the user typing them.' } else { '' }
            New-TcpkFinding -Module 'static' -RuleId 'electron.argv-session-override' `
                -Severity 'MEDIUM' -Confidence 'Confirmed' `
                -Title "Command-line session/credential overrides parsed in $($t.Name)" `
                -File $t.FullName -Evidence "argv flags: $flags" -Cwe @('CWE-88','CWE-20') `
                -Description ('The app reads security-sensitive overrides from the command line (host / token / credential / proxy). A crafted shortcut or argument can redirect the session to attacker infrastructure or inject a token.' + $dnote) `
                -Fix 'Treat command-line / deep-link overrides as untrusted; require explicit user confirmation before connecting to a CLI-supplied host or applying a CLI-supplied credential.'
        }

        # --- G3: main-process IPC handler surface + sender validation ---
        # ipcMain.handle/on (and a wrapHandler/installHandler indirection) register the
        # privileged operations the renderer can invoke. A handler that does not validate
        # event.senderFrame is reachable from ANY frame -- so a navigated-away renderer or
        # an injected sub-frame can drive it (renderer XSS -> main-process action).
        $ipc1 = [regex]::Matches($code, '(?i)ipcMain\.(?:handle|handleOnce|on)\s*\(\s*([^,\s)]+)')
        $ipc2 = [regex]::Matches($code, '(?i)installHandler\s*\(\s*[\w.$]+\s*,\s*([^,\s)]+)')
        $regCount = $ipc1.Count + $ipc2.Count
        if ($regCount -gt 0) {
            # only list real named channels (string literals, CHANNELS.X, CONSTANTS, ns:chan);
            # bare lowercase vars mean the channels are registered dynamically (a loop/table).
            $named = @(@($ipc1) + @($ipc2) | ForEach-Object { $_.Groups[1].Value } |
                       Where-Object { $_ -match '^[''"]' -or $_ -match '\.' -or $_ -cmatch '^[A-Z][A-Z0-9_]{2,}$' -or $_ -match ':' } |
                       ForEach-Object { $_.Trim('''"') } | Select-Object -Unique)
            $shown = if ($named.Count) { (@($named | Select-Object -First 20) -join ', ') } else { '(resolved at runtime)' }
            New-TcpkFinding -Module 'static' -RuleId 'electron.ipc-surface' `
                -Severity 'INFO' -Confidence 'Confirmed' `
                -Title "$regCount main-process IPC handler site(s) in $($t.Name)" `
                -File $t.FullName -Evidence "$regCount registration site(s); channels: $shown" -Cwe @('CWE-749') `
                -Description 'These ipcMain handlers are the privileged operations the renderer can invoke. Each should be reachable only from a trusted frame and kept least-privilege.' `
                -Fix 'Validate event.senderFrame (origin/URL) in privileged handlers; never execute renderer-supplied paths/commands unchecked.'
            if (-not [regex]::IsMatch($code, '(?i)(senderFrame|validateSender|isValidSender|isTrustedSender|event\.sender\.(getURL|url|origin))')) {
                New-TcpkFinding -Module 'static' -RuleId 'electron.ipc-no-sender-validation' `
                    -Severity 'LOW' -Confidence 'Inferred' `
                    -Title "IPC handlers do not validate the sender frame in $($t.Name)" `
                    -File $t.FullName -Evidence "$regCount handler(s); no event.senderFrame / sender-origin check found" -Cwe @('CWE-346','CWE-749') `
                    -Description 'The app registers main-process IPC handlers but no event.senderFrame / sender-origin validation was found. If untrusted or remote content is ever loaded into a renderer (or a sub-frame), it can invoke these handlers -- turning a renderer compromise / XSS into the privileged main-process action.' `
                    -Fix 'In each privileged handler, verify event.senderFrame.url (or origin) against an allow-list before acting; reject calls from unexpected frames.'
            }
        }

        # --- G4: unsafe archive extraction (zip-slip) in the app's OWN code ---
        # When the app extracts an archive (a project / update / import file), each entry must
        # be contained inside the target dir or a "../.." entry escapes it (zip-slip ->
        # arbitrary file write -> RCE). Flag extraction with no obvious containment guard;
        # recognise a guard (resolve+startsWith / sanitize / ".." reject) and demote to INFO.
        if ([regex]::IsMatch($code, '(?i)(\.extractAllTo\(|\.extractEntryTo\(|adm-zip|yauzl|unzipper|extract-zip|\bdecompress\(|tar\.(x|extract)\b|node-stream-zip)')) {
            $guarded = [regex]::IsMatch($code, '(?i)(validateArchiveEntries|sanitize\s*\(|\.startsWith\(\s*[^)]{0,40}(root|dest|target|workdir|out|base|resolved)|path\.relative\(|includes\(\s*[''"]\.\.|normalize\([^)]*\)[^;]{0,40}startsWith)')
            if (-not $guarded) {
                New-TcpkFinding -Module 'static' -RuleId 'electron.archive-zip-slip' `
                    -Severity 'MEDIUM' -Confidence 'Inferred' `
                    -Title "Archive extraction without a path-containment guard in $($t.Name)" `
                    -File $t.FullName -Evidence ([regex]::Match($code, '(?i)\.extractAllTo\(|\.extractEntryTo\(|adm-zip|yauzl|unzipper|extract-zip|decompress\(|tar\.(x|extract)|node-stream-zip').Value) -Cwe @('CWE-22','CWE-23') `
                    -Description 'The app extracts archive entries but no path-containment / canonicalization guard (resolve+startsWith, sanitize, reject "..") was found. A crafted entry named ..\..\path can write OUTSIDE the target directory (zip-slip) -- arbitrary file write, which on a desktop app (Startup folder, app dir, config) is a path to code execution.' `
                    -Fix 'Before writing each entry, resolve its destination and verify it stays under the extraction root (path.resolve(root,name).startsWith(root+sep)); reject entries containing "..".'
            } else {
                New-TcpkFinding -Module 'static' -RuleId 'electron.archive-extraction' `
                    -Severity 'INFO' -Confidence 'Confirmed' `
                    -Title "Archive extraction with a path-containment guard in $($t.Name)" `
                    -File $t.FullName -Evidence 'extraction present; a containment/sanitize check was found' -Cwe @('CWE-22') `
                    -Description 'The app extracts archives and a path-containment guard appears to be present. Verify the guard also rejects absolute paths and symlink/junction entries and runs for EVERY entry.' `
                    -Fix 'Confirm the containment check covers absolute paths and symlink/junction entries, not just relative "..".'
            }
        }

        # --- G5: embedded local HTTP server -- bind address + CORS ---
        # A desktop app that runs its own HTTP server should bind 127.0.0.1, not all
        # interfaces (0.0.0.0/::), or any machine on the LAN can reach it. Flag the bind
        # address, and note Access-Control-Allow-Origin rewriting.
        if ([regex]::IsMatch($code, '(?i)(http|https|net)\.createServer\(')) {
            $exposed  = [regex]::IsMatch($code, '(?i)\.listen\([^)]*[''"](0\.0\.0\.0|::)[''"]')
            $loopback = [regex]::IsMatch($code, '(?i)\.listen\([^)]*[''"](127\.0\.0\.1|localhost|::1)[''"]')
            $cnote = if ([regex]::IsMatch($code, '(?i)access-control-allow-origin')) { ' It also sets/rewrites Access-Control-Allow-Origin -- review the CORS policy (a permissive ACAO on a local server lets web origins reach it).' } else { '' }
            if ($exposed) {
                New-TcpkFinding -Module 'static' -RuleId 'electron.local-server-exposed' `
                    -Severity 'MEDIUM' -Confidence 'Confirmed' `
                    -Title "Embedded HTTP server bound to all interfaces in $($t.Name)" `
                    -File $t.FullName -Evidence ([regex]::Match($code, '(?i)\.listen\([^)]*[''"](0\.0\.0\.0|::)[''"]').Value) -Cwe @('CWE-1327','CWE-200') `
                    -Description ('The app runs an HTTP server bound to 0.0.0.0 / all interfaces, so any host on the LAN can reach it -- not just this machine.' + $cnote) `
                    -Fix 'Bind the local server to 127.0.0.1 (loopback) unless remote access is a deliberate, authenticated feature.'
            } elseif ($loopback) {
                New-TcpkFinding -Module 'static' -RuleId 'electron.local-server' `
                    -Severity 'INFO' -Confidence 'Confirmed' `
                    -Title "Embedded HTTP server (loopback) in $($t.Name)" `
                    -File $t.FullName -Evidence 'http.createServer + listen(127.0.0.1)' -Cwe @('CWE-200') `
                    -Description ('The app runs a local HTTP server bound to loopback (good).' + $cnote) `
                    -Fix 'Keep it loopback-only; if it proxies credentials/tokens, ensure other local processes cannot abuse it.'
            } else {
                New-TcpkFinding -Module 'static' -RuleId 'electron.local-server' `
                    -Severity 'LOW' -Confidence 'Inferred' `
                    -Title "Embedded HTTP server with an unclear bind address in $($t.Name)" `
                    -File $t.FullName -Evidence 'http.createServer present; no explicit 127.0.0.1 bind found' -Cwe @('CWE-1327','CWE-200') `
                    -Description ('The app runs an HTTP server but no explicit loopback bind was found; Node listen(port) defaults to ALL interfaces, exposing it to the LAN.' + $cnote) `
                    -Fix 'Pass 127.0.0.1 explicitly as the listen host.'
            }
        }
    }
}
