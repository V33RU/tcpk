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

    # --- WDAC / AppLocker bypass: signed host exe + writable resources ---
    # Electron apps run a signed host exe that loads app code from resources/.
    # WDAC/AppLocker trust the signed exe, but if resources/ is user-writable an
    # attacker can replace the app code while the trusted binary still launches it.
    if ($env:OS -eq 'Windows_NT') {
        $wdacPrincipals = '(?i)\b(Everyone|Authenticated Users|Users|INTERACTIVE|BUILTIN\\Users)\b'
        $wdacRights     = 'Write|Modify|FullControl'
        $exes = @(Get-ChildItem -LiteralPath $dir -File -Filter '*.exe' -ErrorAction SilentlyContinue |
                  Where-Object { -not (Test-TcpkIsFrameworkFile $_.Name) })
        $exeIdx = 0
        foreach ($exe in $exes) {
            if (Test-TcpkCheckBudgetExpired) { break }
            $exeIdx++
            Write-TcpkHeartbeat -Component 'Test-TcpkElectron' -Index $exeIdx -Total $exes.Count -Current $exe.Name -CurrentBytes $exe.Length
            $sig = $null
            try { $sig = Get-AuthenticodeSignature -LiteralPath $exe.FullName -ErrorAction Stop } catch { }
            if (-not $sig -or $sig.Status -ne 'Valid') { continue }
            $resDir = Join-Path $dir 'resources'
            $appDir = Join-Path $resDir 'app'
            $writableTarget = $null; $wdacEvidence = ''
            foreach ($checkDir in @($appDir, $resDir)) {
                if (-not (Test-Path -LiteralPath $checkDir)) { continue }
                try { $wAcl = Get-Acl -LiteralPath $checkDir -ErrorAction Stop } catch { continue }
                $wBad = $wAcl.Access | Where-Object {
                    $_.IdentityReference.Value -match $wdacPrincipals -and
                    $_.FileSystemRights -match $wdacRights -and
                    $_.AccessControlType -eq 'Allow'
                }
                if ($null -ne $wBad -and @($wBad).Count -gt 0) {
                    $writableTarget = $checkDir
                    $wdacEvidence = ($wBad | ForEach-Object { "$($_.IdentityReference) -> $($_.FileSystemRights)" }) -join '; '
                    break
                }
            }
            if ($writableTarget) {
                New-TcpkFinding -Module 'static' -RuleId 'electron.wdac-bypass' `
                    -Severity 'HIGH' -Confidence 'Confirmed' `
                    -Title "WDAC/AppLocker bypass: signed Electron host + writable resources" `
                    -File $exe.FullName `
                    -Evidence "signed=$($sig.SignerCertificate.Subject); writable=$writableTarget; $wdacEvidence" `
                    -Cwe @('CWE-427','CWE-732') `
                    -Description ('The Electron host executable is Authenticode-signed, so WDAC and AppLocker ' +
                        'policies that trust signed binaries allow it. But the resources directory where the ' +
                        'actual application code lives is writable by non-admin users -- an attacker can ' +
                        'replace the app code (resources/app/ or app.asar) while the signed exe still launches ' +
                        'it. Full code-execution bypass under the trusted signed identity (T1218).') `
                    -Fix 'Restrict write access to the resources directory to administrators/SYSTEM only. Consider WDAC path rules that validate resources content.'
                break
            }
        }
    }

    # --- Squirrel.Windows auto-updater ---
    $sqExe = Join-Path $dir 'Update.exe'
    if (-not (Test-Path -LiteralPath $sqExe)) {
        $sqExe = Join-Path (Split-Path -Parent $dir) 'Update.exe'
    }
    if (Test-Path -LiteralPath $sqExe) {
        New-TcpkFinding -Module 'static' -RuleId 'electron.squirrel-updater' `
            -Severity 'LOW' -Confidence 'Confirmed' `
            -Title 'Squirrel.Windows auto-updater present' `
            -File $sqExe `
            -Evidence 'Update.exe found in or near the application directory' `
            -Cwe @('CWE-494') `
            -Description ('Squirrel.Windows (Update.exe) manages auto-updates for this Electron app. ' +
                'Squirrel downloads and executes updates with the app''s identity. If the update channel ' +
                'uses HTTP or an attacker can MITM the update server, arbitrary code execution follows. ' +
                'Squirrel has historically lacked robust signature verification on downloaded packages.') `
            -Fix 'Ensure the update feed URL uses HTTPS with certificate pinning. Consider migrating to electron-updater with differential + signature verification.'
    }

    # --- electron-updater version check (CVE-2024-39698) ---
    $euPkgPaths = @(
        (Join-Path $dir 'package.json'),
        (Join-Path (Join-Path $dir 'resources') 'app\package.json'),
        (Join-Path (Join-Path $dir 'resources') 'package.json')
    )
    foreach ($pjp in $euPkgPaths) {
        if (-not (Test-Path -LiteralPath $pjp)) { continue }
        try { $euPkg = Get-Content -LiteralPath $pjp -Raw -ErrorAction Stop | ConvertFrom-Json } catch { continue }
        $euVer = $null
        foreach ($dk in @('dependencies','devDependencies')) {
            if ($euPkg.$dk -and $euPkg.$dk.'electron-updater') {
                $euVer = $euPkg.$dk.'electron-updater'; break
            }
        }
        if (-not $euVer) { continue }
        $euNum = if ($euVer -match '(\d+\.\d+\.\d+)') { $matches[1] } else { $null }
        if (-not $euNum) { continue }
        $euParts = $euNum -split '\.'
        $euMaj = [int]$euParts[0]; $euMin = [int]$euParts[1]
        if ($euMaj -lt 6 -or ($euMaj -eq 6 -and $euMin -lt 3)) {
            New-TcpkFinding -Module 'static' -RuleId 'electron.updater-sig-bypass' `
                -Severity 'HIGH' -Confidence 'Confirmed' `
                -Title "electron-updater ${euNum}: differential update signature bypass (CVE-2024-39698)" `
                -File $pjp `
                -Evidence "electron-updater@$euVer" `
                -Cwe @('CWE-347','CWE-494') `
                -Description ('electron-updater before 6.3.0-alpha.6 does not verify the signature of ' +
                    'differential (blockmap-based) updates. An attacker who can MITM or compromise the ' +
                    'update server can serve a malicious differential update that is applied without ' +
                    'signature verification -- full code execution with the app''s identity.') `
                -Fix 'Upgrade electron-updater to >= 6.3.0 where differential updates are signature-verified.'
        }
        break
    }

    # --- bundled runtime version: Electron / Chromium / Node (the biggest CVE surface) ---
    # The embedded Chromium version is NOT in any deps.json -- it is a string in the main exe.
    # Extract it and flag an outdated bundle (Chromium ships security fixes EVERY major, so a
    # build several majors behind is missing many High/Critical renderer-RCE fixes). The exact
    # advisories come from the OSV electron@<ver> lookup in Get-TcpkCveMatches (-OnlineCve).
    $rv = Get-TcpkRuntimeVersions -Path $dir
    if ($rv) {
        $verEvid = "Electron=$($rv.Electron); Chromium=$($rv.Chromium); Node=$($rv.Node)"
        New-TcpkFinding -Module 'static' -RuleId 'electron.runtime-version' `
            -Severity 'INFO' -Confidence 'Confirmed' `
            -Title "Bundled runtime: Electron $($rv.Electron), Chromium $($rv.Chromium), Node $($rv.Node)" `
            -File $rv.File -Evidence $verEvid `
            -Description 'Detected the embedded Electron/Chromium/Node version from the main binary. The embedded Chromium is the primary CVE surface for an Electron app; see electron.outdated-runtime and run with -OnlineCve for the matching advisories.'

        $bl = $null
        try { $bl = Get-Content -LiteralPath (Join-Path $script:TcpkRoot 'Data\runtime-baseline.json') -Raw | ConvertFrom-Json } catch { }
        if ($bl) {
            $shipMaj = Get-TcpkVersionMajor $rv.Chromium
            $latMaj  = Get-TcpkVersionMajor $bl.chromium.latestStable
            $eMaj    = Get-TcpkVersionMajor $rv.Electron
            $eFloor  = [int]$bl.electron.supportedFloorMajor
            $delta   = if ($null -ne $shipMaj -and $null -ne $latMaj) { $latMaj - $shipMaj } else { $null }

            $sev = $null; $why = ''
            if ($null -ne $eMaj -and $eMaj -lt $eFloor) {
                $sev = 'MEDIUM'; $why = "Electron $($rv.Electron) is past end-of-support (supported majors are >= $eFloor), so it receives no further security backports."
            } elseif ($null -ne $delta -and $delta -ge 3) {
                $sev = 'MEDIUM'; $why = "the embedded Chromium ($($rv.Chromium)) is $delta major versions behind the current stable ($($bl.chromium.latestStable)); Chromium ships security fixes every major."
            } elseif ($null -ne $delta -and $delta -ge 1) {
                $sev = 'LOW'; $why = "the embedded Chromium ($($rv.Chromium)) is $delta major version(s) behind the current stable ($($bl.chromium.latestStable))."
            }
            if ($sev) {
                New-TcpkFinding -Module 'static' -RuleId 'electron.outdated-runtime' `
                    -Severity $sev -Confidence 'Inferred' `
                    -Title "Outdated bundled runtime: Electron $($rv.Electron) / Chromium $($rv.Chromium)" `
                    -File $rv.File `
                    -Evidence "$verEvid | baseline asOf=$($bl.asOf): electron latest=$($bl.electron.latestStable), chromium latest=$($bl.chromium.latestStable)" `
                    -Cwe @('CWE-1104','CWE-1395') `
                    -Description ("The app bundles its own Chromium/Node runtime, and $why As of the TCPK baseline ($($bl.asOf)), this build is behind current stable, so it is likely missing Chromium/V8 and Node security fixes released since -- several of which are typically remote code execution in the renderer (most relevant when the app loads remote or attacker-influenced web content). Run with -OnlineCve to enumerate the specific advisories (OSV electron@$($rv.Electron)), or check electronjs.org/releases.") `
                    -Fix 'Upgrade the bundled Electron to the latest supported release (it carries the patched Chromium + Node) and rebuild; track Electron security releases.'
            }
        }
    }

    $bad = @{
        'nodeIntegration'              = @{ rx = 'nodeIntegration["'']?\s*:\s*true';                sev='CRITICAL'; desc='Renderer has full Node.js access; any XSS becomes RCE.' }
        'contextIsolation'             = @{ rx = 'contextIsolation["'']?\s*:\s*false';              sev='HIGH';     desc='Preload and page JS share a context; enables prototype-pollution -> RCE.' }
        'webSecurity'                  = @{ rx = 'webSecurity["'']?\s*:\s*false';                   sev='HIGH';     desc='Same-origin policy disabled in the renderer.' }
        'allowRunningInsecureContent'  = @{ rx = 'allowRunningInsecureContent["'']?\s*:\s*true';    sev='MEDIUM';   desc='Mixed/insecure content allowed (downgrade).' }
        'sandbox'                      = @{ rx = 'sandbox["'']?\s*:\s*false';                       sev='MEDIUM';   desc='Renderer process not sandboxed.' }
        'enableRemoteModule'           = @{ rx = 'enableRemoteModule["'']?\s*:\s*true';             sev='HIGH';     desc='Legacy remote module exposed to the renderer.' }
        'nodeIntegrationInSubframes'   = @{ rx = 'nodeIntegrationInSub[fF]rames["'']?\s*:\s*true';  sev='HIGH';     desc='Node.js enabled in child frames/iframes; an iframe to attacker content gains Node -> RCE (the Element / CVE-2022-29247 vector).' }
        'experimentalFeatures'         = @{ rx = 'experimentalFeatures["'']?\s*:\s*true';           sev='MEDIUM';   desc='Unstable/experimental Chromium features enabled -- unvetted behavior expands the attack surface.' }
        'experimentalCanvasFeatures'   = @{ rx = 'experimentalCanvasFeatures["'']?\s*:\s*true';     sev='MEDIUM';   desc='Experimental Chromium canvas features enabled -- unvetted behavior expands the attack surface.' }
        'enableBlinkFeatures'          = @{ rx = 'enableBlinkFeatures["'']?\s*:\s*["''][^"'']';     sev='MEDIUM';   desc='Non-default Blink features force-enabled; can re-expose disabled/insecure web behaviors.' }
        'nodeIntegrationInWorkers'     = @{ rx = 'nodeIntegrationInWorkers["'']?\s*:\s*true';       sev='HIGH';     desc='Node.js enabled inside web workers; an attacker-controlled worker gains Node -> RCE.' }
        'webviewTag'                   = @{ rx = 'webviewTag["'']?\s*:\s*true';                     sev='MEDIUM';   desc='The <webview> tag is enabled; a webview can spawn higher-privileged renderers and load remote content (the RCE-via-webView surface).' }
        'enableWebSQL'                 = @{ rx = '\bwebSQL["'']?\s*:\s*true';                        sev='LOW';      desc='Deprecated WebSQL storage enabled -- an obsolete, removed-from-browsers engine; disable to shrink the attack surface.' }
    }

    # search targets: every .asar (JS is plaintext inside) + loose main/preload JS,
    # INCLUDING webpack/rollup-bundled output (main.bundle.js, background.js, a hashed
    # main.a1b2c3.js, etc.) which the old exact-name allow-list silently skipped -- so a
    # non-asar / bundled Electron app previously reported nothing. Match a bounded set of
    # main-process-ish names, exclude node_modules, and cap size to avoid slurping a giant
    # renderer/vendor bundle. NB: Get-ChildItem -Include is SILENTLY IGNORED with
    # -LiteralPath (it would return EVERY file), so filter by name explicitly.
    $jsRx = '(?i)^(main|preload|index|app|background|electron(-main)?|entry|renderer)(\.[\w-]+)?\.js$'
    $targets = @()
    $targets += $asars
    # NO SIZE FILTER. There used to be a `-lt 5MB` here, and it was backwards: a
    # webpack/esbuild-bundled Electron main.js is routinely 5-50 MB, and that bundle is
    # exactly where BrowserWindow/webPreferences lives. So the cap silently skipped the
    # one file this check exists to read, on precisely the apps most likely to be
    # misconfigured, and reported nothing. Large files are streamed below instead.
    $targets += @(Get-ChildItem -LiteralPath $dir -Recurse -File -Filter '*.js' -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -notmatch '(?i)[\\/]node_modules[\\/]' -and $_.Name -match $jsRx })

    # --- insecure-by-DEFAULT: an OLD Electron that OMITS a hardening key inherits the insecure
    # default -- nodeIntegration is ON before Electron 5, contextIsolation OFF before 12, the
    # renderer sandbox OFF before 20. The explicit-value checks below only fire on ':true'/':false';
    # a build that simply never sets the key silently passes, though it is the MOST common real
    # misconfig. Correlate the extracted major with key ABSENCE across the app's main/preload/asar
    # code (a key even in a comment counts as 'set' -> conservative, no false alarm). Inferred: a
    # version-default inference, not a proven config -- verify the webPreferences blocks.
    if ($rv) {
        $eMaj = Get-TcpkVersionMajor $rv.Electron
        if ($null -ne $eMaj) {
            $sawBW  = $false
            $sawKey = @{ nodeIntegration = $false; contextIsolation = $false; sandbox = $false }
            # Streamed: an app.asar or a bundled main.js can be hundreds of MB, and
            # ReadAllBytes on one of those was both a memory spike and, for the .js side,
            # unreachable behind the old 5 MB filter. This only needs presence flags, so
            # it stops as soon as all four are set.
            foreach ($t in ($targets | Select-Object -Unique)) {
                $st = @{ Stop = $false; BW = $sawBW; K = $sawKey }
                Invoke-TcpkOnFileText -Path $t.FullName -State $st -Utf8Only -OnText {
                    param($Text, $Src, $S)
                    if (-not $Text) { return }
                    if (-not $S.BW -and ($Text -match 'BrowserWindow' -or $Text -match 'webPreferences')) { $S.BW = $true }
                    foreach ($k in @('nodeIntegration', 'contextIsolation', 'sandbox')) {
                        if (-not $S.K[$k] -and [regex]::IsMatch($Text, ($k + '["'']?\s*:'))) { $S.K[$k] = $true }
                    }
                    if ($S.BW -and $S.K['nodeIntegration'] -and $S.K['contextIsolation'] -and $S.K['sandbox']) { $S.Stop = $true }
                }
                $sawBW = $st.BW
            }
            if ($sawBW) {
                $defaults = @(
                    @{ key = 'nodeIntegration';  floor = 5;  sev = 'CRITICAL'; state = 'defaults to TRUE';  cwe = @('CWE-1188','CWE-94'); why = 'the renderer has full Node.js access, so any XSS or remote / attacker-influenced content becomes RCE' }
                    @{ key = 'contextIsolation'; floor = 12; sev = 'HIGH';     state = 'defaults to FALSE'; cwe = @('CWE-1188');           why = 'preload and page JS share a context (prototype-pollution -> RCE, and any leaked Node primitive is reachable from the page)' }
                    @{ key = 'sandbox';          floor = 20; sev = 'MEDIUM';   state = 'defaults to OFF';   cwe = @('CWE-1188');           why = 'a compromised renderer has a wider break-out surface' }
                )
                foreach ($d in $defaults) {
                    if ($eMaj -lt $d.floor -and -not $sawKey[$d.key]) {
                        New-TcpkFinding -Module 'static' -RuleId ("electron.insecure-default-" + $d.key) `
                            -Severity $d.sev -Confidence 'Inferred' `
                            -Title "Electron $($rv.Electron): $($d.key) $($d.state) and is never set" `
                            -File $rv.File `
                            -Evidence "Electron major $eMaj (< $($d.floor), where the default changed); no '$($d.key)' key found in the app's main / preload / asar code" `
                            -Cwe $d.cwe `
                            -Description ("This Electron build ($($rv.Electron)) is old enough that $($d.key) $($d.state) by default, and no explicit $($d.key) setting was found in the scanned main / preload / asar code -- so any BrowserWindow that does not override it inherits the insecure default, meaning $($d.why). This is the most common real-world Electron misconfiguration: not an explicit ':true' / ':false', but an OMITTED key on an old runtime. Confirm every webPreferences block sets $($d.key) explicitly, and upgrade Electron.") `
                            -Fix "Set $($d.key) explicitly on every BrowserWindow (nodeIntegration:false, contextIsolation:true, sandbox:true, webSecurity:true) and upgrade to a supported Electron release."
                    }
                }
            }
        }
    }

    foreach ($t in ($targets | Select-Object -Unique)) {
        # STREAMED, NOT SIZE-CAPPED. This used to be one ReadAllBytes, which on a 200 MB
        # app.asar or a bundled main.js meant several hundred MB of string per file. Large
        # files now arrive as bounded overlapping chunks; small ones still arrive whole, so
        # their behaviour is byte-for-byte unchanged. -Utf8Only because a UTF-16 decode of
        # JavaScript is noise.
        #
        # The 64 KB overlap deliberately re-presents boundary bytes, so a match sitting in it
        # is seen in two chunks. Invoke-TcpkAudit's triage would collapse those on
        # RuleId::File::Title, but a direct call (the GUI runs single checks) does not go
        # through triage, so dedupe here on the same key rather than rely on the caller.
        $seenF = @{}
        $st = @{ Stop = $false }
        $found = @(Invoke-TcpkOnFileText -Path $t.FullName -State $st -Utf8Only -OnText {
            param($blob, $Src, $S)
            if (-not $blob) { return }
            # Strip JS comments first so a flag that only appears in a comment (e.g.
            # "// we avoid webSecurity:false") does NOT fire -- a real false-positive class.
            $code = Get-TcpkJsCodeOnly $blob
            if (-not $code) { return }
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

        # --- TLS certificate-validation bypass (JS) ---
        # The custom cert-verify path is the highest-impact Electron footgun and is INVISIBLE
        # to the .NET IL prover, so this JS-aware check is what catches it. Accept-all shapes:
        #   * setCertificateVerifyProc present but NO callback(-2) reject path -> every cert is
        #     accepted (the trust-on-first-use-that-never-rejects shape).
        #   * rejectUnauthorized:false / NODE_TLS_REJECT_UNAUTHORIZED=0 -> validation disabled.
        #   * an unconditional certificate-error handler that calls callback(true).
        if ([regex]::IsMatch($code, 'setCertificateVerifyProc\s*\(')) {
            # A safe custom verifier rejects a mismatch with callback(-2). If none exists, the
            # callback can only ever succeed -> any server certificate is trusted.
            $hasReject = [regex]::IsMatch($code, 'callback\s*\(\s*-\s*2\b')
            if (-not $hasReject) {
                New-TcpkFinding -Module 'static' -RuleId 'electron.cert-validation-bypass' `
                    -Severity 'HIGH' -Confidence 'Inferred' `
                    -Title "Electron certificate verification has no reject path (accepts any cert) in $($t.Name)" `
                    -File $t.FullName -Evidence 'session.setCertificateVerifyProc present; no callback(-2) reject path found' -Cwe @('CWE-295','CWE-297') `
                    -Description 'The app overrides Chromium certificate verification via session.setCertificateVerifyProc, but no callback(-2) reject path was found -- so the callback can only succeed and ANY server certificate is trusted. A network/on-path attacker can present a forged certificate and MITM the app''s TLS (credentials, session/WS tokens, control traffic). Trust-on-first-use pinning that re-pins instead of rejecting on mismatch has the same effect. Open the verify callback and confirm it returns callback(-2) on a fingerprint/chain mismatch.' `
                    -Fix 'Return callback(-2) when the certificate chain or pinned fingerprint does not match; never succeed unconditionally. Scope any self-signed allowance to a verified, exact-matched host.'
            }
        }
        if ([regex]::IsMatch($code, 'rejectUnauthorized["'']?\s*:\s*false')) {
            New-TcpkFinding -Module 'static' -RuleId 'electron.cert-validation-bypass' `
                -Severity 'HIGH' -Confidence 'Confirmed' `
                -Title "TLS validation disabled (rejectUnauthorized:false) in $($t.Name)" `
                -File $t.FullName -Evidence ([regex]::Match($code, 'rejectUnauthorized["'']?\s*:\s*false').Value) -Cwe @('CWE-295') `
                -Description 'A TLS request sets rejectUnauthorized:false, disabling certificate validation for that connection -- any server certificate is accepted, so the connection is trivially MITM-able.' `
                -Fix 'Remove rejectUnauthorized:false; validate (and, if needed, pin) the server certificate.'
        }
        if ([regex]::IsMatch($code, 'NODE_TLS_REJECT_UNAUTHORIZED["'']?\s*[:=]\s*["'']?0')) {
            New-TcpkFinding -Module 'static' -RuleId 'electron.cert-validation-bypass' `
                -Severity 'HIGH' -Confidence 'Confirmed' `
                -Title "Process-wide TLS validation disabled (NODE_TLS_REJECT_UNAUTHORIZED=0) in $($t.Name)" `
                -File $t.FullName -Evidence ([regex]::Match($code, 'NODE_TLS_REJECT_UNAUTHORIZED["'']?\s*[:=]\s*["'']?0').Value) -Cwe @('CWE-295') `
                -Description 'NODE_TLS_REJECT_UNAUTHORIZED is set to 0, disabling certificate validation for EVERY TLS connection in the Node process -- all HTTPS/WSS traffic becomes MITM-able.' `
                -Fix 'Never set NODE_TLS_REJECT_UNAUTHORIZED=0 in shipped code; validate certificates per connection.'
        }
        if ([regex]::IsMatch($code, 'certificate-error') -and
            [regex]::IsMatch($code, 'event\.preventDefault\s*\(') -and
            [regex]::IsMatch($code, 'callback\s*\(\s*true\s*\)')) {
            New-TcpkFinding -Module 'static' -RuleId 'electron.cert-error-accept-all' `
                -Severity 'HIGH' -Confidence 'Inferred' `
                -Title "Electron certificate-error handler trusts the cert in $($t.Name)" `
                -File $t.FullName -Evidence "certificate-error + event.preventDefault() + callback(true)" -Cwe @('CWE-295') `
                -Description 'The app handles the certificate-error event with event.preventDefault() + callback(true), overriding Chromium to trust a certificate it rejected. If unconditional, this accepts ANY invalid certificate (MITM). Confirm the handler trusts only a specific, fingerprint-verified certificate.' `
                -Fix 'Do not override certificate-error to trust rejected certs; if pinning a known self-signed cert, compare its fingerprint and accept only on an exact match.'
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

        # --- G3b: IPC handler body reaches a dangerous sink (renderer-driven RCE) ---
        # The highest-impact Electron IPC bug: a handler that feeds its renderer-supplied
        # argument into exec / shell / eval / fs / loadURL. We parse each handler body and
        # correlate a payload param with a sink -- direct arg flow -> Confirmed (higher sev);
        # a sink merely reachable from the handler -> Inferred (arg flow not proven).
        $ipcSinks = @(
            @{ rx = '\b(execSync|execFileSync|execFile|exec|spawnSync|spawn|fork)\s*\('; kind = 'command-execution'; sev = 'CRITICAL'; inf = 'HIGH';   cwe = @('CWE-78','CWE-94') }
            @{ rx = '\beval\s*\(|new\s+Function\s*\(';                                    kind = 'dynamic-code-eval'; sev = 'CRITICAL'; inf = 'HIGH';   cwe = @('CWE-95','CWE-94') }
            @{ rx = '\bshell\s*\.\s*(openExternal|openPath)\s*\(';                        kind = 'shell-open';        sev = 'HIGH';     inf = 'MEDIUM'; cwe = @('CWE-78','CWE-601') }
            @{ rx = '\bfs\s*\.\s*(writeFile|writeFileSync|appendFile|appendFileSync|createWriteStream|unlink|unlinkSync|rename|renameSync|copyFile|copyFileSync)\s*\('; kind = 'filesystem-write'; sev = 'HIGH'; inf = 'MEDIUM'; cwe = @('CWE-22','CWE-73') }
            @{ rx = '\bfs\s*\.\s*(readFile|readFileSync|createReadStream)\s*\(';          kind = 'filesystem-read';   sev = 'MEDIUM';   inf = 'LOW';    cwe = @('CWE-22') }
            @{ rx = '\.loadURL\s*\(|\.loadFile\s*\(';                                     kind = 'navigation';        sev = 'MEDIUM';   inf = 'LOW';    cwe = @('CWE-601') }
        )
        foreach ($h in (Get-TcpkJsHandlerBodies -Code $code)) {
            if (-not $h.Body) { continue }
            foreach ($s in $ipcSinks) {
                $sm = [regex]::Match($h.Body, $s.rx)
                if (-not $sm.Success) { continue }
                # is a renderer-supplied payload param inside the sink's argument region?
                $tainted = $false
                if ($h.Payload.Count) {
                    $as = $sm.Index + $sm.Length
                    $slice = $h.Body.Substring($as, [Math]::Min(240, $h.Body.Length - $as))
                    foreach ($pp in $h.Payload) { if ($pp -and [regex]::IsMatch($slice, '\b' + [regex]::Escape($pp) + '\b')) { $tainted = $true; break } }
                }
                $sev  = if ($tainted) { $s.sev } else { $s.inf }
                $conf = if ($tainted) { 'Confirmed' } else { 'Inferred' }
                $chanTxt = if ($h.Channel) { "'$($h.Channel)'" } else { '(runtime-resolved channel)' }
                $flow = if ($tainted) { 'the renderer-supplied argument reaches the sink directly' }
                        else { 'the sink is reachable from this renderer-invokable handler (direct arg flow not proven)' }
                New-TcpkFinding -Module 'static' -RuleId 'electron.ipc-handler-sink' `
                    -Severity $sev -Confidence $conf `
                    -Title "IPC handler $chanTxt reaches a $($s.kind) sink in $($t.Name)" `
                    -File $t.FullName `
                    -Evidence ("channel $chanTxt -> $($sm.Value)  [payload params: $(@($h.Payload) -join ', ')]") `
                    -Cwe $s.cwe `
                    -Description ("The main-process IPC handler for channel $chanTxt calls a $($s.kind) sink, and $flow. Any renderer can invoke this channel over IPC, and if untrusted / remote content is ever loaded into a renderer (or an injected sub-frame), an XSS invokes it too -- turning a renderer action into a main-process $($s.kind). This is the highest-impact Electron IPC bug class.") `
                    -Fix 'Never pass renderer-supplied data into exec / shell / eval / fs / loadURL. Validate the payload against a strict allow-list, prefer execFile with a fixed binary + argument array (no shell string), and verify event.senderFrame before acting.'
                break   # one finding per handler, most-severe sink first
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

        # --- auto-updater HTTP feed URL (MITM-able update channel) ---
        if ([regex]::IsMatch($code, '(?i)(autoUpdater\.setFeedURL|autoUpdater\.checkForUpdates|update-electron-app)')) {
            $httpFeed = [regex]::Match($code, '(?i)(?:setFeedURL|feedUrl|url)\s*[:=(]\s*[''"]http://')
            if ($httpFeed.Success) {
                New-TcpkFinding -Module 'static' -RuleId 'electron.update-http' `
                    -Severity 'HIGH' -Confidence 'Confirmed' `
                    -Title "Auto-updater uses plaintext HTTP feed URL in $($t.Name)" `
                    -File $t.FullName -Evidence $httpFeed.Value -Cwe @('CWE-494','CWE-319') `
                    -Description ('The auto-updater feed URL uses plaintext HTTP, so an on-path attacker ' +
                        'can serve a malicious update package -- arbitrary code execution with the app''s ' +
                        'identity. This is the simplest Electron supply-chain attack.') `
                    -Fix 'Use HTTPS for the update feed URL and verify the update signature.'
            }
        }
        })
        foreach ($fnd in $found) {
            $k = "$($fnd.RuleId)::$($fnd.Title)"
            if ($seenF.ContainsKey($k)) { continue }
            $seenF[$k] = $true
            $fnd
        }
    }
}
