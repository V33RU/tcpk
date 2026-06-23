function Test-TcpkElectronJs {
<#
.SYNOPSIS
    A41. Electron JavaScript vulnerable-code-pattern scan (renderer-RCE / XSS sinks).

.DESCRIPTION
    Complements Test-TcpkElectron (which audits CONFIG: renderer flags, contextBridge / IPC
    surface, TLS cert validation). This scans the app's bundled JS (app.asar + loose
    main / preload / renderer scripts) for the dangerous CODE PATTERNS behind the published
    Electron attack chains -- XSS -> RCE, file:// execution, download-and-execute, local file
    leak, and prototype-pollution allow-list bypass:

      electronjs.exec-sink                child_process / eval / new Function / vm.runInThisContext
      electronjs.open-external-untrusted  shell.openExternal/openPath with file:// or a non-literal arg
      electronjs.dom-xss-sink             innerHTML / document.write / dangerouslySetInnerHTML / v-html / srcdoc
      electronjs.markdown-unsanitized     marked / markdown-it / showdown render with no DOMPurify / sanitize
      electronjs.resource-path-traversal  registerFileProtocol/... building a path with no containment guard
      electronjs.missing-nav-guard        BrowserWindow / loadURL with no will-navigate / setWindowOpenHandler deny
      electronjs.proto-pollution-sink     __proto__ / Object.prototype / constructor.prototype writes

    Every finding is Inferred -- a JS string-scan is a LEAD, not proof (TCPK has no JS taint /
    AST engine). The sink patterns also match bundled third-party libraries, so each is emitted
    ONCE per file with an occurrence COUNT and points the reviewer at app-authored code (esp.
    preload / main). Comments are stripped before matching. Pure ASCII.

.PARAMETER Path
    File or directory.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $item = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
    $dir  = if ($item -and $item.PSIsContainer) { $Path } elseif ($item) { Split-Path -Parent $item.FullName } else { $null }
    if (-not $dir) { return }

    # --- gate: Electron-family only (same markers as Test-TcpkElectron, kept independent) ---
    $isElectron = $false
    foreach ($marker in 'electron.exe','libcef.dll','nw.exe','ffmpeg.dll') {
        if (Get-ChildItem -LiteralPath $dir -Recurse -File -Filter $marker -ErrorAction SilentlyContinue | Select-Object -First 1) { $isElectron = $true; break }
    }
    $asars = @(Get-ChildItem -LiteralPath $dir -Recurse -File -Filter '*.asar' -ErrorAction SilentlyContinue)
    if ($asars.Count) { $isElectron = $true }
    if (-not $isElectron) { return }

    # --- data-driven sink rules ---
    $rules = @()
    try { $rules = @((Get-Content -LiteralPath (Join-Path $script:TcpkRoot 'Data\electron-js-sinks.json') -Raw | ConvertFrom-Json).rules) } catch { }
    foreach ($r in $rules) {
        if (-not $r.PSObject.Properties['_RX']) {
            $r | Add-Member -NotePropertyName _RX -NotePropertyValue ([regex]::new(
                $r.pattern,
                [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [System.Text.RegularExpressions.RegexOptions]::Multiline
            )) -Force
        }
    }

    # --- targets: asar (plaintext JS inside) + loose first-party JS ---
    $jsNames = @('main.js','preload.js','index.js','app.js','renderer.js','background.js')
    $targets = @()
    $targets += $asars
    $targets += @(Get-ChildItem -LiteralPath $dir -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -in $jsNames })

    foreach ($t in ($targets | Select-Object -Unique)) {
        $blob = ''
        try { $blob = [Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes($t.FullName)) } catch { continue }
        if (-not $blob) { continue }
        $code = Get-TcpkJsCodeOnly $blob
        if (-not $code) { continue }
        $leaf = $t.Name

        # (A) data-driven sink rules: one finding per (rule, file) with the occurrence count
        foreach ($r in $rules) {
            $mts = $r._RX.Matches($code)
            if ($mts.Count -eq 0) { continue }
            $sample = ($mts[0].Value -replace '\s+', ' ').Trim()
            if ($sample.Length -gt 60) { $sample = $sample.Substring(0, 60) + '...' }
            New-TcpkFinding -Module 'static' -RuleId "electronjs.$($r.id)" `
                -Severity $r.severity -Confidence 'Inferred' `
                -Title "$($r.title) in $leaf" -File $t.FullName `
                -Evidence "$($mts.Count) occurrence(s); e.g. $sample" -Cwe ([string[]]$r.cwe) `
                -Description "$($r.desc) NOTE: a JS pattern match is a LEAD, not proof (it also matches bundled libraries) -- review the app's own code, especially preload / main." `
                -Fix $r.fix
        }

        # (B) shell.openExternal / openPath with a non-literal-https argument (file-exec / download+exec)
        foreach ($m in [regex]::Matches($code, "(?i)(?:shell\s*\.\s*)?(?:openExternal|openPath)\s*\(\s*([^)\r\n]{0,100})")) {
            $argClean = ($m.Groups[1].Value).Trim().TrimStart([char[]]@('"', "'", [char]96, ' '))
            if ($argClean -match '^https://')  { continue }   # hard-coded https URL is fine
            if ($argClean -match '^mailto:')   { continue }
            $isFile = $argClean -match '^file:'
            $sev = if ($isFile) { 'HIGH' } else { 'MEDIUM' }
            New-TcpkFinding -Module 'static' -RuleId 'electronjs.open-external-untrusted' `
                -Severity $sev -Confidence 'Inferred' `
                -Title "shell.openExternal/openPath with non-literal target in $leaf" -File $t.FullName `
                -Evidence (($m.Value -replace '\s+', ' ').Trim()) -Cwe @('CWE-749','CWE-78') `
                -Description 'shell.openExternal / openPath is called with a value that is not a hard-coded https URL (a variable, template, or file:// path). If the target is attacker-influenced this is the file-execution / download-and-execute primitive in the Electron RCE chains (e.g. opening file:///.../Calculator.app or a dropped .bat / .ps1). Confirm the URL/path is validated against a strict allow-list and the scheme is restricted to https.' `
                -Fix 'Validate the target against an allow-list; permit only https:// (and known safe schemes); never open file:// or a path under the user download directory from untrusted input.'
        }

        # (C) markdown render without an HTML sanitizer
        if (($code -match '(?i)\b(?:marked|markdown-?it|showdown|remarkable|snarkdown)\b') -and
            (-not ($code -match '(?i)(?:DOMPurify|sanitize-?html|sanitizeHtml|purify|\bxss\s*\()'))) {
            New-TcpkFinding -Module 'static' -RuleId 'electronjs.markdown-unsanitized' `
                -Severity 'MEDIUM' -Confidence 'Inferred' `
                -Title "Markdown rendering without an HTML sanitizer in $leaf" -File $t.FullName `
                -Evidence 'markdown renderer present; no DOMPurify / sanitize-html detected' -Cwe @('CWE-79') `
                -Description 'A markdown renderer (marked / markdown-it / showdown / ...) is used and no HTML sanitizer (DOMPurify / sanitize-html) was found in the same script. Markdown that allows raw HTML (or image / link titles) is a classic Electron note-app XSS vector. Confirm rendered markdown is sanitized before it reaches the DOM.' `
                -Fix 'Sanitize rendered markdown with DOMPurify, or enable the renderer''s safe/sanitize mode and disable raw HTML.'
        }

        # (D) custom resource protocol without a path-containment guard (local file leak)
        if (($code -match '(?i)register(?:File|Stream|Buffer|Http)Protocol\s*\(') -and
            (-not ($code -match '(?i)(?:path\s*\.\s*normalize|path\s*\.\s*resolve|\.startsWith\s*\(|isInside|path-is-inside)'))) {
            New-TcpkFinding -Module 'static' -RuleId 'electronjs.resource-path-traversal' `
                -Severity 'MEDIUM' -Confidence 'Inferred' `
                -Title "Custom resource protocol without path containment in $leaf" -File $t.FullName `
                -Evidence 'registerFileProtocol / registerStreamProtocol present; no path.normalize/resolve/startsWith containment found' -Cwe @('CWE-22') `
                -Description 'The app registers a custom file / stream resource protocol but no path-containment guard (path.normalize/resolve + startsWith, or path-is-inside) was found in the same script. A request path built from the URL without containment allows ../ traversal to read arbitrary local files (the IDE / webview local-file-leak class, e.g. ..%2f..%2fetc%2fpasswd). Confirm the resolved path is constrained to an intended root.' `
                -Fix 'Canonicalize the requested path (path.resolve) and verify it stays under the intended root (startsWith / path-is-inside) before serving; reject ../ and URL-encoded traversal.'
        }

        # (E) creates a window / loads a URL but no navigation guard
        if ((($code -match '(?i)new\s+BrowserWindow\b') -or ($code -match '(?i)\.\s*loadURL\s*\(')) -and
            (-not ($code -match '(?i)(?:will-navigate|will-redirect|setWindowOpenHandler\s*\(|new-window)'))) {
            New-TcpkFinding -Module 'static' -RuleId 'electronjs.missing-nav-guard' `
                -Severity 'LOW' -Confidence 'Inferred' `
                -Title "No navigation / window-open guard in $leaf" -File $t.FullName `
                -Evidence 'BrowserWindow/loadURL present; no will-navigate / setWindowOpenHandler / new-window handler found' -Cwe @('CWE-1021') `
                -Description 'The app creates a window / loads URLs but no navigation lockdown (will-navigate / will-redirect deny, or setWindowOpenHandler) was found. Without it, a renderer (or an XSS) can navigate the window to an attacker origin -- the delivery step for the embed-then-exploit chains. Confirm navigation is restricted to known origins.' `
                -Fix 'Add a will-navigate / will-redirect handler that allow-lists known origins, and a setWindowOpenHandler that denies or restricts window.open / target=_blank.'
        }

        # (F) script-initiated navigation sink with a non-literal target -- the residual risk the
        # DOM-tree-type defense explicitly CANNOT catch: window.open / location.href = <var>, or a
        # javascript: URL navigates the top document and can execute a payload.
        foreach ($m in [regex]::Matches($code, "(?i)(?:location\s*\.\s*(?:href|assign|replace)|window\s*\.\s*open)\s*(?:=|\()\s*([^);,\r\n]{0,100})")) {
            $navArg = ($m.Groups[1].Value).Trim().TrimStart([char[]]@('"', "'", [char]96, ' '))
            if ([string]::IsNullOrWhiteSpace($navArg)) { continue }
            if ($navArg -match '^(?:https://|#|/|\.|about:|mailto:)') { continue }   # literal-safe target
            $isJs = $navArg -match '^javascript:'
            $sev = if ($isJs) { 'HIGH' } else { 'MEDIUM' }
            New-TcpkFinding -Module 'static' -RuleId 'electronjs.nav-injection-sink' `
                -Severity $sev -Confidence 'Inferred' `
                -Title "Script-initiated navigation with non-literal target in $leaf" -File $t.FullName `
                -Evidence (($m.Value -replace '\s+', ' ').Trim()) -Cwe @('CWE-601','CWE-79') `
                -Description 'location.href/assign/replace or window.open receives a non-literal value (variable, template, or a javascript: URL). If attacker-influenced this is the script-initiated top-level navigation vector -- navigate the app to an attacker page, or execute a javascript: payload in the top document -- the residual risk that even DOM-mutation defenses explicitly cannot catch. Confirm the target is validated.' `
                -Fix 'Validate navigation targets against an allow-list; block javascript: / data: schemes; restrict navigation with Electron will-navigate / setWindowOpenHandler.'
        }

        # (G) webContents.executeJavaScript with a non-literal argument -- main-process JS injected
        # into a renderer; with user/remote-derived input this is code execution (Inspectron's
        # cross-context JS-execution check).
        foreach ($m in [regex]::Matches($code, "(?i)\.executeJavaScript\s*\(\s*([^)\r\n]{0,80})")) {
            $ejArg = ($m.Groups[1].Value).Trim()
            if ($ejArg -match '^["''`]') { continue }   # a fixed string-literal script is the common safe case
            if ([string]::IsNullOrWhiteSpace($ejArg)) { continue }
            New-TcpkFinding -Module 'static' -RuleId 'electronjs.execute-js-dynamic' `
                -Severity 'MEDIUM' -Confidence 'Inferred' `
                -Title "executeJavaScript with a non-literal argument in $leaf" -File $t.FullName `
                -Evidence (($m.Value -replace '\s+', ' ').Trim()) -Cwe @('CWE-94','CWE-95') `
                -Description 'webContents.executeJavaScript is called with a non-literal argument (a variable or template). Main-process code injected into a renderer from user/remote-derived input is arbitrary JS execution in that renderer context. Confirm the script is a fixed literal, not built from untrusted input.' `
                -Fix 'Pass only fixed literal scripts to executeJavaScript; never build the script from user/remote input -- use a fixed IPC API for dynamic behavior.'
        }
    }
}
