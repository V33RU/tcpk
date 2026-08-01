function Test-TcpkCrashReporter {
<#
.SYNOPSIS
    A47. Electron / Crashpad crash-reporting exposure.

.DESCRIPTION
    Electron applications do NOT use Windows Error Reporting. They ship Crashpad
    (crashpad_handler.exe / chrome_crashpad_handler.exe) and configure it from JS
    via crashReporter.start(). So for an Electron target the WER checks
    (Test-TcpkWerPolicy, Test-TcpkWerExposure) do not apply, and this one does.

    A crash minidump captures process memory at fault time. For a chat, mail or
    trading client that means message content, session tokens and keys can land
    on disk, and can be uploaded off the machine, depending entirely on choices
    the vendor made in their own code.

    Checks:
      1. Crashpad handler binaries shipped with the application.
      2. crashReporter.start() configuration recovered from app.asar and loose
         first-party JS: uploadToServer, submitURL, and any extra{} parameters.
      3. The Crashpad database under the app's userData directory: whether it is
         user-writable, and whether dumps are sitting in it.

    ATTRIBUTION. The Crashpad database lives INSIDE the application's own
    userData directory (%APPDATA%\<productName>\Crashpad), not in a shared
    machine location, so everything found under it belongs to this application
    by construction. productName is resolved from the app's package.json, with
    the main executable's ProductName resource as a fallback. Nothing outside
    that directory is examined, so no other product's crash data can be
    reported against this target.

    This is a STATIC check. It reads configuration and on-disk artefacts and
    never launches the application.

.PARAMETER Path
    File or directory to scan.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $item = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
    if (-not $item) { return }
    $dir = if ($item.PSIsContainer) { $item.FullName } else { $item.DirectoryName }

    # --- 1. Crashpad handler binaries -------------------------------------------
    $handlerNames = @('crashpad_handler.exe', 'chrome_crashpad_handler.exe')
    $handlers = @(Get-TcpkChildItemSafe -Path $dir -File |
        Where-Object { $handlerNames -contains $_.Name.ToLowerInvariant() })

    $asars = @(Get-TcpkChildItemSafe -Path $dir -File |
        Where-Object { $_.Extension.ToLowerInvariant() -eq '.asar' })

    # Only an Electron-shaped target is in scope. Without either signal this
    # check has nothing to say and stays silent rather than guessing.
    if (-not $handlers.Count -and -not $asars.Count) { return }

    if ($handlers.Count) {
        New-TcpkFinding -Module 'static' -RuleId 'crashreporter.crashpad-present' `
            -Severity 'INFO' -Confidence 'Confirmed' `
            -Title "Crashpad crash handler shipped ($($handlers.Count) binary/binaries)" `
            -File $handlers[0].FullName `
            -Evidence (($handlers | Select-Object -First 4 | ForEach-Object { $_.Name }) -join '; ') `
            -Description ('This application handles its own crashes with Crashpad rather than ' +
                'Windows Error Reporting. Crash minidumps are written under the application''s ' +
                'userData directory and may be uploaded, according to the crashReporter ' +
                'configuration in the app''s JavaScript.') `
            -Fix 'No action by itself. Review the crashReporter configuration and the dump directory ACLs.'
    }

    # --- 2. crashReporter.start() configuration ---------------------------------
    # asar bundles store JS in plaintext, so a raw text read recovers the call
    # site without unpacking. Loose first-party scripts are scanned too.
    $jsNames = @('main.js', 'preload.js', 'index.js', 'app.js', 'renderer.js', 'background.js')
    $targets = @()
    $targets += $asars
    $targets += @(Get-TcpkChildItemSafe -Path $dir -File | Where-Object { $jsNames -contains $_.Name.ToLowerInvariant() })

    $cfgSeen = $false
    foreach ($t in ($targets | Select-Object -First 40)) {
        $text = ''
        try { $text = Read-TcpkAllText -Path $t.FullName } catch { continue }
        if (-not $text) { continue }
        if ($text -notmatch 'crashReporter\s*\.\s*start') { continue }
        $cfgSeen = $true

        # Look at a bounded window after each call site so values from unrelated
        # code elsewhere in a large bundle are not attributed to this call.
        foreach ($m in [regex]::Matches($text, 'crashReporter\s*\.\s*start\s*\(')) {
            $start = $m.Index
            $len = [Math]::Min(600, $text.Length - $start)
            if ($len -le 0) { continue }
            $win = $text.Substring($start, $len)

            $submit = ''
            $sm = [regex]::Match($win, 'submitURL\s*:\s*[''"]([^''"]+)[''"]')
            if ($sm.Success) { $submit = $sm.Groups[1].Value }

            # Electron defaults uploadToServer to true, so absent means uploading.
            $uploadOff = $win -match 'uploadToServer\s*:\s*false'

            if ($submit -and -not $uploadOff) {
                # NB: not $host -- that is a PowerShell automatic variable and is read-only.
                $submitHost = $submit
                try { $submitHost = ([uri]$submit).Host } catch { }
                if (-not $submitHost) { $submitHost = $submit }
                New-TcpkFinding -Module 'static' -RuleId 'crashreporter.uploads-enabled' `
                    -Severity 'LOW' -Confidence 'Confirmed' `
                    -Title "Crash reports are uploaded to $submitHost" `
                    -File $t.FullName `
                    -Evidence "submitURL=$submit; uploadToServer not disabled" `
                    -Cwe @('CWE-200') `
                    -Description ('crashReporter is configured to upload crash reports off the ' +
                        'machine. A minidump contains process memory at fault time, so anything ' +
                        'resident then (message content, session tokens, keys) can leave the host ' +
                        'inside the report. Electron defaults uploadToServer to true, so an absent ' +
                        'setting still uploads.') `
                    -Fix 'Confirm the endpoint is first-party and over HTTPS, that reports are scrubbed before upload, and that users consent. Set uploadToServer:false where upload is not required.'
            }

            # extra{} values are attached verbatim to every report.
            $em = [regex]::Match($win, 'extra\s*:\s*\{([^}]{0,300})\}')
            if ($em.Success -and $em.Groups[1].Value.Trim()) {
                New-TcpkFinding -Module 'static' -RuleId 'crashreporter.extra-params' `
                    -Severity 'INFO' -Confidence 'Inferred' `
                    -Title 'crashReporter attaches extra parameters to every report' `
                    -File $t.FullName `
                    -Evidence (Get-TcpkRedact ($em.Groups[1].Value.Trim())) `
                    -Cwe @('CWE-200') `
                    -Description ('The extra{} block is sent verbatim with every crash report. ' +
                        'Review it for identifiers, tokens or paths that should not leave the host.') `
                    -Fix 'Send only non-identifying diagnostic values in extra{}.'
            }
        }
    }

    if ($handlers.Count -and -not $cfgSeen) {
        New-TcpkFinding -Module 'static' -RuleId 'crashreporter.config-not-found' `
            -Severity 'INFO' -Confidence 'Inferred' `
            -Title 'Crashpad ships but no crashReporter.start() call was recovered' `
            -File $dir `
            -Evidence 'crashpad handler present; no crashReporter.start in scanned asar/JS' `
            -Description ('The handler is shipped but the configuration call was not recovered. ' +
                'It may be minified beyond recognition, loaded from a bundle that was not scanned, ' +
                'or set natively. Crash dumps may still be produced, so check the database below.') `
            -Fix 'Confirm manually how crashReporter is configured in this build.'
    }

    # --- 3. Crashpad database under the app's userData directory ----------------
    $productNames = New-Object 'System.Collections.Generic.List[string]'
    foreach ($pjp in @(
            (Join-Path $dir 'package.json'),
            (Join-Path $dir 'resources\app\package.json'),
            (Join-Path $dir 'resources\package.json'))) {
        if (-not (Test-Path -LiteralPath $pjp)) { continue }
        try {
            $pkg = Get-Content -LiteralPath $pjp -Raw -ErrorAction Stop | ConvertFrom-Json
            foreach ($n in @($pkg.productName, $pkg.name)) {
                if ($n -and -not $productNames.Contains("$n")) { $productNames.Add("$n") }
            }
        } catch { }
    }
    # Fallback: the ProductName resource on a shipped executable.
    if (-not $productNames.Count) {
        foreach ($exe in @(Get-TcpkChildItemSafe -Path $dir -File |
                Where-Object { $_.Extension.ToLowerInvariant() -eq '.exe' -and
                               $_.Name -notmatch '(?i)(setup|install|uninstall|update|crashpad|helper|elevate|squirrel)' } |
                Select-Object -First 3)) {
            try {
                $pn = $exe.VersionInfo.ProductName
                if ($pn -and -not $productNames.Contains("$pn")) { $productNames.Add("$pn") }
            } catch { }
        }
    }

    $userRx = '(?i)\b(Everyone|Authenticated Users|Users|INTERACTIVE|BUILTIN\\Users)\b'
    foreach ($pn in $productNames) {
        $clean = ($pn -replace '[<>:"/\\|?*]', '').Trim()
        if (-not $clean) { continue }
        foreach ($base in @($env:APPDATA, $env:LOCALAPPDATA)) {
            if (-not $base) { continue }
            $db = Join-Path (Join-Path $base $clean) 'Crashpad'
            if (-not (Test-Path -LiteralPath $db -PathType Container)) { continue }

            $dumps = @(Get-TcpkChildItemSafe -Path $db -File |
                Where-Object { $_.Extension.ToLowerInvariant() -in @('.dmp', '.dump') })

            $writable = $false
            try {
                $acl = Get-Acl -LiteralPath $db -ErrorAction Stop
                $writable = @($acl.Access | Where-Object {
                    $_.IdentityReference.Value -match $userRx -and
                    $_.FileSystemRights -match 'Write|Modify|FullControl' -and
                    $_.AccessControlType -eq 'Allow'
                }).Count -gt 0
            } catch { }

            if ($dumps.Count) {
                $sev = 'LOW'
                if ($writable) { $sev = 'MEDIUM' }
                $sample = ($dumps | Select-Object -First 5 | ForEach-Object {
                    "$($_.Name) ($([math]::Round($_.Length / 1MB, 1))MB)" }) -join '; '
                New-TcpkFinding -Module 'static' -RuleId 'crashreporter.dumps-present' `
                    -Severity $sev -Confidence 'Confirmed' `
                    -Title "$($dumps.Count) Crashpad minidump(s) on disk for $clean" `
                    -File $db `
                    -Evidence "$sample; dir-writable=$writable" `
                    -Cwe @('CWE-532', 'CWE-200') `
                    -Description ('Crash minidumps for this application are sitting on disk. Each ' +
                        'captures process memory at fault time and may contain message content, ' +
                        'session tokens, keys or PII. They persist until the app or the user removes ' +
                        'them.') `
                    -Fix 'Purge dumps after a successful upload, cap retention, and keep the database directory restricted to the owning user.'
            }

            if ($writable) {
                New-TcpkFinding -Module 'static' -RuleId 'crashreporter.db-user-writable' `
                    -Severity 'MEDIUM' -Confidence 'Confirmed' `
                    -Title "Crashpad database is user-writable: $clean" `
                    -File $db `
                    -Evidence "$db writable by a non-admin principal" `
                    -Cwe @('CWE-732') `
                    -Description ('The Crashpad database directory is writable by a non-admin ' +
                        'principal. Beyond reading other users'' dumps, an attacker can tamper with ' +
                        'settings.dat or plant report files that the uploader will send onward.') `
                    -Fix 'Restrict the Crashpad database directory to the owning user account.'
            }
        }
    }
}
