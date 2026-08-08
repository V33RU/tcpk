function Test-TcpkQtSurface {
<#
.SYNOPSIS
    Qt/C++ thick-client security surface: QSettings credential storage, the QProcess
    command-injection API family, bundled Qt WebEngine Chromium, QML dynamic loading,
    and .rcc resource bundles.

.DESCRIPTION
    Test-TcpkAppStack already fingerprints Qt (qt5core.dll / qt6core.dll) but stops at the
    fingerprint. Qt/C++ is the dominant stack for industrial, ICS, engineering, trading and
    device-management thick clients, so it needs its own checks. This one examines five
    things inside the target footprint:

      1. QSettings credential storage. QSettings persists to an INI/conf file
         (QSettings::IniFormat) or to HKCU\Software\<Organization>\<Application>
         (NativeFormat). Neither is encrypted. Shipped or generated .ini/.conf/.cfg files
         are parsed and keys with credential-ish names are reported. The VALUE IS ALWAYS
         MASKED in the evidence - the key and a masked value are shown, never the secret.
         Registry-backed QSettings is not visible statically; that is stated in the finding.

      2. QProcess command-injection SURFACE. QProcess::start(const QString &command) (Qt5)
         and QProcess::startCommand(const QString &command) (Qt6) parse ONE string into a
         program plus arguments, so any attacker-influenced text concatenated into that
         string changes what is executed. The check reports which QProcess overload family
         the binary actually references, read from the mangled symbol names in the file.
         THIS IS A SURFACE OBSERVATION, NOT A PROVEN INJECTION: it says the injection-prone
         API family is used, and nothing about whether the argument is attacker controlled.
         Confirming that needs a disassembler on the call sites.

      3. Qt WebEngine. Qt5WebEngineCore.dll / Qt6WebEngineCore.dll is a bundled Chromium.
         It is patched on the Qt release cadence, not Chrome's, so it commonly lags upstream
         Chrome by weeks or months and carries whatever Chromium CVEs landed in between.
         The bundled version is recovered from the embedded Chrome/QtWebEngine version
         strings when present, and reported as OBSERVED.

      4. QML dynamic loading. Qt.createQmlObject() and Qt.include() compile a string into
         live QML at runtime, and QML JavaScript reaches every C++ type the app registered.
         They are the QML equivalent of eval(). A NON-LITERAL argument (a variable, a
         concatenation, a template string) is the one that matters. QML loaded from a
         network URL is reported separately.

      5. .rcc resource bundles are compiled Qt resources that can hold QML, certificates and
         config. They are inventoried, not parsed - unpack them with rcc/pyrcc or a
         qresource carver and re-scan the contents.

    When Qt is detected and nothing above fires, an INFO inventory finding is emitted stating
    what was examined, so a Qt target never produces silence.

.PARAMETER Path
    File or directory. A file is treated as a pointer to its containing directory.

.PARAMETER MaxTextBytes
    Per-file cap for the text files that are read whole (.ini/.conf/.cfg/.qml). Default 8 MB.
    A file above the cap produces a Skipped finding rather than being dropped silently.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [int]$MaxTextBytes = 8388608
    )

    $out = New-Object 'System.Collections.Generic.List[object]'

    $item = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
    if (-not $item) {
        $out.Add((New-TcpkFinding -Module 'static' -RuleId 'qt.path-unreadable' `
            -Severity 'INFO' -Confidence 'Skipped' `
            -Title 'Qt surface scan did not run: target path is unreadable' `
            -File $Path -Evidence "Get-Item returned nothing for: $Path" `
            -AttributionBasis 'unproven' `
            -Description 'The Qt checks never executed against this path, so the absence of Qt findings says nothing about the target.' `
            -Fix 'Re-run Test-TcpkQtSurface against a readable install directory.'))
        foreach ($f in $out) { $f }
        return
    }
    $dir = $item.FullName
    if (-not $item.PSIsContainer) { $dir = Split-Path -Parent $item.FullName }
    if (-not $dir) { foreach ($f in $out) { $f }; return }

    # ---------------------------------------------------------------------------------
    # Inventory the footprint once. Every check below reads from these lists.
    # ---------------------------------------------------------------------------------
    $allFiles = @(Get-TcpkChildItemSafe -Path $dir -File)

    # Qt runtime module DLLs. Named alternation (not a bare 'qt*') so an app DLL that merely
    # begins with 'qt' is not mistaken for the framework.
    $qtModuleRx = '(?i)^(lib)?qt[0-9]*(core|gui|widgets|network|qml|quick|quickcontrols2|quicktemplates2|quickwidgets|webenginecore|webenginewidgets|webengine|webchannel|websockets|printsupport|sql|svg|xml|concurrent|dbus|opengl|multimedia|serialport|charts|positioning|virtualkeyboard|test|help|designer|statemachine|remoteobjects|scxml|texttospeech|bluetooth|sensors|location)[a-z0-9]*\.dll$'
    # Anything shipped BY Qt: used to keep the framework's own copy of QProcess out of the
    # first-party scan. Deliberately broad on purpose - a false skip here is quieter than
    # attributing Qt's own symbols to the application.
    $qtRuntimeRx  = '(?i)^(lib)?qt[0-9]*[a-z0-9_+-]*\.(dll|exe)$'
    $webEngineRx  = '(?i)^(lib)?qt[0-9]*webenginecore[a-z0-9]*\.dll$'

    $qtDlls   = @($allFiles | Where-Object { $_.Name -match $qtModuleRx })
    $webCore  = @($allFiles | Where-Object { $_.Name -match $webEngineRx })
    $qmlFiles = @($allFiles | Where-Object { $_.Extension -and $_.Extension.ToLowerInvariant() -eq '.qml' })
    $rccFiles = @($allFiles | Where-Object { $_.Extension -and $_.Extension.ToLowerInvariant() -eq '.rcc' })
    $qrcFiles = @($allFiles | Where-Object { $_.Extension -and $_.Extension.ToLowerInvariant() -eq '.qrc' })
    $iniFiles = @($allFiles | Where-Object { $_.Extension -and $_.Extension.ToLowerInvariant() -in '.ini', '.conf', '.cfg' })
    $qtConf   = @($allFiles | Where-Object { $_.Name.ToLowerInvariant() -eq 'qt.conf' })

    # Qt present? Any of: a Qt module DLL, a qt.conf, a QML source, or a compiled Qt resource.
    $qtDetected = ($qtDlls.Count -gt 0) -or ($qtConf.Count -gt 0) -or ($qmlFiles.Count -gt 0) -or
                  ($rccFiles.Count -gt 0) -or ($qrcFiles.Count -gt 0)
    if (-not $qtDetected) { foreach ($f in $out) { $f }; return }

    $qtMarker = 'qt.conf'
    if ($qtDlls.Count) { $qtMarker = $qtDlls[0].Name }
    elseif ($rccFiles.Count) { $qtMarker = $rccFiles[0].Name }
    elseif ($qmlFiles.Count) { $qtMarker = $qmlFiles[0].Name }

    # ---------------------------------------------------------------------------------
    # 1. QSettings credential storage (INI / conf backing store).
    # ---------------------------------------------------------------------------------
    # A value that carries no secret: empty, a template token, a well-known filler, a bare
    # boolean, or a bare number. These become the MEDIUM "key present, no usable value" case.
    $placeholderRx = '(?i)^\s*(|-+|\.+|n/?a|none|null|nil|empty|todo|tbd|fixme|change[_ -]?me|placeholder|example|sample|dummy|test|password|passwd|secret|token|apikey|api[_-]?key|your[_a-z0-9-]*|my[_]?(password|secret|key|token)|x{3,}|\*{2,}|<[^>]*>|\$\{[^}]*\}|%[^%]*%|\{\{[^}]*\}\}|\{[^}]*\}|true|false|yes|no|on|off|[0-9]+)\s*$'
    # Boolean preference flags ("SavePassword=true"): a UI preference, not a stored secret.
    $flagKeyRx  = '(?i)^(save|saved|remember|store|stored|use|is|has|had|enable|enabled|disable|require|required|allow|show|hide|ask|prompt|need|auto|do)[_a-z0-9]*$'
    $flagValRx  = '(?i)^\s*(0|1|true|false|yes|no|on|off)\s*$'
    $credKeyRx  = [regex]'(?i)(password|passwd|\bpwd\b|passphrase|secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|\btoken\b|credential|connection[_-]?string|connectionstring|private[_-]?key|client[_-]?secret|\bkey\b)'

    $credHigh   = 0
    $credMedium = 0
    $flagKeys   = 0
    $iniParsed  = 0

    foreach ($ini in $iniFiles) {
        if ($ini.Length -gt $MaxTextBytes) {
            $out.Add((New-TcpkFinding -Module 'static' -RuleId 'qt.settings-file-too-large' `
                -Severity 'INFO' -Confidence 'Skipped' `
                -Title "Settings file not parsed: over the size cap ($($ini.Name))" `
                -File $ini.FullName -Evidence "size=$($ini.Length) bytes, cap=$MaxTextBytes bytes" `
                -AttributionBasis 'established-footprint' `
                -Description 'This settings file was NOT read, so no statement is made about credentials inside it.' `
                -Fix 'Re-run with a larger -MaxTextBytes, or grep the file manually for credential keys.'))
            continue
        }
        $lines = $null
        try { $lines = @(Get-Content -LiteralPath $ini.FullName -ErrorAction Stop) } catch {
            $out.Add((New-TcpkFinding -Module 'static' -RuleId 'qt.settings-file-unreadable' `
                -Severity 'INFO' -Confidence 'Skipped' `
                -Title "Settings file not parsed: unreadable ($($ini.Name))" `
                -File $ini.FullName -Evidence $_.Exception.Message `
                -AttributionBasis 'established-footprint' `
                -Description 'This settings file could not be read, so no statement is made about credentials inside it.' `
                -Fix 'Check the file ACL and re-run, or read the file manually.'))
            continue
        }
        $iniParsed++

        $section = ''
        foreach ($line in $lines) {
            if ($null -eq $line) { continue }
            $t = $line.Trim()
            if (-not $t) { continue }
            if ($t.StartsWith('#') -or $t.StartsWith(';')) { continue }
            if ($t.StartsWith('[') -and $t.EndsWith(']')) { $section = $t.TrimStart('[').TrimEnd(']'); continue }
            $eq = $t.IndexOf('=')
            if ($eq -lt 1) { continue }
            $key = $t.Substring(0, $eq).Trim()
            $val = $t.Substring($eq + 1).Trim()
            if (-not $key) { continue }

            $km = $credKeyRx.Match($key)
            if (-not $km.Success) { continue }

            # QSettings wrappers: "quoted", @ByteArray(...), @Variant(...).
            if ($val.Length -ge 2 -and $val.StartsWith('"') -and $val.EndsWith('"')) { $val = $val.Substring(1, $val.Length - 2) }
            $isVariant = $false
            if ($val -match '^@ByteArray\((.*)\)$') { $val = $Matches[1] }
            elseif ($val -match '^@Variant\(') { $isVariant = $true }

            if ($key -match $flagKeyRx -and $val -match $flagValRx) { $flagKeys++; continue }

            $where = $ini.Name
            if ($section) { $where = "$($ini.Name) [$section]" }

            $hasSecret = $false
            if ($isVariant) { $hasSecret = $true }
            elseif ($val.Trim().Length -ge 6 -and ($val -notmatch $placeholderRx)) { $hasSecret = $true }

            if ($hasSecret) {
                $masked = '@Variant(<binary QVariant blob>)'
                $shape  = 'QVariant binary blob'
                if (-not $isVariant) {
                    $masked = Format-TcpkMaskedSecret -Secret $val
                    $shape  = "len=$($val.Length)"
                    $ent = Get-TcpkShannonEntropy -Text $val
                    $shape = "len=$($val.Length), entropy=$ent bits/char"
                }
                $credHigh++
                $out.Add((New-TcpkFinding -Module 'static' -RuleId 'qt.qsettings-credential' `
                    -Severity 'HIGH' -Confidence 'Confirmed' `
                    -Title "Credential stored in cleartext in a Qt settings file ($where, key '$key')" `
                    -File $ini.FullName `
                    -Evidence "$where -> $key = $masked  ($shape)  [value masked by TCPK]" `
                    -Cwe @('CWE-256', 'CWE-522', 'CWE-312') `
                    -AttributionBasis 'established-footprint' `
                    -Description 'A QSettings-style settings file inside the target footprint holds a credential-named key with a real value. QSettings::IniFormat writes plain text with no encryption and no ACL beyond the containing directory, so any process running as that user (and anyone with the roaming profile, a backup, or a support bundle) reads the value directly. The value is masked in this finding; open the file to read it.' `
                    -Impact 'Any local process running as the user, and anyone holding a copy of the profile or a backup, recovers this credential with no cracking step.' `
                    -Fix 'Do not persist credentials through QSettings. Store them with the platform secret store (Windows Credential Manager via CredWrite, or DPAPI ProtectedData scoped to the current user), keep only a non-reversible handle in QSettings, and remove any value already written to disk.'))
            } else {
                $shown = '(empty)'
                if ($val.Trim().Length -gt 0) { $shown = Format-TcpkMaskedSecret -Secret $val }
                $credMedium++
                $out.Add((New-TcpkFinding -Module 'static' -RuleId 'qt.qsettings-credential-key' `
                    -Severity 'MEDIUM' -Confidence 'Confirmed' `
                    -Title "Qt settings file defines a credential key with no usable value ($where, key '$key')" `
                    -File $ini.FullName `
                    -Evidence "$where -> $key = $shown  (empty or placeholder)  [value masked by TCPK]" `
                    -Cwe @('CWE-522', 'CWE-312') `
                    -AttributionBasis 'established-footprint' `
                    -Description 'The shipped settings file declares a credential-named key but the value is empty or a placeholder. That names the exact key the application writes the real credential to at runtime, in a plaintext QSettings store. Run the application, log in, and re-read this file (and HKCU\Software\<Organization>\<Application>, which QSettings NativeFormat uses instead and which static analysis cannot see) to confirm what actually lands on disk.' `
                    -Impact 'Identifies where a credential will be persisted in cleartext once the user authenticates.' `
                    -Fix 'Move credential persistence off QSettings and onto the platform secret store; keep only non-secret preferences in the INI/registry settings.'))
            }
        }
    }

    # ---------------------------------------------------------------------------------
    # 2. QProcess command-injection SURFACE (mangled symbol names in first-party binaries).
    # ---------------------------------------------------------------------------------
    # MSVC:     ?startCommand@QProcess@@QEAAX AEBVQString@@ ...
    # Itanium:  _ZN8QProcess12startCommandERK7QString...
    # The single-QString overloads split ONE command string into program + arguments; the
    # (program, QStringList) overloads do not. The mangled parameter list tells them apart.
    $qprocSymRx = '(?:\?(?:start|startDetached|startCommand|execute)@QProcess@@[!-~]{0,200})|(?:_ZN8QProcess\d{1,2}(?:start|startDetached|startCommand|execute)[!-~]{0,200})'
    $qprocPeScanned = 0
    $qprocHits      = 0

    foreach ($pe in Get-TcpkPeFiles -Path $dir) {
        if (Test-TcpkIsFrameworkFile $pe.Name) { continue }
        if (Test-TcpkIsNativeNoise   $pe.Name) { continue }
        if ($pe.Name -match $qtRuntimeRx)      { continue }   # Qt's own copy of QProcess
        $qprocPeScanned++

        # Cheap streamed pre-filter: most binaries never mention QProcess at all.
        if (-not (Test-TcpkFileContainsAny -Path $pe.FullName -Needles @('QProcess') -CaseSensitive)) { continue }

        $syms = @(Select-TcpkFileMatch -Path $pe.FullName -Pattern $qprocSymRx -MaxMatches 40 -CaseSensitive)
        if (-not $syms.Count) {
            # 'QProcess' appears but no start/execute symbol was recovered (the call may be
            # inlined, or the symbol split across a chunk boundary). Say exactly that.
            $qprocHits++
            $out.Add((New-TcpkFinding -Module 'static' -RuleId 'qt.qprocess-surface' `
                -Severity 'INFO' -Confidence 'Confirmed' `
                -Title "QProcess referenced in $($pe.Name) (no start/execute symbol recovered)" `
                -File $pe.FullName -Evidence "string 'QProcess' present; no ?start@QProcess / _ZN8QProcess symbol matched" `
                -Cwe @('CWE-78') `
                -AttributionBasis 'established-footprint' `
                -Description 'The binary references QProcess, Qt''s child-process API, but no start/startDetached/startCommand/execute symbol was recovered from its strings. This records that the process-spawning surface exists. It is NOT a claim that a command is built from attacker input.' `
                -Fix 'Informational. Disassemble the QProcess call sites if child-process spawning is in scope.'))
            continue
        }

        $stringOverload = New-Object 'System.Collections.Generic.List[string]'
        $listOverload   = New-Object 'System.Collections.Generic.List[string]'
        foreach ($s in $syms) {
            $short = $s
            if ($short.Length -gt 120) { $short = $short.Substring(0, 120) + '...' }
            if ($s -match 'startCommand') { $stringOverload.Add($short); continue }
            if ($s -match 'QList|QStringList') { $listOverload.Add($short); continue }
            $stringOverload.Add($short)
        }

        $qprocHits++
        if ($stringOverload.Count) {
            $ev = ($stringOverload | Select-Object -First 3) -join ' | '
            $out.Add((New-TcpkFinding -Module 'static' -RuleId 'qt.qprocess-string-command' `
                -Severity 'MEDIUM' -Confidence 'Confirmed' `
                -Title "$($pe.Name) uses the QProcess single-string command API (injection-prone overload family; injection NOT proven)" `
                -File $pe.FullName -Evidence "recovered symbol(s): $ev" `
                -Cwe @('CWE-78', 'CWE-88') `
                -AttributionBasis 'established-footprint' `
                -Description 'The binary references the QProcess overloads that take ONE command string - QProcess::start(const QString &command) in Qt5 or QProcess::startCommand(const QString &command) in Qt6. Qt splits that string into a program and arguments itself, so any attacker-influenced text concatenated into it changes the argument vector and, depending on the program invoked, the program itself. THIS FINDING IS THE SURFACE, NOT AN INJECTION: it states which API family is referenced and says nothing about whether the argument is attacker controlled. Confirm by disassembling the call sites (Ghidra / IDA) and tracing what feeds the QString.' `
                -Impact 'If any of these call sites builds its command string from a file, registry value, IPC message, URL, or network response, that input controls the argument vector of a spawned process.' `
                -Fix 'Use the QProcess overload that takes a program and a QStringList of arguments (setProgram + setArguments + start, or start(program, args)). Never build a single command string from external input. On Qt6, prefer start(program, args) over startCommand.'))
        } else {
            $ev = ($listOverload | Select-Object -First 3) -join ' | '
            $out.Add((New-TcpkFinding -Module 'static' -RuleId 'qt.qprocess-surface' `
                -Severity 'INFO' -Confidence 'Confirmed' `
                -Title "$($pe.Name) spawns child processes via QProcess (program + argument-list overload)" `
                -File $pe.FullName -Evidence "recovered symbol(s): $ev" `
                -Cwe @('CWE-78') `
                -AttributionBasis 'established-footprint' `
                -Description 'Only the QProcess overloads that take a program plus a separate argument list were recovered. That form does not re-parse a command string, so it is the safer variant. The child-process surface is recorded here for review: what gets spawned, from where, and whether the program path itself is attacker influenced.' `
                -Fix 'Informational. Verify the program path is absolute and not user writable, and that no argument crosses a shell.'))
        }
    }

    # ---------------------------------------------------------------------------------
    # 3. Qt WebEngine (bundled Chromium).
    # ---------------------------------------------------------------------------------
    foreach ($we in $webCore) {
        $chrome = Get-TcpkFirstFileMatch -Path $we.FullName -Pattern 'Chrome/\d{2,3}\.\d+\.\d+\.\d+'
        if (-not $chrome) { $chrome = Get-TcpkFirstFileMatch -Path $we.FullName -Pattern 'Chrome/\d{2,3}\.\d+' }
        $qtwe = Get-TcpkFirstFileMatch -Path $we.FullName -Pattern 'QtWebEngine/\d+\.\d+(\.\d+)?'

        $parts = New-Object 'System.Collections.Generic.List[string]'
        if ($chrome) { $parts.Add($chrome) }
        if ($qtwe)   { $parts.Add($qtwe) }

        if ($parts.Count) {
            $ver = ($parts -join ', ')
            $out.Add((New-TcpkFinding -Module 'static' -RuleId 'qt.webengine-chromium' `
                -Severity 'MEDIUM' -Confidence 'Confirmed' `
                -Title "Bundled Qt WebEngine Chromium observed: $ver ($($we.Name))" `
                -File $we.FullName -Evidence "version string(s) read from the binary: $ver" `
                -Cwe @('CWE-1395', 'CWE-937') `
                -AttributionBasis 'established-footprint' `
                -Description "Qt WebEngine embeds a full Chromium. It is rebased and shipped on the Qt release cadence, not Chrome's, so the bundled engine commonly lags upstream stable Chrome and carries the Chromium CVEs fixed in between - including any that were exploited in the wild. The version above was READ FROM THE BINARY; treat it as the engine version to check, not as a vulnerability by itself. Compare it against the Chrome stable channel and the Qt WebEngine release notes, and check the Chromium CVE list for everything newer." `
                -Impact 'Any content rendered by this engine (in-app browser, help viewer, dashboard, OAuth window, remote-loaded page) runs against a Chromium that may be missing upstream security fixes.' `
                -Fix 'Track the Qt WebEngine release notes and update Qt when a rebase lands. Restrict what the WebEngine loads (no remote/untrusted origins), keep the sandbox enabled (do not pass --no-sandbox or --disable-web-security via QTWEBENGINE_CHROMIUM_FLAGS), and disable unused schemes and plugins.'))
        } else {
            $out.Add((New-TcpkFinding -Module 'static' -RuleId 'qt.webengine-present' `
                -Severity 'INFO' -Confidence 'Confirmed' `
                -Title "Qt WebEngine (bundled Chromium) present: $($we.Name) - version not recovered" `
                -File $we.FullName -Evidence "$($we.Name), size=$($we.Length) bytes; no Chrome/ or QtWebEngine/ version string recovered" `
                -Cwe @('CWE-1395', 'CWE-937') `
                -AttributionBasis 'established-footprint' `
                -Description "The application bundles Chromium through Qt WebEngine, but no embedded version string was recovered from this file, so NO version claim is made. The bundled engine is patched on the Qt release cadence rather than Chrome's and commonly lags upstream stable." `
                -Fix 'Read the version from the file properties or the Qt install manifest, then compare against Chrome stable and the Qt WebEngine release notes. Restrict what the WebEngine is allowed to load and keep its sandbox enabled.'))
        }
    }

    # ---------------------------------------------------------------------------------
    # 4. QML dynamic construction and remote QML.
    # ---------------------------------------------------------------------------------
    # A COMPLETE quoted literal followed immediately by ',' or ')' is the literal case.
    # Anything else (variable, concatenation, template string) is non-literal.
    $literalArgRx = '^\s*(?:"(?:[^"\\]|\\.)*"|''(?:[^''\\]|\\.)*'')\s*[,)]'
    $dynCallRx    = [regex]'(?<fn>Qt\.createQmlObject|Qt\.include|(?<![\w.$])eval)\s*\(\s*(?<arg>[^\r\n]{0,300})'
    $remoteRx     = [regex]'(?i)(?:Qt\.createComponent\s*\(\s*["''](?<u1>https?://[^"'']+)["''])|(?:\bimport\s+["''](?<u2>https?://[^"'']+)["''])|(?:\bsource\s*:\s*["''](?<u3>https?://[^"'']+\.qml)["''])'
    $qmlParsed    = 0

    foreach ($q in $qmlFiles) {
        if ($q.Length -gt $MaxTextBytes) {
            $out.Add((New-TcpkFinding -Module 'static' -RuleId 'qt.qml-file-too-large' `
                -Severity 'INFO' -Confidence 'Skipped' `
                -Title "QML source not parsed: over the size cap ($($q.Name))" `
                -File $q.FullName -Evidence "size=$($q.Length) bytes, cap=$MaxTextBytes bytes" `
                -AttributionBasis 'established-footprint' `
                -Description 'This QML source was NOT read, so no statement is made about dynamic QML construction inside it.' `
                -Fix 'Re-run with a larger -MaxTextBytes, or grep the file for Qt.createQmlObject / Qt.include / eval.'))
            continue
        }
        $text = $null
        try { $text = Get-Content -LiteralPath $q.FullName -Raw -ErrorAction Stop } catch {
            $out.Add((New-TcpkFinding -Module 'static' -RuleId 'qt.qml-file-unreadable' `
                -Severity 'INFO' -Confidence 'Skipped' `
                -Title "QML source not parsed: unreadable ($($q.Name))" `
                -File $q.FullName -Evidence $_.Exception.Message `
                -AttributionBasis 'established-footprint' `
                -Description 'This QML source could not be read, so no statement is made about dynamic QML construction inside it.' `
                -Fix 'Check the file ACL and re-run, or read the file manually.'))
            continue
        }
        if ($null -eq $text) { $text = '' }
        $qmlParsed++

        foreach ($m in $dynCallRx.Matches($text)) {
            $fn  = $m.Groups['fn'].Value
            $arg = $m.Groups['arg'].Value
            $isLiteral = [bool]($arg -match $literalArgRx)

            # Trim the excerpt at the statement separator so the evidence shows THIS call and
            # not whatever else shares the line in a minified / single-line .qml. Skipped for
            # the literal case, where the ';' is usually INSIDE the QML string being compiled.
            $snip = ($fn + '(' + $arg)
            if (-not $isLiteral) {
                $semi = $snip.IndexOf(';')
                if ($semi -gt 0) { $snip = $snip.Substring(0, $semi) }
            }
            if ($snip.Length -gt 160) { $snip = $snip.Substring(0, 160) + '...' }
            $snip = $snip -replace '\s+', ' '

            if ($isLiteral) {
                $out.Add((New-TcpkFinding -Module 'static' -RuleId 'qt.qml-dynamic-eval-literal' `
                    -Severity 'LOW' -Confidence 'Confirmed' `
                    -Title "$($q.Name) builds QML at runtime with $fn (literal argument)" `
                    -File $q.FullName -Evidence $snip `
                    -Cwe @('CWE-95') `
                    -AttributionBasis 'established-code' `
                    -Description "$fn compiles a string into live QML or JavaScript at runtime. Here the argument is a string literal, so nothing external reaches the compiler at this call site. It is recorded because the dynamic-construction path exists: a later change that concatenates external text into this argument turns it into QML injection, and QML JavaScript reaches every C++ type the application registered with qmlRegisterType." `
                    -Fix 'Prefer a static component plus a Loader, or Qt.createComponent with a fixed local URL. Keep the argument a literal.'))
            } else {
                $out.Add((New-TcpkFinding -Module 'static' -RuleId 'qt.qml-dynamic-eval' `
                    -Severity 'MEDIUM' -Confidence 'Confirmed' `
                    -Title "$($q.Name) compiles a non-literal string into QML with $fn" `
                    -File $q.FullName -Evidence $snip `
                    -Cwe @('CWE-95', 'CWE-94') `
                    -AttributionBasis 'established-code' `
                    -Description "$fn is the QML equivalent of eval(): it compiles the string it is given into live QML/JavaScript. At this call site the argument is NOT a string literal - it is a variable, a concatenation, or a template string - so whatever fills it becomes executable QML. QML JavaScript can reach every C++ type registered with qmlRegisterType / setContextProperty, so this is a route from a data value into application code, not just into the UI. Trace the argument back to its source to determine whether it crosses a trust boundary (file, network, IPC, URL, clipboard, user field)." `
                    -Impact 'If the string reaching this call is influenced by external data, the attacker executes QML/JavaScript inside the application and can call the C++ objects exposed to QML.' `
                    -Fix 'Do not compile strings into QML. Use a static .qml component with a Loader and pass data through properties or a context model. If dynamic construction is unavoidable, build it only from a fixed allow-list of component names, never from external text.'))
            }
        }

        foreach ($m in $remoteRx.Matches($text)) {
            $url = $m.Groups['u1'].Value
            if (-not $url) { $url = $m.Groups['u2'].Value }
            if (-not $url) { $url = $m.Groups['u3'].Value }
            if (-not $url) { continue }
            $isHttp = $url -match '(?i)^http://'
            $sev = 'MEDIUM'
            if ($isHttp) { $sev = 'HIGH' }
            $why = 'over TLS'
            if ($isHttp) { $why = 'over cleartext http' }
            $out.Add((New-TcpkFinding -Module 'static' -RuleId 'qt.qml-remote-source' `
                -Severity $sev -Confidence 'Confirmed' `
                -Title "$($q.Name) loads QML from a network URL $why" `
                -File $q.FullName -Evidence "$url" `
                -Cwe @('CWE-829', 'CWE-494', 'CWE-95') `
                -AttributionBasis 'established-code' `
                -Description "This QML source loads a component from a remote URL. QML fetched at runtime is executable: it carries JavaScript and can reach every C++ type the application registered for QML. Loading it over cleartext http lets any on-path attacker replace it outright; loading it over TLS still makes whoever controls that origin a code-supply-chain dependency of the client." `
                -Impact 'Whoever controls (or intercepts) that URL supplies executable QML to the application process.' `
                -Fix 'Ship QML inside the binary or a .qrc/.rcc resource. If remote QML is a product requirement, serve it over TLS with pinning and verify a signature over the payload before compiling it.'))
        }
    }

    # ---------------------------------------------------------------------------------
    # 5. .rcc compiled resource bundles (inventory only - no rcc parsing is attempted).
    # ---------------------------------------------------------------------------------
    $rccListed = 0
    foreach ($r in $rccFiles) {
        if ($rccListed -ge 50) { break }
        $rccListed++
        $out.Add((New-TcpkFinding -Module 'static' -RuleId 'qt.rcc-bundle' `
            -Severity 'INFO' -Confidence 'Confirmed' `
            -Title "Compiled Qt resource bundle: $($r.Name)" `
            -File $r.FullName -Evidence "$($r.Name), size=$($r.Length) bytes" `
            -AttributionBasis 'established-footprint' `
            -Description 'A .rcc file is a compiled Qt resource bundle. It commonly carries QML sources, certificates, keys, SQL, and configuration that no other TCPK check can see, because TCPK does NOT parse .rcc. This finding exists so that content is not mistaken for absent.' `
            -Fix 'Unpack the bundle manually (rcc, pyrcc, or a qresource carver), then re-run the secret, QML and endpoint checks against the extracted tree.'))
    }
    if ($rccFiles.Count -gt $rccListed) {
        $out.Add((New-TcpkFinding -Module 'static' -RuleId 'qt.rcc-bundle-truncated' `
            -Severity 'INFO' -Confidence 'Skipped' `
            -Title "Qt resource inventory truncated: $($rccFiles.Count) .rcc files, $rccListed listed" `
            -File $dir -Evidence "$($rccFiles.Count) .rcc files found; per-file findings capped at $rccListed" `
            -AttributionBasis 'established-footprint' `
            -Description 'The .rcc inventory was capped, so the list above is incomplete.' `
            -Fix 'Enumerate the remaining .rcc files manually and unpack them.'))
    }

    # ---------------------------------------------------------------------------------
    # Inventory. Emitted only when nothing above fired, so a Qt target is never silent.
    # ---------------------------------------------------------------------------------
    if ($out.Count -eq 0) {
        $weTxt = 'no'
        if ($webCore.Count) { $weTxt = "yes ($($webCore.Count))" }
        $ev = "qt marker=$qtMarker; qt module dlls=$($qtDlls.Count); webengine=$weTxt; " +
              "settings files parsed=$iniParsed; credential-named flag keys ignored=$flagKeys; " +
              "qml sources parsed=$qmlParsed; qrc=$($qrcFiles.Count); rcc=$($rccFiles.Count); " +
              "first-party binaries scanned for QProcess=$qprocPeScanned"
        $out.Add((New-TcpkFinding -Module 'static' -RuleId 'qt.surface-inventory' `
            -Severity 'INFO' -Confidence 'Confirmed' `
            -Title 'Qt application examined: no Qt-specific issue found by these checks' `
            -File $dir -Evidence $ev `
            -AttributionBasis 'established-footprint' `
            -Description 'Qt was detected and every Qt check ran: QSettings credential storage in shipped .ini/.conf/.cfg files, the QProcess command API family in first-party binaries, bundled Qt WebEngine Chromium, QML dynamic construction and remote QML, and .rcc resource bundles. None of them fired. This is a scoped negative, not a clean bill of health: QSettings NativeFormat writes to HKCU\Software\<Organization>\<Application> and is invisible to a static file scan, QML compiled into the binary or into a .rcc is not read here, and native Qt/C++ logic needs a disassembler.' `
            -Fix 'Informational. Run the application and re-scan its settings file and registry hive, unpack any .rcc, and review the native code with a disassembler.'))
    }

    foreach ($f in $out) { $f }
}
