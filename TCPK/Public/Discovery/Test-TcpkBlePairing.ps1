function Test-TcpkBlePairing {
<#
.SYNOPSIS
    A56. BLE pairing model of a Windows companion app. Static complement to A50
    Test-TcpkDeviceComm (which only reports that BLE is spoken).

.DESCRIPTION
    Test-TcpkDeviceComm flags the presence of BLE code (devcomm.ble). What it does not
    say is whether the app pairs with a MITM-protected ceremony, whether it auto-accepts
    incoming pairing requests, or whether a fixed passkey or LTK is baked in.

    This cmdlet reads .NET IL text and native PE strings across the install tree, gates
    per-file on a BLE anchor (so a DevicePairingProtectionLevel reference from an
    unrelated Wi-Fi Direct / Miracast / USB picker cannot fire), and emits one finding
    per matched rule.

    Rules (rule id / severity / confidence):
      ble-pair.custom-ceremony-present    INFO    Confirmed   DeviceInformationCustomPairing reference
      ble-pair.protection-none            HIGH    Inferred    'DevicePairingProtectionLevel.None' literal
      ble-pair.protection-encryption-only MEDIUM  Inferred    'Encryption' without 'EncryptionAndAuthentication'
      ble-pair.protection-omitted         MEDIUM  Inferred    PairAsync used, no ProtectionLevel string
      ble-pair.kinds-confirmonly-only     HIGH    Inferred    'ConfirmOnly' only DevicePairingKinds member present
      ble-pair.auto-accept-suspected      HIGH    Inferred    'PairingRequested' + Accept() with no UI prompt tokens
      ble-pair.hardcoded-passkey          HIGH    Inferred    ldstr of 4/6-digit near ProvidePin / Accept(pin)
      ble-pair.hardcoded-key-material     HIGH    Inferred    32-hex or 16-byte constant near LTK/IRK anchor
      ble-pair.32feet-hardcoded-pin       HIGH    Inferred    numeric literal near 32feet.NET Bluetooth security
      ble-pair.32feet-autoconfirm         HIGH    Inferred    BluetoothWin32Authentication + Confirm=true
      ble-pair.qt-confirm-true            HIGH    Inferred    pairingConfirmation(true) in Qt binary
      ble-pair.native-mitm-not-required   MEDIUM  Inferred    BLUETOOTH_MITM_PROTECTION_NOT_REQUIRED string
      ble-pair.sdk-legacy-pairing-forced  MEDIUM  Inferred    Firmware SDK marker requesting legacy pairing / .mitm=0

    Confidence is Inferred by default: a string in a binary is not proof of runtime execution.
    A live central-role trace (Frida hook on the pairing callback, or a WireShark BT-HCI capture
    parsed by _Pcap.ps1's pcap.bt-justworks family) promotes any of the above to Confirmed.

    Shape gate. Before any rule fires, the same file must reference at least one BLE anchor
    from the Test-TcpkDeviceComm needle set: BluetoothLEAdvertisementWatcher, BluetoothLEDevice,
    GattDeviceService, GattCharacteristic, BluetoothLEScanningMode, or the imports
    BluetoothGATTGetServices / BluetoothGATTSetCharacteristicValue / BluetoothFindFirstRadio.
    Classic-BT anchors BluetoothAuthenticateDeviceEx / BluetoothRegisterForAuthenticationEx
    also open the gate for the 32feet.NET and native-MITM rules.

.PARAMETER Path
    Install directory or single binary.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { return }

    # Anchor sets. LE anchors are enough for the WinRT LE rules; either LE or classic-BT
    # anchors open the gate for the classic rules (32feet, native BluetoothAuthenticate*).
    $leAnchors = @(
        'BluetoothLEAdvertisementWatcher','BluetoothLEDevice','GattDeviceService',
        'GattCharacteristic','BluetoothLEScanningMode',
        'BluetoothGATTGetServices','BluetoothGATTSetCharacteristicValue','BluetoothFindFirstRadio'
    )
    $classicAnchors = @(
        'BluetoothAuthenticateDeviceEx','BluetoothRegisterForAuthenticationEx',
        'BluetoothClient','BluetoothRadio','BluetoothSecurity','BluetoothDeviceInfo',
        'InTheHand.Net.Bluetooth'
    )

    # Enumerate PE files. Get-TcpkPeFiles handles budget + heartbeat + reparse-safety.
    $items = @()
    if ((Get-Item -LiteralPath $Path).PSIsContainer) {
        try { $items = @(Get-TcpkPeFiles -Path $Path) } catch { return }
    } else {
        try { $items = @([IO.FileInfo]::new((Resolve-Path -LiteralPath $Path).Path)) } catch { return }
    }

    foreach ($pe in $items) {
        if (Test-TcpkIsFrameworkFile $pe.Name) { continue }

        $text = Read-TcpkAllText -Path $pe.FullName
        if (-not $text) { continue }

        # Fast anchor gate. Compare with word-boundary the same way Test-TcpkDeviceComm does.
        $hasLe = $false
        foreach ($n in $leAnchors) {
            if ([regex]::IsMatch($text, '(?<![A-Za-z0-9_])' + [regex]::Escape($n) + '(?![A-Za-z0-9_])')) {
                $hasLe = $true; break
            }
        }
        $hasClassic = $false
        foreach ($n in $classicAnchors) {
            if ([regex]::IsMatch($text, '(?<![A-Za-z0-9_])' + [regex]::Escape($n) + '(?![A-Za-z0-9_])')) {
                $hasClassic = $true; break
            }
        }
        if (-not ($hasLe -or $hasClassic)) { continue }

        # ---- ble-pair.custom-ceremony-present (INFO, Confirmed) --------------------------
        # Fires only with an LE anchor. Establishes that the file owns the pairing UX.
        $hasCustom = $hasLe -and [regex]::IsMatch($text, '(?<![A-Za-z0-9_])DeviceInformationCustomPairing(?![A-Za-z0-9_])')
        if ($hasCustom) {
            New-TcpkFinding -Module 'discovery' -RuleId 'ble-pair.custom-ceremony-present' `
                -Severity 'INFO' -Confidence 'Confirmed' `
                -Title "$($pe.Name) uses DeviceInformationCustomPairing (BLE pairing ceremony owned by the app)" `
                -File $pe.FullName -Evidence 'DeviceInformationCustomPairing + LE anchor in same file' `
                -Cwe @('CWE-287') `
                -Description ("The binary references Windows.Devices.Enumeration.DeviceInformationCustomPairing, " +
                    "meaning the app implements its own BLE pairing ceremony rather than delegating to the OS " +
                    "default. This is scope information: the pairing-quality rules below apply because the app " +
                    "chose the model.") `
                -Fix 'No fix required. The rule flags scope for the LE pairing-model rules that follow.'
        }

        # ---- ble-pair.protection-none (HIGH, Inferred) -----------------------------------
        if ($hasLe -and [regex]::IsMatch($text, '(?<![A-Za-z0-9_])DevicePairingProtectionLevel\.None(?![A-Za-z0-9_])')) {
            New-TcpkFinding -Module 'discovery' -RuleId 'ble-pair.protection-none' `
                -Severity 'HIGH' -Confidence 'Inferred' `
                -Title "$($pe.Name) requests DevicePairingProtectionLevel.None for BLE pairing" `
                -File $pe.FullName -Evidence 'DevicePairingProtectionLevel.None' `
                -Cwe @('CWE-319','CWE-300') `
                -Description ("The literal 'DevicePairingProtectionLevel.None' appears in the file. In WinRT, " +
                    "None means the pairing negotiates no encryption and no authentication: an attacker in radio " +
                    "range can MITM the pairing exchange, derive the session keys, and forge or read every " +
                    "subsequent characteristic. Inferred because a string reference does not prove the value is " +
                    "used at the PairAsync call site. Confirmation is a Frida hook on the pairing callback or a " +
                    "BT-HCI pcap showing no encryption change on the link.") `
                -Fix 'Request DevicePairingProtectionLevel.EncryptionAndAuthentication and refuse to pair if the peripheral cannot support it. Do not fall back silently to None.'
        }
        # ---- ble-pair.protection-encryption-only (MEDIUM, Inferred) ----------------------
        # Encryption without EncryptionAndAuthentication -> LE Secure Connections without MITM.
        if ($hasLe -and
            [regex]::IsMatch($text, '(?<![A-Za-z0-9_])DevicePairingProtectionLevel\.Encryption(?![A-Za-z0-9_])') -and
            -not [regex]::IsMatch($text, '(?<![A-Za-z0-9_])DevicePairingProtectionLevel\.EncryptionAndAuthentication(?![A-Za-z0-9_])')) {
            New-TcpkFinding -Module 'discovery' -RuleId 'ble-pair.protection-encryption-only' `
                -Severity 'MEDIUM' -Confidence 'Inferred' `
                -Title "$($pe.Name) requests Encryption but not EncryptionAndAuthentication (no MITM protection)" `
                -File $pe.FullName -Evidence "'DevicePairingProtectionLevel.Encryption' without '.EncryptionAndAuthentication'" `
                -Cwe @('CWE-300','CWE-287') `
                -Description ("The file requests the Encryption protection level but never the " +
                    "EncryptionAndAuthentication level. On BLE this maps to LE Secure Connections without " +
                    "authenticated pairing: the session is encrypted but there is no MITM protection because " +
                    "the pairing IO capabilities negotiated a Just-Works ceremony.") `
                -Fix 'Request EncryptionAndAuthentication and set DevicePairingKinds to ConfirmPinMatch or DisplayPin/ProvidePin to force a MITM-protected ceremony.'
        }
        # ---- ble-pair.protection-omitted (MEDIUM, Inferred) ------------------------------
        if ($hasLe -and
            [regex]::IsMatch($text, '(?<![A-Za-z0-9_])PairAsync(?![A-Za-z0-9_])') -and
            -not [regex]::IsMatch($text, 'DevicePairingProtectionLevel')) {
            New-TcpkFinding -Module 'discovery' -RuleId 'ble-pair.protection-omitted' `
                -Severity 'MEDIUM' -Confidence 'Inferred' `
                -Title "$($pe.Name) calls PairAsync without any DevicePairingProtectionLevel reference" `
                -File $pe.FullName -Evidence "'PairAsync' present, 'DevicePairingProtectionLevel' absent" `
                -Cwe @('CWE-1188','CWE-300') `
                -Description ("PairAsync is called without any protection level literal in the same binary, " +
                    "so the app either uses the parameterless PairAsync() overload or PairAsync(Default). " +
                    "Both delegate to the OS default association model, which negotiates Just-Works when the " +
                    "peripheral advertises NoInputNoOutput IO capabilities. Inferred because the actual PairAsync " +
                    "overload is not IL-traced here.") `
                -Fix 'Call PairAsync(DevicePairingProtectionLevel.EncryptionAndAuthentication) explicitly and refuse to pair with a peripheral whose IO capabilities force Just-Works.'
        }

        # ---- ble-pair.kinds-confirmonly-only (HIGH, Inferred) ----------------------------
        if ($hasLe -and $hasCustom) {
            $kConfirmOnly   = [regex]::IsMatch($text, '(?<![A-Za-z0-9_])ConfirmOnly(?![A-Za-z0-9_])')
            $kDisplayPin    = [regex]::IsMatch($text, '(?<![A-Za-z0-9_])DisplayPin(?![A-Za-z0-9_])')
            $kProvidePin    = [regex]::IsMatch($text, '(?<![A-Za-z0-9_])ProvidePin(?![A-Za-z0-9_])')
            $kConfirmPin    = [regex]::IsMatch($text, '(?<![A-Za-z0-9_])ConfirmPinMatch(?![A-Za-z0-9_])')
            $kProvideCred   = [regex]::IsMatch($text, '(?<![A-Za-z0-9_])ProvidePasswordCredential(?![A-Za-z0-9_])')
            if ($kConfirmOnly -and -not ($kDisplayPin -or $kProvidePin -or $kConfirmPin -or $kProvideCred)) {
                New-TcpkFinding -Module 'discovery' -RuleId 'ble-pair.kinds-confirmonly-only' `
                    -Severity 'HIGH' -Confidence 'Inferred' `
                    -Title "$($pe.Name) advertises only ConfirmOnly DevicePairingKinds (Just-Works)" `
                    -File $pe.FullName -Evidence "'ConfirmOnly' present, other DevicePairingKinds absent" `
                    -Cwe @('CWE-287','CWE-300') `
                    -Description ("ConfirmOnly is the only DevicePairingKinds member referenced in the file, so " +
                        "the app declares NoInputNoOutput IO capabilities to every peripheral. Under SMP this " +
                        "always negotiates Just-Works, and an attacker in radio range can passively decrypt the " +
                        "link after MITMing the pairing. Legitimate when the target peripheral has a physical " +
                        "Yes/No button; not legitimate against peripherals that can display or enter a passkey.") `
                    -Fix 'Also register DisplayPin, ProvidePin, or ConfirmPinMatch and select the strongest ceremony the peripheral supports at pair time.'
            }
        }

        # ---- ble-pair.auto-accept-suspected (HIGH, Inferred) -----------------------------
        if ($hasLe -and [regex]::IsMatch($text, '(?<![A-Za-z0-9_])PairingRequested(?![A-Za-z0-9_])')) {
            $acceptsZero = [regex]::IsMatch($text, 'DevicePairingRequestedEventArgs::Accept\s*\(\)') -or
                           [regex]::IsMatch($text, 'DevicePairingRequestedEventArgs\.Accept\s*\(\s*\)')
            $uiPrompt    = [regex]::IsMatch($text,
                '(ContentDialog\.ShowAsync|MessageDialog\.ShowAsync|MessageBox\.Show|TaskCompletionSource|GetDeferral)')
            if ($acceptsZero) {
                $sev = if ($uiPrompt) { 'MEDIUM' } else { 'HIGH' }
                New-TcpkFinding -Module 'discovery' -RuleId 'ble-pair.auto-accept-suspected' `
                    -Severity $sev -Confidence 'Inferred' `
                    -Title "$($pe.Name) BLE PairingRequested handler calls zero-arg Accept()" `
                    -File $pe.FullName `
                    -Evidence ("'PairingRequested' + zero-arg 'Accept()'" + $(if ($uiPrompt) { ' (UI-prompt tokens present)' } else { '' })) `
                    -Cwe @('CWE-306','CWE-287') `
                    -Description ("The file subscribes to DeviceInformationCustomPairing.PairingRequested AND " +
                        "calls the zero-argument DevicePairingRequestedEventArgs.Accept() overload. That is the " +
                        "auto-accept shape: any pairing request is consented to without user input. Downgraded " +
                        "to MEDIUM when UI-prompt tokens (ContentDialog / MessageBox / MessageDialog / " +
                        "TaskCompletionSource / GetDeferral) appear in the same file, since the call MAY sit " +
                        "behind a prompt a static scanner cannot see. Manual-review flag, not a confirmed defect.") `
                    -Fix 'Present the pairing request to the user (ContentDialog / MessageBox), obtain explicit consent, and only then call Accept(). Reject after a timeout.'
            }
        }

        # ---- ble-pair.hardcoded-passkey (HIGH, Inferred) ---------------------------------
        # Look for 6- or 4-digit numeric literals within 512 bytes of a passkey-adjacent anchor.
        # NB: 'InTheHand.Net.Bluetooth' is deliberately NOT in this anchor set - the 32feet rule
        # below owns that path. Keeping it here made this LE rule fire on 32feet-only binaries.
        if ($hasLe) {
            $anchors = @(
                'ProvidePin', 'DevicePairingRequestedEventArgs\.Accept\s*\(\s*"',
                'DevicePairingRequestedEventArgs::Accept\(System\.String\)'
            )
            $anchorRx = '(' + ($anchors -join '|') + ')'
            $pkRx = '(?is)' + $anchorRx + '.{0,512}?(?<!\d)(\d{6}|\d{4})(?!\d)|(?<!\d)(\d{6}|\d{4})(?!\d).{0,512}?' + $anchorRx
            $m = [regex]::Match($text, $pkRx)
            if ($m.Success) {
                # Prefer the captured group that is the literal itself.
                $literal = ''
                foreach ($g in $m.Groups) { if ($g.Value -match '^\d{4}$|^\d{6}$') { $literal = $g.Value; break } }
                # Sentinel filter. A raw 4/6-digit run in a PE text blob overlaps with buffer
                # sizes, timeouts and Win32 error decimals. Filter those out because they hit
                # inside the anchor window (WinRT metadata alone contains 'ProvidePin' as an
                # enum-name string). Weak-but-canonical PINs like 0000/1234/123456 are DELIBERATELY
                # left in - a binary that ships those with a passkey anchor is exactly the finding
                # this rule is here to raise.
                $isSentinel =
                    $literal -match '^(19\d\d|20\d\d)$' -or                              # calendar years
                    $literal -in @('1024','2048','4096','8192','16384','32768','65535','65536',
                                   '10000','15000','20000','25000','30000','45000',
                                   '60000','90000','100000','120000','180000','300000',
                                   '500000','600000','900000')                            # buffer sizes / timeouts
                if ($literal -and -not $isSentinel) {
                    New-TcpkFinding -Module 'discovery' -RuleId 'ble-pair.hardcoded-passkey' `
                        -Severity 'HIGH' -Confidence 'Inferred' `
                        -Title "$($pe.Name) ships a numeric literal near a BLE passkey call site" `
                        -File $pe.FullName -Evidence "literal $literal near passkey anchor" `
                        -Cwe @('CWE-798','CWE-259') `
                        -Description ("A 4- or 6-digit numeric literal ($literal) is loaded in the binary within " +
                            "512 bytes of a BLE passkey-related API token (ProvidePin, Accept(String), or a " +
                            "32feet.NET security call). Any attacker who reverses the app pairs with it every " +
                            "time. Inferred because a static scanner cannot prove the literal is passed to " +
                            "the pairing call, but the proximity is evidence enough to open for triage.") `
                        -Fix 'Require the user to enter the passkey shown on the peripheral, or derive a per-device passkey from a device-unique attestation. Never ship a fixed PIN.'
                }
            }
        }

        # ---- ble-pair.hardcoded-key-material (HIGH, Inferred) ----------------------------
        if ($hasLe) {
            # NB: 'rand' as a plain token was in an earlier draft but hits the C runtime rand
            # import in every native PE and false-positives at HIGH. Restrict to BLE-specific tokens
            # (LTK/IRK/CSRK/ediv are SMP key material names; ble_gap_* are Nordic SoftDevice symbols).
            $keyCtxRx = '(?i)(LTK|IRK|CSRK|ediv|ble_gap_enc_info|ble_gap_id_key)'
            if ([regex]::IsMatch($text, $keyCtxRx)) {
                # 32 contiguous hex chars near the context token (128 bit)
                $hexRx = '(?i)' + $keyCtxRx + '.{0,256}?[0-9a-f]{32}|[0-9a-f]{32}.{0,256}?' + $keyCtxRx
                $km = [regex]::Match($text, $hexRx)
                if ($km.Success) {
                    $sample = ($km.Value -replace '\s',' ').Substring(0, [Math]::Min(120, $km.Length))
                    New-TcpkFinding -Module 'discovery' -RuleId 'ble-pair.hardcoded-key-material' `
                        -Severity 'HIGH' -Confidence 'Inferred' `
                        -Title "$($pe.Name) ships a 128-bit constant near a BLE key-material anchor" `
                        -File $pe.FullName -Evidence $sample `
                        -Cwe @('CWE-798','CWE-321') `
                        -Description ("A 32-hex-character literal appears within 256 bytes of a BLE key-material " +
                            "identifier (LTK / IRK / CSRK / ediv / rand / ble_gap_enc_info). The WinRT LE stack " +
                            "keeps LTK/IRK inside the OS keystore and does NOT expose them to the app, so a 16-byte " +
                            "constant sitting next to these names is either a debug fixed-key path, a test vector " +
                            "shipped by mistake, or a lower-stack SDK integration that provides its own bond store. " +
                            "Inferred because entropy alone cannot prove intent.") `
                        -Fix 'Delete debug fixed-key paths from the release build. If bond material has to be persisted, use DPAPI or WinRT KeyCredentialManager; never a static byte array.'
                }
            }
        }

        # ---- ble-pair.32feet-hardcoded-pin (HIGH, Inferred) ------------------------------
        # A ldstr numeric literal within 256 bytes of a 32feet.NET security surface.
        if ($hasClassic -or [regex]::IsMatch($text, 'InTheHand\.Net\.Bluetooth')) {
            $stfCtx = '(InTheHand\.Net\.Bluetooth|BluetoothSecurity\.PairRequest|BluetoothClient\.SetPin|BluetoothWin32Authentication)'
            $stfRx  = '(?is)' + $stfCtx + '.{0,256}?(?<!\d)(\d{4,16})(?!\d)|(?<!\d)(\d{4,16})(?!\d).{0,256}?' + $stfCtx
            $stfM = [regex]::Match($text, $stfRx)
            if ($stfM.Success) {
                $lit = ''
                foreach ($g in $stfM.Groups) { if ($g.Value -match '^\d{4,16}$') { $lit = $g.Value; break } }
                if ($lit -and $lit -notmatch '^(2\d{3}|19\d\d)$') {
                    New-TcpkFinding -Module 'discovery' -RuleId 'ble-pair.32feet-hardcoded-pin' `
                        -Severity 'HIGH' -Confidence 'Inferred' `
                        -Title "$($pe.Name) ships a numeric literal near 32feet.NET Bluetooth security surface" `
                        -File $pe.FullName -Evidence "literal $lit near 32feet security call" `
                        -Cwe @('CWE-798','CWE-259') `
                        -Description ("32feet.NET is a classic Bluetooth API for .NET. A ldstr of a 4-16 digit " +
                            "string sits within 256 bytes of BluetoothSecurity.PairRequest / BluetoothClient.SetPin / " +
                            "BluetoothWin32Authentication, which take a PIN parameter. Same threat model as the LE " +
                            "hardcoded-passkey rule: reversing the app yields a permanent pairing credential.") `
                        -Fix 'Prompt the user for the PIN and pass it to PairRequest. Never ship a fixed PIN.'
                }
            }
        }

        # ---- ble-pair.32feet-autoconfirm (HIGH, Inferred) --------------------------------
        # Window the Confirm=true match against the BluetoothWin32Authentication anchor so a
        # WPF binding property named Confirm or an unrelated dialog assignment cannot fire it.
        # The whitelist tokens must ALSO sit inside the same window; StringComparison.Ordinal
        # alone is not evidence of an address check and was removed (it appears in most .NET IL).
        $win32AutoRx = '(?is)BluetoothWin32Authentication.{0,512}?\bConfirm\s*=\s*true\b|\bConfirm\s*=\s*true\b.{0,512}?BluetoothWin32Authentication'
        if ([regex]::IsMatch($text, $win32AutoRx)) {
            $whitelistRx = '(?is)BluetoothWin32Authentication.{0,512}?(address\.Equals|BluetoothAddress\.Parse|\bif\b\s*\(\s*(m_)?[Cc]onfirm\b)|(address\.Equals|BluetoothAddress\.Parse|\bif\b\s*\(\s*(m_)?[Cc]onfirm\b).{0,512}?BluetoothWin32Authentication'
            $hasWhitelist = [regex]::IsMatch($text, $whitelistRx)
            if (-not $hasWhitelist) {
                New-TcpkFinding -Module 'discovery' -RuleId 'ble-pair.32feet-autoconfirm' `
                    -Severity 'HIGH' -Confidence 'Inferred' `
                    -Title "$($pe.Name) sets BluetoothWin32Authentication.Confirm=true with no visible address check" `
                    -File $pe.FullName -Evidence 'BluetoothWin32Authentication + Confirm=true within 512 chars, no address/PIN branch in the same window' `
                    -Cwe @('CWE-306') `
                    -Description ("The file uses 32feet.NET BluetoothWin32Authentication and, within 512 chars, " +
                        "assigns Confirm=true. No adjacent address comparison or PIN-branch tokens were found in " +
                        "the same proximity window. The Confirm=true assignment MAY sit inside a legitimate " +
                        "whitelist branch a static regex cannot see; treat as manual-review.") `
                    -Fix 'Compare the remote BluetoothAddress against an allow-list before setting Confirm=true, and require a user prompt for unknown addresses.'
            }
        }

        # ---- ble-pair.qt-confirm-true (HIGH, Inferred) -----------------------------------
        if ([regex]::IsMatch($text, 'pairingConfirmation\s*\(\s*true\s*\)') -and
            ($hasLe -or [regex]::IsMatch($text, 'QBluetoothLocalDevice|QLowEnergyController'))) {
            New-TcpkFinding -Module 'discovery' -RuleId 'ble-pair.qt-confirm-true' `
                -Severity 'HIGH' -Confidence 'Inferred' `
                -Title "$($pe.Name) contains 'pairingConfirmation(true)' (Qt Bluetooth auto-confirm)" `
                -File $pe.FullName -Evidence 'pairingConfirmation(true) literal in a Qt-Bluetooth binary' `
                -Cwe @('CWE-306') `
                -Description ("Qt's QBluetoothLocalDevice::pairingConfirmation(bool) accepts (true) or rejects " +
                    "(false) a pending pairing request. A literal call with true short-circuits the user prompt. " +
                    "The literal may not survive Qt moc into a shipped binary in every build config; treat as " +
                    "manual review, but the source-form match is worth surfacing.") `
                -Fix 'Route the pairingRequested signal to a UI slot that confirms with the user before calling pairingConfirmation(true).'
        }

        # ---- ble-pair.native-mitm-not-required (MEDIUM, Inferred) ------------------------
        if ([regex]::IsMatch($text, '(?<![A-Za-z0-9_])BLUETOOTH_MITM_PROTECTION_NOT_REQUIRED(?![A-Za-z0-9_])') -and
            ($hasLe -or $hasClassic -or
             [regex]::IsMatch($text, '(?<![A-Za-z0-9_])(BluetoothAuthenticateDeviceEx|BluetoothRegisterForAuthenticationEx)(?![A-Za-z0-9_])'))) {
            New-TcpkFinding -Module 'discovery' -RuleId 'ble-pair.native-mitm-not-required' `
                -Severity 'MEDIUM' -Confidence 'Inferred' `
                -Title "$($pe.Name) references BLUETOOTH_MITM_PROTECTION_NOT_REQUIRED" `
                -File $pe.FullName -Evidence 'BLUETOOTH_MITM_PROTECTION_NOT_REQUIRED + native Bluetooth surface' `
                -Cwe @('CWE-300','CWE-287') `
                -Description ("The native BLUETOOTH_MITM_PROTECTION_NOT_REQUIRED authentication-requirements " +
                    "enum value appears in the binary. Passed to BluetoothAuthenticateDeviceEx it declares that " +
                    "the app does not require MITM protection for the pairing. The literal may also appear in " +
                    "an enum-name string table without being passed at a call site; Inferred.") `
                -Fix 'Pass BLUETOOTH_MITM_PROTECTION_REQUIRED or BLUETOOTH_MITM_PROTECTION_REQUIRED_GENERAL_BONDING and fail the pair if the peripheral cannot satisfy it.'
        }

        # ---- ble-pair.sdk-legacy-pairing-forced (MEDIUM, Inferred) -----------------------
        # Nordic / TI / Silabs SDK markers that request legacy pairing (no LESC) or set MITM off.
        $sdkPatterns = @(
            @{ Pat = 'ble_gap_sec_params_t'; Neigh = '(?is)\.lesc\s*=\s*0';           Vendor = 'Nordic SoftDevice' }
            @{ Pat = 'ble_gap_sec_params_t'; Neigh = '(?is)\.mitm\s*=\s*0';           Vendor = 'Nordic SoftDevice' }
            @{ Pat = 'GAPBOND_';             Neigh = 'GAPBOND_SECURE_CONNECTION_NONE'; Vendor = 'TI SimpleLink' }
            @{ Pat = 'GAPBOND_PAIRING_MODE_NO_PAIRING'; Neigh = '.'; Vendor = 'TI SimpleLink' }
            @{ Pat = 'sl_bt_sm_configure';   Neigh = '(?is)io_capabilities\s*=\s*sl_bt_sm_io_capability_noinputnooutput'; Vendor = 'Silabs BGAPI' }
        )
        foreach ($sp in $sdkPatterns) {
            if (-not [regex]::IsMatch($text, [regex]::Escape($sp.Pat))) { continue }
            if ($sp.Neigh -ne '.' -and -not [regex]::IsMatch($text, $sp.Neigh)) { continue }
            New-TcpkFinding -Module 'discovery' -RuleId 'ble-pair.sdk-legacy-pairing-forced' `
                -Severity 'MEDIUM' -Confidence 'Inferred' `
                -Title "$($pe.Name) $($sp.Vendor) marker requests legacy or no-MITM pairing" `
                -File $pe.FullName -Evidence "$($sp.Pat) + $($sp.Neigh)" `
                -Cwe @('CWE-757','CWE-326') `
                -Description ("A $($sp.Vendor) firmware-SDK identifier in this binary is adjacent to a setting " +
                    "that turns off LE Secure Connections or MITM. The strings may appear verbatim in vendor " +
                    "sample projects included as documentation; Inferred.") `
                -Fix 'For LE Secure Connections capable stacks, set .lesc=1 and .mitm=1 (Nordic) or the equivalent for the vendor SDK. Do not ship the SDK example values unchanged.'
            break
        }
    }
}
