function Test-TcpkProvisioningPoP {
<#
.SYNOPSIS
    A58. IoT provisioning Proof-of-Possession material shipped in a Windows companion app:
    ESP-IDF Wi-Fi provisioning, AWS IoT fleet claim certs, Azure DPS symmetric keys,
    Matter setup passcodes, Zigbee install codes, and BLE Just-Works fallback markers.

.DESCRIPTION
    Provisioning is the step where a factory-fresh device joins a user's account. Every
    stack builds its authorization around a Proof-of-Possession (PoP): a shared secret,
    a claim certificate, a symmetric key, a setup passcode, or an install code. When
    that secret is shipped inside the companion app, any installer holder replays the
    provisioning flow against any device from the same product line.

    Supported stacks (per-file anchor gate):
      * ESP-IDF Wi-Fi Provisioning         WIFI_PROV_SECURITY_, wifi_prov_mgr_, wifi_prov_scheme_, esp_prov
      * AWS IoT Fleet Provisioning         $aws/certificates/create, $aws/provisioning-templates
      * Azure IoT Device Provisioning      global.azure-devices-provisioning.net, ProvisioningDeviceClient
      * Matter (CHIP) commissioning        ManualPairingCode, SetupPayload, kSetupPINCode, MT:
      * Zigbee commissioning               install_code, TCLK, ZDO_MGMT_PERMIT_JOIN_REQ
      * BLE SMP capabilities               BLE_SM_IOCAP_NO_INPUT_OUTPUT, NoInputNoOutput

    Rules (rule id / severity / confidence):
      prov.esp.wifi-prov-anchor             INFO      Confirmed  ESP-IDF wifi_provisioning stack anchor
      prov.esp.security0                    HIGH      Confirmed  WIFI_PROV_SECURITY_0 (no PoP)
      prov.esp.pop-hardcoded                HIGH      Confirmed  Shipped PoP literal near ESP anchor
      prov.esp.default-pop-sentinel         HIGH      Confirmed  Sample PoP 'abcd1234' near ESP anchor
      prov.esp.security2-creds-hardcoded    HIGH      Confirmed  WIFI_PROV_SECURITY_2 username+password literals
      prov.aws.claim-cert-shipped           HIGH      Confirmed  claim cert + key files in install tree
      prov.aws.fleet-topic                  MEDIUM    Confirmed  AWS IoT Fleet Provisioning topic literal
      prov.azure.dps-endpoint               INFO      Confirmed  Azure DPS endpoint literal
      prov.azure.dps-symkey-hardcoded       HIGH      Confirmed  SecurityProviderSymmetricKey + base64 literal
      prov.matter.passcode-hardcoded        HIGH      Confirmed  11-digit setup PIN near Matter anchor
      prov.matter.sample-pin                HIGH      Confirmed  CHIP SDK sample passcode 20202021 / 12345678
      prov.matter.qr-shipped                MEDIUM    Confirmed  Matter setup QR payload MT:... or QR image file
      prov.zigbee.default-tclk              CRITICAL  Confirmed  Well-known Zigbee TCLK 'ZigBeeAlliance09'
      prov.zigbee.install-code-hardcoded    HIGH      Confirmed  16/18-byte install code hex near Zigbee anchor
      prov.ble.just-works-fallback          MEDIUM    Confirmed  BLE NoInputNoOutput / allow_just_works=true near SMP anchor

.PARAMETER Path
    Install directory or a single file.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { return }

    # Family anchors. Per-file gate: a rule may fire only when the corresponding family
    # anchor is present in the SAME file (except AWS claim-cert which is file-based).
    $espAnchors    = @('wifi_prov_mgr_start_provisioning','wifi_prov_mgr_init','wifi_prov_scheme_ble',
                       'wifi_prov_scheme_softap','esp_prov','WIFI_PROV_SECURITY_')
    $awsAnchors    = @('$aws/certificates/create','$aws/provisioning-templates')
    $azureAnchors  = @('global.azure-devices-provisioning.net','azure-devices-provisioning.net',
                       'ProvisioningDeviceClient','SecurityProviderSymmetricKey','SecurityProviderX509')
    $matterAnchors = @('ManualPairingCode','SetupPayload','kSetupPINCode','setup_pin_code','chip-tool',
                       'matter-tool','chip::PayloadContents','SetupQRCode')
    $zigbeeAnchors = @('ZigBeeAlliance09','install_code','installCode','ZDO_MGMT_PERMIT_JOIN_REQ',
                       'TrustCenterLinkKey','TCLK')
    $bleSmpAnchors = @('BLE_SM_IOCAP_NO_INPUT_OUTPUT','NoInputNoOutput','allow_just_works','ble_sm_pair')

    function _AnchorHit([string]$Text, [string[]]$Anchors) {
        foreach ($a in $Anchors) {
            $esc = [regex]::Escape($a)
            if ([regex]::IsMatch($Text, '(?<![A-Za-z0-9_])' + $esc + '(?![A-Za-z0-9_])')) { return $a }
        }
        return $null
    }

    # Enumerate files that are worth reading: PEs, .py, .json, .xml, .config, .yaml, .ini,
    # .cfg, .txt, .h/.c/.cpp shipped alongside the companion.
    $configExts = @('.json','.xml','.config','.yaml','.yml','.ini','.cfg','.txt','.h','.c','.cpp',
                    '.hpp','.cs','.py','.js','.env','.plist','.toml','.bin','.elf')
    $peItems  = @()
    $miscItems = @()
    $item = Get-Item -LiteralPath $Path
    if ($item.PSIsContainer) {
        try { $peItems = @(Get-TcpkPeFiles -Path $Path) } catch { }
        try {
            $miscItems = @(Get-ChildItem -LiteralPath $Path -Recurse -File -ErrorAction SilentlyContinue |
                           Where-Object { $configExts -contains $_.Extension.ToLowerInvariant() -and $_.Length -lt 1048576 })
        } catch { }
    } else {
        try { $peItems = @([IO.FileInfo]::new((Resolve-Path -LiteralPath $Path).Path)) } catch { }
    }

    # --- prov.aws.claim-cert-shipped: file-based rule -------------------------------
    if ($item.PSIsContainer) {
        $claimCertPatterns = @('claim.crt','claim.cert.pem','claim-certificate.pem','bootstrap-cert.pem',
                               'provisioning-claim.pem','fleet-provisioning-cert.pem')
        $claimKeyPatterns  = @('claim.key','claim.private.key','claim-private-key.pem','bootstrap-key.pem',
                               'provisioning-claim.key','fleet-provisioning-key.pem')
        $claimCerts = @()
        $claimKeys  = @()
        try {
            $tree = @(Get-ChildItem -LiteralPath $Path -Recurse -File -ErrorAction SilentlyContinue)
            foreach ($fi in $tree) {
                $name = $fi.Name.ToLowerInvariant()
                if ($claimCertPatterns -contains $name) { $claimCerts += $fi }
                if ($claimKeyPatterns  -contains $name) { $claimKeys  += $fi }
            }
        } catch { }
        if ($claimCerts.Count -gt 0 -and $claimKeys.Count -gt 0) {
            # Cross-check: at least one bundled file must reference the AWS fleet-provisioning API topic.
            $sawAwsTopic = $false
            foreach ($mi in $miscItems + $peItems) {
                $bodyMi = $null
                try {
                    if ($mi.Extension -ieq '.dll' -or $mi.Extension -ieq '.exe' -or $mi.Extension -ieq '.sys') {
                        $bodyMi = Read-TcpkAllText -Path $mi.FullName
                    } else {
                        $bodyMi = [IO.File]::ReadAllText($mi.FullName)
                    }
                } catch { continue }
                if ($bodyMi -and (_AnchorHit $bodyMi $awsAnchors)) { $sawAwsTopic = $true; break }
            }
            if ($sawAwsTopic) {
                $cert = $claimCerts[0]; $key = $claimKeys[0]
                New-TcpkFinding -Module 'discovery' -RuleId 'prov.aws.claim-cert-shipped' `
                    -Severity 'HIGH' -Confidence 'Confirmed' `
                    -Title "AWS IoT fleet provisioning claim cert + key ship in the install tree" `
                    -File $cert.FullName -Evidence "cert=$($cert.Name); key=$($key.Name); AWS fleet-topic anchor present" `
                    -Cwe @('CWE-798','CWE-321') `
                    -Description ("Both an AWS IoT provisioning claim certificate AND its private key are shipped " +
                        "inside the install tree, and at least one bundled binary references the AWS Fleet " +
                        "Provisioning API topic. Any installer holder can run the RegisterThing flow against " +
                        "the fleet template, mint per-device certs at will, and enroll rogue devices under the " +
                        "customer's AWS account.") `
                    -Fix 'Do not ship claim credentials with the app. Provision each end user through a customer-authenticated backend that creates a per-device claim, or use user-authenticated Amazon Cognito federated identities as the provisioning principal.'
            }
        }
    }

    foreach ($f in $peItems + $miscItems) {
        if ($f -is [IO.FileInfo] -and (Test-TcpkIsFrameworkFile $f.Name)) { continue }

        $text = $null
        try {
            if ($configExts -contains $f.Extension.ToLowerInvariant()) {
                $text = [IO.File]::ReadAllText($f.FullName)
            } else {
                $text = Read-TcpkAllText -Path $f.FullName
            }
        } catch { continue }
        if (-not $text) { continue }

        $espHit    = _AnchorHit $text $espAnchors
        $awsHit    = _AnchorHit $text $awsAnchors
        $azureHit  = _AnchorHit $text $azureAnchors
        $matterHit = _AnchorHit $text $matterAnchors
        $zigbeeHit = _AnchorHit $text $zigbeeAnchors
        $bleHit    = _AnchorHit $text $bleSmpAnchors
        if (-not ($espHit -or $awsHit -or $azureHit -or $matterHit -or $zigbeeHit -or $bleHit)) { continue }

        # ---- prov.esp.wifi-prov-anchor ---------------------------------------------
        if ($espHit) {
            New-TcpkFinding -Module 'discovery' -RuleId 'prov.esp.wifi-prov-anchor' `
                -Severity 'INFO' -Confidence 'Confirmed' `
                -Title "$($f.Name) drives the ESP-IDF Wi-Fi provisioning stack ($espHit)" `
                -File $f.FullName -Evidence "anchor=$espHit" `
                -Description ("Scope information. The file references the ESP-IDF wifi_provisioning API. The " +
                    "prov.esp.* rules are gated on this anchor to keep noise off unrelated files.") `
                -Fix 'No fix. Scope information for the ESP provisioning rules.'
        }

        # ---- prov.esp.security0 ----------------------------------------------------
        if ($espHit -and [regex]::IsMatch($text, '(?<![A-Za-z0-9_])WIFI_PROV_SECURITY_0(?![A-Za-z0-9_])')) {
            New-TcpkFinding -Module 'discovery' -RuleId 'prov.esp.security0' `
                -Severity 'HIGH' -Confidence 'Confirmed' `
                -Title "$($f.Name) configures ESP-IDF provisioning with WIFI_PROV_SECURITY_0 (no PoP)" `
                -File $f.FullName -Evidence 'WIFI_PROV_SECURITY_0 present near ESP anchor' `
                -Cwe @('CWE-306') `
                -Description ("WIFI_PROV_SECURITY_0 disables the PoP challenge and encrypts nothing on the " +
                    "wire. An attacker with radio range (BLE or SoftAP) reads the Wi-Fi credentials the user " +
                    "types into the app during onboarding and joins the same AP.") `
                -Fix 'Use WIFI_PROV_SECURITY_2 with a per-device unique username+password (or WIFI_PROV_SECURITY_1 with a per-device PoP). Never ship a static PoP.'
        }

        # ---- prov.esp.pop-hardcoded ------------------------------------------------
        # A pop=/PoP=/PROOF_OF_POSSESSION= literal near an ESP anchor. The proximity
        # window is enforced by construction: an ESP token must sit within 512 chars of
        # the pop literal, otherwise 'POP3_HOST' / 'popup' / 'popover' etc. in an ESP
        # anchored file would fire. Lowercase 'pop' is deliberately NOT case-insensitive
        # (the WinRT / config idiom is 'PoP'/'pop='/'kPop'), while the surrounding
        # capitalised variants are literal.
        if ($espHit) {
            # Two-pass. First find every candidate pop=/PoP=/PROOF_OF_POSSESSION= literal
            # (case-sensitive on the KEY - the WinRT/ESP idiom is 'pop'/'PoP'/'kPop', not
            # 'POP' which is POP3/popup/popover in unrelated JSON). Then keep only the
            # candidates whose position is within 512 chars of an ESP anchor. A file-wide
            # ESP anchor gate is not enough on its own: an ESP header file that also
            # carries a "POP3_HOST" or "popup" config elsewhere would otherwise fire.
            $popKeyRx = '(?<![A-Za-z0-9_])(pop|PoP|kPop|gProvPop|PROOF_OF_POSSESSION|proof[_\-]?of[_\-]?possession)(?![A-Za-z0-9_])\s*[:=]\s*["''`]([A-Za-z0-9!\-_@#$%^&*.]{4,64})["''`]'
            $espTokenRx = '(?<![A-Za-z0-9_])(WIFI_PROV_SECURITY_|wifi_prov_mgr_|esp_prov|wifi_prov_scheme_)'
            $popLit = ''
            $candidates = [regex]::Matches($text, $popKeyRx)
            foreach ($cand in $candidates) {
                $wStart = [Math]::Max(0, $cand.Index - 512)
                $wEnd   = [Math]::Min($text.Length, $cand.Index + $cand.Length + 512)
                $window = $text.Substring($wStart, $wEnd - $wStart)
                if ([regex]::IsMatch($window, $espTokenRx)) {
                    $popLit = $cand.Groups[2].Value
                    break
                }
            }
            if ($popLit -and $popLit -notin @('YOUR_POP','TODO','changeme','xxxx','')) {
                $sample = $popLit.Substring(0, [Math]::Min(6, $popLit.Length)) + '***'
                New-TcpkFinding -Module 'discovery' -RuleId 'prov.esp.pop-hardcoded' `
                    -Severity 'HIGH' -Confidence 'Confirmed' `
                    -Title "$($f.Name) ships a hardcoded ESP-IDF Wi-Fi provisioning PoP" `
                    -File $f.FullName -Evidence "pop literal (masked)=$sample (len=$($popLit.Length))" `
                    -Cwe @('CWE-798') `
                    -Description ("A PoP shared secret is a shipped constant in the companion. Any installer " +
                        "holder can run wifi_provisioning against any device from this product line and read " +
                        "the Wi-Fi credentials the user types in during onboarding, then join the same AP.") `
                    -Fix 'Generate the PoP per device at manufacture time and print it on a factory sticker / QR that the user scans in the app, or ship WIFI_PROV_SECURITY_2 with a per-device SRP6a credential.'
            }
            # Sentinel: the ESP-IDF example project's default 'abcd1234' near the anchor.
            $sentRx = '(?is)abcd1234.{0,512}?(?:WIFI_PROV_SECURITY_|wifi_prov_mgr|esp_prov)|(?:WIFI_PROV_SECURITY_|wifi_prov_mgr|esp_prov).{0,512}?abcd1234'
            if ([regex]::IsMatch($text, $sentRx)) {
                New-TcpkFinding -Module 'discovery' -RuleId 'prov.esp.default-pop-sentinel' `
                    -Severity 'HIGH' -Confidence 'Confirmed' `
                    -Title "$($f.Name) ships the ESP-IDF sample PoP 'abcd1234'" `
                    -File $f.FullName -Evidence "literal 'abcd1234' within 512 bytes of an ESP provisioning anchor" `
                    -Cwe @('CWE-1394') `
                    -Description ("'abcd1234' is the sample PoP from the ESP-IDF wifi_prov example. Shipping " +
                        "it in production means the device accepts a well-known-value provisioning session; the " +
                        "PoP guarantee has effectively been turned off.") `
                    -Fix 'Replace with a per-device secret. The sentinel exists so builds cannot ship the example unchanged.'
            }
        }

        # ---- prov.esp.security2-creds-hardcoded ------------------------------------
        if ($espHit -and [regex]::IsMatch($text, '(?<![A-Za-z0-9_])WIFI_PROV_SECURITY_2(?![A-Za-z0-9_])')) {
            $u = [regex]::Match($text, '--sec2_username[=\s]+(\S+)')
            $p = [regex]::Match($text, '--sec2_pwd[=\s]+(\S+)')
            if ($u.Success -and $p.Success) {
                $userLit = $u.Groups[1].Value
                if ($userLit -notin @('user','test','demo','example','placeholder')) {
                    New-TcpkFinding -Module 'discovery' -RuleId 'prov.esp.security2-creds-hardcoded' `
                        -Severity 'HIGH' -Confidence 'Confirmed' `
                        -Title "$($f.Name) ships hardcoded ESP-IDF WIFI_PROV_SECURITY_2 credentials" `
                        -File $f.FullName -Evidence "--sec2_username + --sec2_pwd literals present" `
                        -Cwe @('CWE-798') `
                        -Description ("WIFI_PROV_SECURITY_2 uses an SRP6a username+password. Both are shipped " +
                            "as literals in the file, so every installer holds the PoP for every device.") `
                        -Fix 'Compute per-device SRP6a credentials at manufacture time. Print the PoP on a factory sticker / QR that the user scans.'
                }
            }
        }

        # ---- prov.aws.fleet-topic --------------------------------------------------
        if ($awsHit) {
            # Escalate to HIGH when a claim cert also shipped (checked earlier by prov.aws.claim-cert-shipped)
            New-TcpkFinding -Module 'discovery' -RuleId 'prov.aws.fleet-topic' `
                -Severity 'MEDIUM' -Confidence 'Confirmed' `
                -Title "$($f.Name) invokes AWS IoT Fleet Provisioning API ($awsHit)" `
                -File $f.FullName -Evidence "topic=$awsHit" `
                -Cwe @('CWE-284') `
                -Description ("The file publishes to the AWS IoT Fleet Provisioning API. Whether this is safe " +
                    "depends on which principal is authenticated at the MQTT connection: a per-user Cognito " +
                    "identity is safe, a shared claim certificate shipped with the app is not (see " +
                    "prov.aws.claim-cert-shipped).") `
                -Fix 'Authenticate the MQTT connection with a per-user AWS credential (Cognito) rather than a shipped claim cert.'
        }

        # ---- prov.azure.dps-endpoint -----------------------------------------------
        # NB: local variable is $dpsHost, not $host. $host is a PowerShell automatic
        # variable (the runspace host); shadowing it inside this function scope would
        # leak into anything downstream that expects $host.UI to be an object.
        if ($azureHit -eq 'global.azure-devices-provisioning.net' -or
            [regex]::IsMatch($text, '(?i)[a-z0-9\-]+\.azure-devices-provisioning\.net')) {
            $dpsHost = 'global.azure-devices-provisioning.net'
            $hm = [regex]::Match($text, '(?i)([a-z0-9\-]+\.azure-devices-provisioning\.net)')
            if ($hm.Success) { $dpsHost = $hm.Groups[1].Value }
            New-TcpkFinding -Module 'discovery' -RuleId 'prov.azure.dps-endpoint' `
                -Severity 'INFO' -Confidence 'Confirmed' `
                -Title "$($f.Name) targets Azure IoT Device Provisioning Service ($dpsHost)" `
                -File $f.FullName -Evidence "host=$dpsHost" `
                -Description ("Inventory rule. The file references an Azure DPS host. Distinct from " +
                    "secrets.azure-iothub-connection which fires post-provisioning at the IoT Hub.") `
                -Fix 'No fix. Scope information.'
        }

        # ---- prov.azure.dps-symkey-hardcoded ---------------------------------------
        if ($azureHit -and [regex]::IsMatch($text, 'SecurityProviderSymmetricKey')) {
            # Base64 literal of 44 or 88 chars ending with = within 200 chars of the type name.
            $b64Rx = '(?is)SecurityProviderSymmetricKey.{0,200}?["'']([A-Za-z0-9+/]{43}=|[A-Za-z0-9+/]{86}==?)["'']|["'']([A-Za-z0-9+/]{43}=|[A-Za-z0-9+/]{86}==?)["''].{0,200}?SecurityProviderSymmetricKey'
            $b64M = [regex]::Match($text, $b64Rx)
            if ($b64M.Success) {
                $key = ''
                for ($gi = 1; $gi -lt $b64M.Groups.Count; $gi++) {
                    if ($b64M.Groups[$gi].Success -and $b64M.Groups[$gi].Value) { $key = $b64M.Groups[$gi].Value; break }
                }
                if ($key) {
                    New-TcpkFinding -Module 'discovery' -RuleId 'prov.azure.dps-symkey-hardcoded' `
                        -Severity 'HIGH' -Confidence 'Confirmed' `
                        -Title "$($f.Name) ships an Azure DPS symmetric-key attestation secret" `
                        -File $f.FullName -Evidence "SecurityProviderSymmetricKey + base64 literal (len=$($key.Length))" `
                        -Cwe @('CWE-321','CWE-798') `
                        -Description ("A base64 literal of 32 or 64 raw bytes sits within 200 chars of " +
                            "SecurityProviderSymmetricKey. In DPS symmetric-key attestation this is either the " +
                            "enrollment-group key (worst case) or a device-specific derived key baked in. Either " +
                            "way it is a permanent secret held by every installer.") `
                        -Fix 'Move to X.509 attestation (SecurityProviderX509) with a per-device certificate provisioned at manufacture, or derive the per-device key server-side from a customer-authenticated request.'
                }
            }
        }

        # ---- prov.matter.passcode-hardcoded ----------------------------------------
        if ($matterHit) {
            $mpRx = '(?is)(ManualPairingCode|SetupPayload|kSetupPINCode|setup_pin_code).{0,128}?\b(\d{11})\b|\b(\d{11})\b.{0,128}?(ManualPairingCode|SetupPayload|kSetupPINCode|setup_pin_code)'
            $mp = [regex]::Match($text, $mpRx)
            if ($mp.Success) {
                $pin = ''
                foreach ($g in $mp.Groups) { if ($g.Value -match '^\d{11}$') { $pin = $g.Value; break } }
                if ($pin -and $pin -notmatch '^(19|20)\d{9}$') {  # skip 19xxxxxxxxx / 20xxxxxxxxx (epoch-shaped)
                    New-TcpkFinding -Module 'discovery' -RuleId 'prov.matter.passcode-hardcoded' `
                        -Severity 'HIGH' -Confidence 'Confirmed' `
                        -Title "$($f.Name) ships a Matter commissioning passcode literal" `
                        -File $f.FullName -Evidence "11-digit passcode near Matter anchor $matterHit (masked=$($pin.Substring(0,3))********)" `
                        -Cwe @('CWE-798') `
                        -Description ("A Matter setup passcode is an 11-digit decimal used by SPAKE2+ at " +
                            "commissioning. Shipped as a literal in the companion, any installer holder can " +
                            "commission any device from the same product line onto their own fabric.") `
                        -Fix 'Do not embed the passcode. The device prints its passcode on a factory sticker + QR; the user scans it in the app.'
                }
            }
            # Sentinel: CHIP SDK sample passcodes.
            foreach ($sent in @('20202021','12345678')) {
                $rx = '(?is)' + [regex]::Escape($sent) + '.{0,256}?(ManualPairingCode|SetupPayload|kSetupPINCode|setup_pin_code|MT:)|(ManualPairingCode|SetupPayload|kSetupPINCode|setup_pin_code|MT:).{0,256}?' + [regex]::Escape($sent)
                if ([regex]::IsMatch($text, $rx)) {
                    New-TcpkFinding -Module 'discovery' -RuleId 'prov.matter.sample-pin' `
                        -Severity 'HIGH' -Confidence 'Confirmed' `
                        -Title "$($f.Name) ships the CHIP SDK sample Matter passcode $sent" `
                        -File $f.FullName -Evidence "literal '$sent' within 256 bytes of a Matter anchor" `
                        -Cwe @('CWE-1188','CWE-1394') `
                        -Description ("$sent is a sample passcode in the CHIP / Matter SDK examples. Shipping it " +
                            "in production means the device accepts a well-known passcode; commissioning is " +
                            "effectively unauthenticated.") `
                        -Fix 'Replace with a factory-generated per-device passcode.'
                    break
                }
            }
            # QR payload MT:...
            $qrM = [regex]::Match($text, 'MT:[A-Z0-9\.\-]{19,}')
            if ($qrM.Success) {
                New-TcpkFinding -Module 'discovery' -RuleId 'prov.matter.qr-shipped' `
                    -Severity 'MEDIUM' -Confidence 'Confirmed' `
                    -Title "$($f.Name) contains a Matter setup QR payload literal" `
                    -File $f.FullName -Evidence "QR payload=$($qrM.Value.Substring(0, [Math]::Min(30,$qrM.Value.Length)))..." `
                    -Cwe @('CWE-798') `
                    -Description ("A Matter setup QR payload (MT: base38) is baked into the shipped file. The " +
                        "payload embeds the setup passcode; the same threat model as prov.matter.passcode-hardcoded.") `
                    -Fix 'Generate the QR at commissioning time from the per-device passcode; do not ship a fixed QR.'
            }
        }

        # ---- prov.zigbee.default-tclk ----------------------------------------------
        if ([regex]::IsMatch($text, '(?<![A-Za-z0-9_])ZigBeeAlliance09(?![A-Za-z0-9_])') -or
            [regex]::IsMatch($text, '(?i)5A6967426565416C6C69616E63653039')) {
            New-TcpkFinding -Module 'discovery' -RuleId 'prov.zigbee.default-tclk' `
                -Severity 'CRITICAL' -Confidence 'Confirmed' `
                -Title "$($f.Name) ships the well-known Zigbee Trust Center Link Key" `
                -File $f.FullName -Evidence "'ZigBeeAlliance09' or hex 5A6967426565416C6C69616E63653039 present" `
                -Cwe @('CWE-1394','CWE-321') `
                -Description ("'ZigBeeAlliance09' is the Zigbee Alliance well-known Trust Center Link Key, " +
                    "designed to bootstrap a device onto a temporary trust anchor before rekeying. If the app or " +
                    "device retains it as a real TCLK, any Zigbee sniffer on the same channel decrypts the " +
                    "network key exchange and reads the mesh.") `
                -Fix 'Use per-network install codes or per-device certified security. The well-known TCLK is only for temporary bootstrap, not for a shipped trust anchor.'
        }

        # ---- prov.zigbee.install-code-hardcoded ------------------------------------
        if ($zigbeeHit) {
            $icRx = '(?is)(install_code|installCode|InstallCode).{0,256}?\b([0-9A-Fa-f]{32}|[0-9A-Fa-f]{36})\b|\b([0-9A-Fa-f]{32}|[0-9A-Fa-f]{36})\b.{0,256}?(install_code|installCode|InstallCode)'
            $ic = [regex]::Match($text, $icRx)
            if ($ic.Success) {
                $code = ''
                foreach ($g in $ic.Groups) { if ($g.Value -match '^[0-9A-Fa-f]{32,36}$') { $code = $g.Value; break } }
                # Skip md5/sha1 shape in a manifest/hash context. The install-code neighbourhood filters most, but tighten:
                if ($code -and -not [regex]::IsMatch($text, '(?is)(md5|sha1)\s*[:=]\s*["'']?' + [regex]::Escape($code))) {
                    New-TcpkFinding -Module 'discovery' -RuleId 'prov.zigbee.install-code-hardcoded' `
                        -Severity 'HIGH' -Confidence 'Confirmed' `
                        -Title "$($f.Name) ships a Zigbee install-code literal" `
                        -File $f.FullName -Evidence "install code hex length=$($code.Length) near Zigbee anchor $zigbeeHit" `
                        -Cwe @('CWE-798') `
                        -Description ("A 16- or 18-byte hex literal sits within 256 chars of a Zigbee install-code " +
                            "token. Zigbee install codes are per-device credentials that a coordinator uses to " +
                            "derive the Trust Center Link Key. Shipped in the companion, every installer holds " +
                            "the same commissioning primitive for every device.") `
                        -Fix 'Print the install code on a factory sticker/QR and read it via the camera at commissioning time.'
                }
            }
        }

        # ---- prov.ble.just-works-fallback ------------------------------------------
        if ($bleHit -and
            ([regex]::IsMatch($text, '(?is)(BLE_SM_IOCAP_NO_INPUT_OUTPUT|NoInputNoOutput)') -or
             [regex]::IsMatch($text, '(?i)allow_just_works\s*[:=]\s*true') -or
             [regex]::IsMatch($text, '(?i)allow_unsecured_rejoin\s*[:=]\s*true'))) {
            New-TcpkFinding -Module 'discovery' -RuleId 'prov.ble.just-works-fallback' `
                -Severity 'MEDIUM' -Confidence 'Confirmed' `
                -Title "$($f.Name) permits BLE Just-Works commissioning fallback" `
                -File $f.FullName -Evidence "SMP IO capability NoInputNoOutput or allow_just_works=true near $bleHit" `
                -Cwe @('CWE-306','CWE-1391') `
                -Description ("The file declares the peripheral (or the central) as NoInputNoOutput, or " +
                    "explicitly permits Just-Works commissioning as a fallback. Under SMP this negotiates a " +
                    "Just-Works ceremony: no MITM protection, any attacker in radio range pairs.") `
                -Fix 'Set the IO capability to DisplayOnly / KeyboardOnly / DisplayYesNo so the peripheral advertises a stronger ceremony. Remove allow_just_works fallbacks.'
        }
    }
}
