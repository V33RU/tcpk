function Test-TcpkIotCloudCreds {
<#
.SYNOPSIS
    A63. AWS IoT Core Thing certificates and Azure IoT Hub connection strings shipped
    inside the install tree. Post-provisioning credential leaks, distinct from the
    A58 provisioning-PoP surface (claim / DPS enrollment).

.DESCRIPTION
    Two shapes, both HIGH Confirmed:

      * AWS IoT Core Thing cert:  a client X.509 certificate + matching private key
        pair shipped inside the install tree, alongside an AWS IoT Core MQTT
        endpoint reference (`iot.<region>.amazonaws.com`, `-ats.iot.<region>.amazonaws.com`,
        or the topic literal `$aws/things/*/shadow/`). Any installer holder has the
        Thing's identity and speaks to IoT Core as it.

      * Azure IoT Hub connection string: the canonical
        `HostName=<hub>.azure-devices.net;DeviceId=<id>;SharedAccessKey=<b64>`
        shape in a shipped .config / .json / .env / .cs / .cpp / .py / .yaml.
        Same threat: any installer holder is that device.

    Rules:
      creds.aws-iot-thing-cert            HIGH   Confirmed
      creds.azure-iothub-connection-string HIGH  Confirmed
      creds.azure-iothub-sas-token         HIGH  Confirmed  (short-lived SAS shipped)

    Distinct from A58 Test-TcpkProvisioningPoP (which fires on the CLAIM cert /
    DPS enrollment key, i.e. the bootstrap material). This rule fires on the
    per-device operational credentials that come out of provisioning.

.PARAMETER Path
    Install directory or a single file.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { return }

    # ---- Enumerate scanning candidates -------------------------------------------
    $item = Get-Item -LiteralPath $Path
    $configExts = @('.json','.xml','.config','.yaml','.yml','.ini','.env','.toml','.cfg','.conf',
                    '.properties','.cs','.cpp','.c','.h','.hpp','.py','.js','.ts','.plist')
    $treeFiles = @()
    if ($item.PSIsContainer) {
        try {
            $treeFiles = @(Get-ChildItem -LiteralPath $Path -Recurse -File -ErrorAction SilentlyContinue |
                           Where-Object { $_.Length -lt 1048576 })
        } catch { return }
    } else {
        $treeFiles = @($item)
    }
    if ($treeFiles.Count -eq 0) { return }

    # Text-scannable subset
    $textFiles = @($treeFiles | Where-Object { $configExts -contains $_.Extension.ToLowerInvariant() })

    # ---- Azure IoT Hub connection string / SAS token -----------------------------
    # Canonical shape: HostName=<hub>.azure-devices.net;DeviceId=<id>;SharedAccessKey=<b64>
    # Also allow SharedAccessKeyName= (service-side, elevated). And SAS token:
    #   SharedAccessSignature sr=<uri>&sig=<b64url>&se=<epoch>&skn=<keyName>
    $connRx = '(?is)HostName\s*=\s*([a-z0-9\-]+\.azure-devices\.net)\s*;\s*(?:DeviceId\s*=\s*([^;\r\n"'']+)\s*;\s*)?(?:SharedAccessKeyName\s*=\s*[^;\r\n"'']+\s*;\s*)?SharedAccessKey\s*=\s*([A-Za-z0-9+/=]{20,})'
    $sasRx  = '(?i)SharedAccessSignature\s+sr=[^&\s"''<>]+&sig=[A-Za-z0-9%+/=]+&se=\d+(?:&skn=[^&\s"''<>]+)?'

    foreach ($f in $textFiles) {
        $body = $null
        try { $body = [IO.File]::ReadAllText($f.FullName) } catch { continue }
        if (-not $body) { continue }
        if ($body.IndexOf('azure-devices.net', [StringComparison]::OrdinalIgnoreCase) -ge 0) {
            $seen = New-Object 'System.Collections.Generic.HashSet[string]'
            foreach ($m in [regex]::Matches($body, $connRx)) {
                $hub = $m.Groups[1].Value
                $dev = $m.Groups[2].Value
                $key = $m.Groups[3].Value
                if (-not $key -or $key.Length -lt 20) { continue }
                # Placeholder rejection
                if ($key -match '^(X+|0+|<[^>]+>|\$\{[^}]+\}|YOUR[_-]?KEY|PLACEHOLDER|CHANGEME|SharedAccessKey)$') { continue }
                $sig = "$hub|$dev|$($key.Substring(0,[Math]::Min(8,$key.Length)))"
                if ($seen.Contains($sig)) { continue }
                [void]$seen.Add($sig)
                $maskedKey = $key.Substring(0,1) + '***' + $key.Substring($key.Length - 1, 1) + " (len=$($key.Length))"
                New-TcpkFinding -Module 'discovery' -RuleId 'creds.azure-iothub-connection-string' `
                    -Severity 'HIGH' -Confidence 'Confirmed' `
                    -Title "$($f.Name) ships an Azure IoT Hub connection string (hub=$hub, deviceId=$(if($dev){$dev}else{'<not captured>'}))" `
                    -File $f.FullName -Evidence "HostName=$hub;DeviceId=$dev;SharedAccessKey=$maskedKey" `
                    -Cwe @('CWE-798','CWE-321','CWE-522') `
                    -Description ('The shipped file carries a canonical Azure IoT Hub device connection ' +
                        'string. The SharedAccessKey is the device-level credential; any installer holder ' +
                        'speaks to Hub as this device (or SharedAccessKeyName if service-scoped) and can ' +
                        'send device telemetry, receive C2D commands and impersonate the device in every ' +
                        'downstream pipeline. Distinct from A58 provisioning: this is the post-DPS ' +
                        'operational credential, not the bootstrap.') `
                    -Fix 'Do not ship device connection strings. Provision each install through DPS (X.509 or TPM attestation), or resolve the SharedAccessKey per boot from a Cognito / Azure AD user-authenticated call. Rotate the exposed key server-side and remove the DeviceId from the fleet if the leak is external.'
            }
            foreach ($m in [regex]::Matches($body, $sasRx)) {
                $tok = $m.Value
                $sample = $tok.Substring(0, [Math]::Min(48, $tok.Length)) + '...'
                New-TcpkFinding -Module 'discovery' -RuleId 'creds.azure-iothub-sas-token' `
                    -Severity 'HIGH' -Confidence 'Confirmed' `
                    -Title "$($f.Name) ships an Azure SAS token literal" `
                    -File $f.FullName -Evidence $sample `
                    -Cwe @('CWE-798','CWE-522') `
                    -Description ('A SharedAccessSignature token is shipped as a literal in the file. SAS ' +
                        'tokens are time-scoped but sometimes minted for years; treat as a live credential ' +
                        'until confirmed otherwise. Once expired the shape stays a template for offline ' +
                        'brute-force against the underlying SharedAccessKey.') `
                    -Fix 'Mint SAS tokens on the client from a securely-stored SharedAccessKey at runtime, or move to X.509 device auth so no shared key is needed.'
            }
        }
    }

    # ---- AWS IoT Core Thing cert + private key pair ------------------------------
    # Detect by co-location: a *.crt / *.pem cert file plus a *.key / *.pem private
    # key file, in the same directory, with an AWS IoT Core reference SOMEWHERE in
    # the install tree (host, ARN, or $aws/ topic).
    if ($item.PSIsContainer) {
        # Cache the "AWS IoT Core seen anywhere" flag once per install tree.
        $awsIotSeen = $false
        foreach ($tf in $textFiles) {
            $b = $null
            try { $b = [IO.File]::ReadAllText($tf.FullName) } catch { continue }
            if (-not $b) { continue }
            if ($b -match '(?i)(?:[a-z0-9\-]+-ats\.iot\.[a-z0-9\-]+\.amazonaws\.com|iot\.[a-z0-9\-]+\.amazonaws\.com|\$aws/(?:things|events|jobs|shadow)/)') {
                $awsIotSeen = $true; break
            }
        }
        if ($awsIotSeen) {
            # Group files by directory. For each directory, find a cert + key pair.
            $byDir = @{}
            foreach ($tf in $treeFiles) {
                $d = $tf.Directory.FullName
                if (-not $byDir.ContainsKey($d)) { $byDir[$d] = @() }
                $byDir[$d] += $tf
            }
            $certNameRx = '(?i)^(?!.*(?:ca|root|chain))(?:cert(?:ificate)?|device|thing|client)[.\-_].*\.(pem|crt|cer)$|^[A-Za-z0-9\-_.]+\-certificate\.pem\.crt$|^[A-Za-z0-9\-_.]+\.cert\.pem$'
            $keyNameRx  = '(?i)^(?:private|priv|device|thing|client)[.\-_].*\.(pem|key)$|^[A-Za-z0-9\-_.]+\-private\.pem\.key$|^[A-Za-z0-9\-_.]+\.private\.key$|^[A-Za-z0-9\-_.]+\.key$'
            foreach ($d in $byDir.Keys) {
                $filesInDir = $byDir[$d]
                $certs = @($filesInDir | Where-Object { $_.Name -match $certNameRx })
                $keys  = @($filesInDir | Where-Object { $_.Name -match $keyNameRx })
                if ($certs.Count -eq 0 -or $keys.Count -eq 0) { continue }
                # Confirm the cert file actually starts with PEM header (drops false-pattern hits).
                $realCert = $null
                foreach ($c in $certs) {
                    try {
                        $head = [IO.File]::ReadAllText($c.FullName)
                    } catch { continue }
                    if ($head -match '-----BEGIN CERTIFICATE-----') { $realCert = $c; break }
                }
                if (-not $realCert) { continue }
                $realKey = $null
                foreach ($k in $keys) {
                    try { $khead = [IO.File]::ReadAllText($k.FullName) } catch { continue }
                    if ($khead -match '-----BEGIN (RSA |EC |ENCRYPTED )?PRIVATE KEY-----') { $realKey = $k; break }
                }
                if (-not $realKey) { continue }
                New-TcpkFinding -Module 'discovery' -RuleId 'creds.aws-iot-thing-cert' `
                    -Severity 'HIGH' -Confidence 'Confirmed' `
                    -Title "AWS IoT Core Thing certificate + private key shipped in $($realCert.Directory.Name)" `
                    -File $realCert.FullName -Evidence "cert=$($realCert.Name); key=$($realKey.Name); AWS IoT anchor present in install tree" `
                    -Cwe @('CWE-798','CWE-321','CWE-522') `
                    -Description ('An X.509 certificate paired with its private key is shipped in the ' +
                        'install tree, alongside an AWS IoT Core endpoint or `$aws/` topic reference. That ' +
                        'is the Thing identity: any installer holder authenticates to IoT Core as the Thing, ' +
                        'sends telemetry, receives Jobs, reads shadow, and pivots into every downstream ' +
                        'AWS service the Thing policy grants. Distinct from A58 prov.aws.claim-cert-shipped ' +
                        '(bootstrap claim); this rule fires on the operational per-device cert.') `
                    -Fix 'Provision each install with a per-device cert via AWS IoT Fleet Provisioning by Claim + a customer-authenticated backend that issues the operational cert at first run. Never ship the operational cert with the installer. Rotate the exposed cert if the leak is external.'
            }
        }
    }
}
