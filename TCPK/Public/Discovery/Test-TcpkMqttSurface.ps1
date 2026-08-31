function Test-TcpkMqttSurface {
<#
.SYNOPSIS
    A57. MQTT client surface: transport, credentials, client-id, subscription topology,
    TLS verification, and stale-dependency posture on a Windows thick client.

.DESCRIPTION
    A companion app that talks to an IoT peripheral almost always speaks MQTT to its
    cloud broker at some point in the flow. TCPK currently sees the network side of
    that only after a live pcap (pcap.mqtt-cleartext in _Pcap.ps1) and the credentials
    inside an authority-form URI (secrets.mqtt-url-with-creds). This cmdlet closes the
    static gap: the MQTT library, the transport it opens, the credentials passed to
    it, the client identifier baked in, the topics it subscribes to, and the TLS-verify
    lambda body.

    Supported libraries (per-file anchor gate):
      * MQTTnet (.NET)                      MQTTnet, MqttClientOptionsBuilder, MqttClientTlsOptions
      * uPLibrary.Networking.M2Mqtt (.NET)  M2Mqtt, uPLibrary.Networking.M2Mqtt
      * System.Net.Mqtt (deprecated)        System.Net.Mqtt
      * paho.mqtt (Python)                  paho.mqtt.client (import in a .py under Path)
      * paho.mqtt.c (native)                PE import MQTTClient_connect / MQTTAsync_connect
      * esp-mqtt (bundled firmware)         esp_mqtt_client_config_t, MQTT_TRANSPORT_OVER_

    Rules (rule id / severity / confidence):
      mqtt.library-present                INFO      Confirmed  MQTT library detected
      mqtt.systemnetmqtt-unmaintained     MEDIUM    Confirmed  Xamarin System.Net.Mqtt ships (archived 2019)
      mqtt.cleartext-uri                  HIGH      Confirmed  mqtt:// literal or tcp://host:1883 literal
      mqtt.paho-c-nontls-build            HIGH      Inferred   paho-mqtt3c/3a only, no 3cs/3as sibling
      mqtt.mqttnet-tls-absent             HIGH      Inferred   WithTcpServer present, no WithTls in same file
      mqtt.tls-explicit-disable           HIGH      Confirmed  UseTls=false / UseTls(false)
      mqtt.paho-python-tls-absent         HIGH      Inferred   paho import + connect() with no tls_set() in same file
      mqtt.tls-verify-off                 HIGH      Confirmed  WithAllowUntrustedCertificates(true) / WithIgnoreCertificateChainErrors(true)
      mqtt.hardcoded-credentials          CRITICAL  Confirmed  WithCredentials("user","pass") string literal pair
      mqtt.static-clientid                HIGH      Inferred   WithClientId("literal") + no Guid/uuid/random neighbour
      mqtt.root-wildcard-subscribe        HIGH      Confirmed  SubscribeAsync with '#' or '+' in topic literal
      mqtt.esp-transport-tcp              HIGH      Confirmed  MQTT_TRANSPORT_OVER_TCP in a shipped firmware blob
      mqtt.no-keepalive                   LOW       Confirmed  WithNoKeepAlive() / KeepAlivePeriod=TimeSpan.Zero

.PARAMETER Path
    Install directory or a single file.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { return }

    # Family anchors. A rule may fire on a given file only when an MQTT anchor sits in
    # THAT file, so a benign log line mentioning 'MQTT' elsewhere in the install tree
    # cannot cross-contaminate an unrelated binary.
    $anchors = @(
        'MQTTnet', 'MqttClientOptionsBuilder', 'MqttClientTlsOptions',
        'M2Mqtt', 'uPLibrary.Networking.M2Mqtt', 'System.Net.Mqtt',
        'MQTTClient_connect', 'MQTTAsync_connect',
        'esp_mqtt_client_config_t', 'esp_mqtt_client_init', 'MQTT_TRANSPORT_OVER_',
        'paho.mqtt.client', 'paho.mqtt'
    )
    $anchorRx = '(?<![A-Za-z0-9_])(' + (($anchors | ForEach-Object { [regex]::Escape($_) }) -join '|') + ')(?![A-Za-z0-9_])'

    # Enumerate PE files and .py files in the tree.
    $peItems = @()
    $pyItems = @()
    $item = Get-Item -LiteralPath $Path
    if ($item.PSIsContainer) {
        try { $peItems = @(Get-TcpkPeFiles -Path $Path) } catch { }
        try {
            $pyItems = @(Get-ChildItem -LiteralPath $Path -Recurse -File -Filter '*.py' -ErrorAction SilentlyContinue |
                         Where-Object { $_.Length -lt 524288 })
        } catch { }
    } else {
        try { $peItems = @([IO.FileInfo]::new((Resolve-Path -LiteralPath $Path).Path)) } catch { }
    }

    # Track which install directory hosts paho-mqtt3c / 3a (non-TLS Paho C library).
    $pahoCPresent  = $false
    $pahoCsPresent = $false
    foreach ($f in $peItems) {
        $lower = $f.Name.ToLowerInvariant()
        if ($lower -in 'paho-mqtt3c.dll','paho-mqtt3a.dll') { $pahoCPresent  = $true }
        if ($lower -in 'paho-mqtt3cs.dll','paho-mqtt3as.dll') { $pahoCsPresent = $true }
    }

    $files = @() + $peItems + $pyItems

    foreach ($f in $files) {
        if ($f -is [IO.FileInfo] -and (Test-TcpkIsFrameworkFile $f.Name)) { continue }
        # Skip paho-python source code itself. A site-packages\paho\mqtt\client.py imports
        # paho.mqtt, calls .connect(), and never calls .tls_set() - that is the library, not
        # the consumer, and the paho-python-tls-absent rule would false-positive on every
        # install that ships paho as a transitive dep.
        $pathLc = $f.FullName.ToLowerInvariant()
        if ($pathLc -like '*\paho\mqtt\*.py' -or $pathLc -like '*/paho/mqtt/*.py' -or
            $pathLc -like '*\site-packages\paho\*' -or $pathLc -like '*/site-packages/paho/*') { continue }

        $text = $null
        try {
            if ($f.Extension -ieq '.py') { $text = [IO.File]::ReadAllText($f.FullName) }
            else { $text = Read-TcpkAllText -Path $f.FullName }
        } catch { continue }
        if (-not $text) { continue }

        # Anchor gate.
        if (-not [regex]::IsMatch($text, $anchorRx)) { continue }

        # ---- mqtt.library-present (INFO, Confirmed) ---------------------------------
        $whichAnchor = [regex]::Match($text, $anchorRx).Groups[1].Value
        New-TcpkFinding -Module 'discovery' -RuleId 'mqtt.library-present' `
            -Severity 'INFO' -Confidence 'Confirmed' `
            -Title "$($f.Name) references an MQTT library ($whichAnchor)" `
            -File $f.FullName -Evidence "anchor=$whichAnchor" `
            -Description ("Inventory rule. The file references an MQTT client library. The rule set below is " +
                "gated on this anchor so the noisier grep rules cannot fire on files that do not actually speak MQTT.") `
            -Fix 'No fix. Scope information for the MQTT rules that follow.'

        # ---- mqtt.systemnetmqtt-unmaintained (MEDIUM, Confirmed) --------------------
        if ($f.Extension -in '.dll', '.exe' -and $f.Name -like 'System.Net.Mqtt*') {
            New-TcpkFinding -Module 'discovery' -RuleId 'mqtt.systemnetmqtt-unmaintained' `
                -Severity 'MEDIUM' -Confidence 'Confirmed' `
                -Title "$($f.Name) is the archived Xamarin System.Net.Mqtt client" `
                -File $f.FullName -Evidence 'assembly System.Net.Mqtt.dll present; xamarin/mqtt archived 2019' `
                -Cwe @('CWE-1104') `
                -Description ("System.Net.Mqtt was a Xamarin community MQTT client that was archived in 2019 " +
                    "and receives no security patches. Shipping it in a companion app means CVEs disclosed in " +
                    "any of its transport / parser dependencies will not be fixed upstream.") `
                -Fix 'Migrate to MQTTnet (dotnet/MQTTnet) or a maintained alternative and remove the System.Net.Mqtt dependency.'
        }

        # ---- mqtt.cleartext-uri (HIGH, Confirmed) -----------------------------------
        $uriM = [regex]::Match($text, '(?i)mqtt://[^\s"''<>]+')
        if (-not $uriM.Success) {
            $uriM = [regex]::Match($text, '(?i)tcp://[^\s"''<>]+:1883(?![0-9])')
        }
        if ($uriM.Success) {
            $uri = $uriM.Value
            # Downgrade when the same file also contains a mqtts:// / ssl:// literal.
            $hasSec = [regex]::IsMatch($text, '(?i)(mqtts://|ssl://|wss://)[^\s"''<>]+')
            $sev = if ($hasSec) { 'MEDIUM' } else { 'HIGH' }
            New-TcpkFinding -Module 'discovery' -RuleId 'mqtt.cleartext-uri' `
                -Severity $sev -Confidence 'Confirmed' `
                -Title "$($f.Name) contains a cleartext MQTT endpoint: $uri" `
                -File $f.FullName -Evidence "URI=$uri$(if ($hasSec) { ' (mqtts sibling present)' } else { '' })" `
                -Cwe @('CWE-319') `
                -Description ("The file carries a cleartext MQTT endpoint literal ($uri). A network attacker on " +
                    "the path can read the topic stream and, for a broker that permits it, publish or subscribe " +
                    "as any client whose credentials are re-observed. Downgraded to MEDIUM when a mqtts:// / " +
                    "ssl:// / wss:// literal for a related host is also present (dev vs prod).") `
                -Fix 'Move to mqtts:// on port 8883 (or wss:// 443) and pin the broker certificate on the client.'
        }

        # ---- mqtt.mqttnet-tls-absent (HIGH, Inferred) -------------------------------
        # Only when the file is MQTTnet-fingerprinted (avoids firing on M2Mqtt-only files
        # where WithTcpServer is not the surface).
        if ([regex]::IsMatch($text, '(?<![A-Za-z0-9_])MQTTnet(?![A-Za-z0-9_])') -and
            [regex]::IsMatch($text, '(?<![A-Za-z0-9_])WithTcpServer(?![A-Za-z0-9_])') -and
            -not [regex]::IsMatch($text, '(?<![A-Za-z0-9_])WithTls(?![A-Za-z0-9_])') -and
            -not [regex]::IsMatch($text, '(?<![A-Za-z0-9_])MqttClientTlsOptions(?![A-Za-z0-9_])')) {
            New-TcpkFinding -Module 'discovery' -RuleId 'mqtt.mqttnet-tls-absent' `
                -Severity 'HIGH' -Confidence 'Inferred' `
                -Title "$($f.Name) MQTTnet options include WithTcpServer but never WithTls" `
                -File $f.FullName -Evidence "'MQTTnet' + 'WithTcpServer' present, 'WithTls' and 'MqttClientTlsOptions' absent" `
                -Cwe @('CWE-319') `
                -Description ("MQTTnet is TLS-opt-in. When an assembly calls WithTcpServer and never references " +
                    "WithTls (or the MqttClientTlsOptions builder), the connection is cleartext. Inferred " +
                    "because the absence of a string in a compiled assembly is not proof (obfuscation, dead-code " +
                    "elimination) but is a strong tell in normal .NET.") `
                -Fix 'Chain .WithTls() onto the MqttClientOptionsBuilder, and pin the broker certificate via WithCertificateValidationHandler.'
        }

        # ---- mqtt.tls-explicit-disable (HIGH, Confirmed) ----------------------------
        if ([regex]::IsMatch($text, 'UseTls\s*=\s*false') -or
            [regex]::IsMatch($text, '\.UseTls\s*\(\s*false\s*\)')) {
            New-TcpkFinding -Module 'discovery' -RuleId 'mqtt.tls-explicit-disable' `
                -Severity 'HIGH' -Confidence 'Confirmed' `
                -Title "$($f.Name) explicitly turns off MQTT TLS (UseTls=false)" `
                -File $f.FullName -Evidence "'UseTls=false' or '.UseTls(false)' literal" `
                -Cwe @('CWE-319') `
                -Description ("The file assigns UseTls=false on an MQTT client options / TLS options block. " +
                    "This overrides any default the surrounding framework would have set to true. Same threat " +
                    "model as mqtt.cleartext-uri.") `
                -Fix 'Remove the UseTls=false assignment. If dev/CI needs a plaintext local broker, gate it on a build symbol, not a shipped value.'
        }

        # ---- mqtt.paho-python-tls-absent (HIGH, Inferred) ---------------------------
        if ($f.Extension -ieq '.py' -and
            [regex]::IsMatch($text, '(?m)^\s*(from|import)\s+paho\.mqtt') -and
            [regex]::IsMatch($text, '\.connect\s*\(') -and
            -not [regex]::IsMatch($text, '\.tls_set\s*\(')) {
            New-TcpkFinding -Module 'discovery' -RuleId 'mqtt.paho-python-tls-absent' `
                -Severity 'HIGH' -Confidence 'Inferred' `
                -Title "$($f.Name) paho.mqtt client connects with no tls_set() in the same file" `
                -File $f.FullName -Evidence "paho.mqtt import + .connect() call, no .tls_set() call in same file" `
                -Cwe @('CWE-319') `
                -Description ("A .py under the install tree imports paho.mqtt, calls .connect(), and never " +
                    "calls .tls_set(). Paho's client defaults to plaintext; TLS is opt-in. Inferred because " +
                    "tls_set() may be called from a helper module in a different file (add a wrapper module " +
                    "and this rule stops firing).") `
                -Fix 'Call .tls_set(ca_certs=..., cert_reqs=ssl.CERT_REQUIRED) before .connect(), and set .tls_insecure_set(False).'
        }

        # ---- mqtt.tls-verify-off (HIGH, Confirmed) ----------------------------------
        if ([regex]::IsMatch($text, '\.WithAllowUntrustedCertificates\s*\(\s*true\s*\)') -or
            [regex]::IsMatch($text, '\.WithIgnoreCertificateChainErrors\s*\(\s*true\s*\)') -or
            [regex]::IsMatch($text, '\.tls_insecure_set\s*\(\s*True\s*\)')) {
            $which = if ([regex]::IsMatch($text, '\.WithAllowUntrustedCertificates')) { 'WithAllowUntrustedCertificates(true)' }
                     elseif ([regex]::IsMatch($text, '\.WithIgnoreCertificateChainErrors')) { 'WithIgnoreCertificateChainErrors(true)' }
                     else { 'tls_insecure_set(True)' }
            New-TcpkFinding -Module 'discovery' -RuleId 'mqtt.tls-verify-off' `
                -Severity 'HIGH' -Confidence 'Confirmed' `
                -Title "$($f.Name) turns off MQTT TLS certificate validation ($which)" `
                -File $f.FullName -Evidence $which `
                -Cwe @('CWE-295') `
                -Description ("TLS is used but the client turns off certificate validation. Any attacker on the " +
                    "path with a self-signed cert can MITM the broker connection.") `
                -Fix 'Remove the option. If a private CA is needed, load it explicitly via WithCertificateValidationHandler (MQTTnet) or ca_certs= (paho).'
        }

        # ---- mqtt.hardcoded-credentials (CRITICAL, Confirmed) -----------------------
        $credRx =
            'WithCredentials\s*\(\s*"([^"]{1,64})"\s*,\s*"([^"]{1,64})"' + '|' +
            '\.Connect\s*\(\s*"[^"]+"\s*,\s*"([^"]+)"\s*,\s*"([^"]+)"'
        $credM = [regex]::Match($text, $credRx)
        if ($credM.Success) {
            # Ignore format-string placeholders, tokens with a curly brace, and empty strings.
            $user = ''; $pass = ''
            for ($gi = 1; $gi -lt $credM.Groups.Count; $gi++) {
                if ($credM.Groups[$gi].Success -and $credM.Groups[$gi].Value) {
                    if (-not $user) { $user = $credM.Groups[$gi].Value; continue }
                    if (-not $pass) { $pass = $credM.Groups[$gi].Value; break }
                }
            }
            $userOk = ($user -and $user -notmatch '[{%]' -and $user -ne 'null' -and $user -ne 'admin')
            $passOk = ($pass -and $pass -notmatch '[{%]')
            if ($userOk -and $passOk) {
                New-TcpkFinding -Module 'discovery' -RuleId 'mqtt.hardcoded-credentials' `
                    -Severity 'CRITICAL' -Confidence 'Confirmed' `
                    -Title "$($f.Name) ships hardcoded MQTT credentials (user=$user)" `
                    -File $f.FullName -Evidence "user=$user; pass=$('*' * $pass.Length) (len=$($pass.Length))" `
                    -Cwe @('CWE-798') `
                    -Description ("Both the broker username and password are shipped as string literals in the " +
                        "client. Any installer holder has the credential permanently. If the broker enforces " +
                        "per-client ACLs on the same account, an attacker publishes and subscribes as this app.") `
                    -Fix 'Fetch broker credentials at runtime from a per-user store (DPAPI, OS keychain, or an SDK CredentialProvider). Do not embed them.'
            }
        }

        # ---- mqtt.static-clientid (HIGH, Inferred) ----------------------------------
        $cidM = [regex]::Match($text, 'WithClientId\s*\(\s*"([^"]{1,64})"\s*\)')
        if (-not $cidM.Success) {
            $cidM = [regex]::Match($text, 'mqtt\.Client\s*\(\s*(?:client_id\s*=\s*)?["'']([^"'']{1,64})["'']')
        }
        if ($cidM.Success) {
            $cid = $cidM.Groups[1].Value
            # Ignore format strings and any file that references a randomizer in the same file.
            $isFormat = ($cid -match '[{%]')
            # NB: bare 'Random' as a substring was too loose - almost every .NET DLL ships
            # System.Random in the import table and any file that contains ANY use of Random
            # would silently disable the rule. Require an actual randomiser idiom.
            $hasRand  = [regex]::IsMatch($text, '(Guid\.NewGuid|new\s+Guid|Environment\.MachineName|new\s+Random|Random\s*\(\s*\)|uuid\.uuid4|os\.urandom)')
            if (-not $isFormat -and -not $hasRand -and $cid) {
                New-TcpkFinding -Module 'discovery' -RuleId 'mqtt.static-clientid' `
                    -Severity 'HIGH' -Confidence 'Inferred' `
                    -Title "$($f.Name) uses a shipped-constant MQTT ClientId ($cid)" `
                    -File $f.FullName -Evidence "clientId=$cid; no Guid/Random/MachineName token in same file" `
                    -Cwe @('CWE-798','CWE-384') `
                    -Description ("The MQTT client identifier is a shipped constant. MQTT brokers disconnect any " +
                        "prior session that reconnects with the same ClientId. An attacker with the credentials " +
                        "(or a broker that trusts client id alone) can force-boot the legitimate client by " +
                        "reconnecting with the same id, and inherit its subscriptions.") `
                    -Fix 'Derive ClientId from a per-install unique value: WithClientId($"{productPrefix}-{Guid.NewGuid()}") or uuid.uuid4() in Python.'
            }
        }

        # ---- mqtt.root-wildcard-subscribe (HIGH, Confirmed) -------------------------
        # Rule fires on a subscribe topic literal that contains '#' or '+' as a wildcard.
        $subs = [regex]::Matches($text, '(?:SubscribeAsync|WithTopic|\.subscribe|MQTTClient_subscribe)\s*\(\s*"([^"]{1,120})"')
        foreach ($sm in $subs) {
            $topic = $sm.Groups[1].Value
            if ($topic -notmatch '[#+]') { continue }
            $isRoot = ($topic -eq '#' -or $topic -eq '+' -or $topic -match '^([^/]{0,20}/){0,1}[#+]$')
            $sev = if ($isRoot) { 'HIGH' } else { 'MEDIUM' }
            New-TcpkFinding -Module 'discovery' -RuleId 'mqtt.root-wildcard-subscribe' `
                -Severity $sev -Confidence 'Confirmed' `
                -Title "$($f.Name) subscribes with an MQTT wildcard: $topic" `
                -File $f.FullName -Evidence "SubscribeAsync topic=$topic" `
                -Cwe @('CWE-284') `
                -Description ("The client subscribes to '$topic'. A single-'#' or 'prefix/#' subscription " +
                    "receives every message under that prefix, so if the broker's authorization is topic-tenanted " +
                    "the client sees other tenants' data. Scoped wildcards further down the path (e.g. " +
                    "tenant/{id}/+/status) are legitimate; those are reported as MEDIUM.") `
                -Fix 'Subscribe only to the specific tenanted topic the client owns. If the client is a fleet manager, run a broker-side ACL that restricts wildcard grants to that account.'
            break
        }

        # ---- mqtt.esp-transport-tcp (HIGH, Confirmed) -------------------------------
        if ([regex]::IsMatch($text, '(?<![A-Za-z0-9_])MQTT_TRANSPORT_OVER_TCP(?![A-Za-z0-9_])') -and
            -not [regex]::IsMatch($text, '(?<![A-Za-z0-9_])MQTT_TRANSPORT_OVER_SSL(?![A-Za-z0-9_])') -and
            -not [regex]::IsMatch($text, '(?<![A-Za-z0-9_])MQTT_TRANSPORT_OVER_WSS(?![A-Za-z0-9_])')) {
            New-TcpkFinding -Module 'discovery' -RuleId 'mqtt.esp-transport-tcp' `
                -Severity 'HIGH' -Confidence 'Confirmed' `
                -Title "$($f.Name) esp-mqtt configured for MQTT_TRANSPORT_OVER_TCP (no TLS)" `
                -File $f.FullName -Evidence 'MQTT_TRANSPORT_OVER_TCP present; no OVER_SSL / OVER_WSS in same file' `
                -Cwe @('CWE-319') `
                -Description ("A bundled ESP-IDF firmware / companion binary declares the esp-mqtt transport as " +
                    "OVER_TCP and never references OVER_SSL or OVER_WSS in the same file. The peripheral talks " +
                    "cleartext to its cloud broker.") `
                -Fix 'Rebuild with MQTT_TRANSPORT_OVER_SSL, pin the broker CA at compile time, and reject transports below WSS in the client config.'
        }

        # ---- mqtt.no-keepalive (LOW, Confirmed) -------------------------------------
        if ([regex]::IsMatch($text, '\.WithNoKeepAlive\s*\(\s*\)') -or
            [regex]::IsMatch($text, '\.WithKeepAlivePeriod\s*\(\s*TimeSpan\.Zero')) {
            New-TcpkFinding -Module 'discovery' -RuleId 'mqtt.no-keepalive' `
                -Severity 'LOW' -Confidence 'Confirmed' `
                -Title "$($f.Name) disables MQTT keepalive" `
                -File $f.FullName -Evidence "'WithNoKeepAlive()' or 'WithKeepAlivePeriod(TimeSpan.Zero)' present" `
                -Cwe @('CWE-693') `
                -Description ("Keepalive is disabled or zero. The broker cannot detect a dead session and will " +
                    "leave the client id occupied until a hard TCP timeout, which delays legitimate reconnects " +
                    "and complicates LWT-based device-state tracking.") `
                -Fix 'Set a modest keepalive (30-60s) or leave the MQTT default 60s.'
        }
    }

    # ---- mqtt.paho-c-nontls-build (HIGH, Inferred) ---------------------------------
    # Directory-scoped: fires once per install tree when the non-TLS Paho C variant ships
    # and the TLS variant does not.
    if ($pahoCPresent -and -not $pahoCsPresent) {
        $sample = ($peItems | Where-Object { $_.Name.ToLowerInvariant() -in 'paho-mqtt3c.dll','paho-mqtt3a.dll' } | Select-Object -First 1)
        if ($sample) {
            New-TcpkFinding -Module 'discovery' -RuleId 'mqtt.paho-c-nontls-build' `
                -Severity 'HIGH' -Confidence 'Inferred' `
                -Title "Non-TLS Eclipse Paho C library ships without a TLS-capable sibling" `
                -File $sample.FullName -Evidence "$($sample.Name) present; no paho-mqtt3cs.dll / paho-mqtt3as.dll sibling" `
                -Cwe @('CWE-319') `
                -Description ("The install tree ships paho-mqtt3c.dll / paho-mqtt3a.dll (non-TLS build) and " +
                    "does not ship paho-mqtt3cs.dll / paho-mqtt3as.dll (TLS build). The Eclipse Paho C library " +
                    "must be built with the -s suffix to support TLS; without it the app cannot use mqtts:// " +
                    "even if the code tries to. Inferred because the app may load the DLL from another location " +
                    "at runtime.") `
                -Fix 'Ship paho-mqtt3cs.dll (or 3as for async) and link against it. Do not carry the non-TLS variant in a production release.'
        }
    }
}
