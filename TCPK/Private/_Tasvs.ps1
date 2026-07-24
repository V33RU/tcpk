# OWASP TASVS (Thick Client App Security Verification Standard) + OWASP Desktop App
# Security Top 10 mapping for TCPK rule IDs. Pure lookup, computed at report time from
# a finding's RuleId (same model as the MITRE ATT&CK map in _Attack.ps1) -- the
# [TcpkFinding] class is unchanged. First/any matching prefix contributes; unioned.

# Ordered list: RuleId regex -> { tasvs = TASVS category, da = Desktop App Top 10 item }.
$script:TcpkTasvsMap = @(
    @{ rx='^(callsites|deser|xxe)';                                                       tasvs=@('TASVS-CODE Code Quality'); da=@('DA1 Injection','DA8 Poor Code Quality') }
    @{ rx='^csv\.';                                                                       tasvs=@('TASVS-CODE Code Quality'); da=@('DA1 Injection') }
    @{ rx='^session\.';                                                                   tasvs=@('TASVS-AUTH Authentication & Session'); da=@('DA2 Broken Authentication','DA5 Improper Authorization') }
    @{ rx='^(jwt|authflags)';                                                             tasvs=@('TASVS-AUTH Authentication & Session'); da=@('DA2 Broken Authentication') }
    @{ rx='^(secrets|entropy|app-?config|plaintext|keymaterial|dpapi|tokencaches|webviewcreds|localdb|credentialmanager|memorysecrets|processenvsecrets)'; tasvs=@('TASVS-STORAGE Sensitive Data Storage'); da=@('DA3 Sensitive Data Exposure') }
    @{ rx='registry.*(secret|value)';                                                     tasvs=@('TASVS-STORAGE Sensitive Data Storage'); da=@('DA3 Sensitive Data Exposure') }
    @{ rx='^crypto\.|weak-symmetric|weak-hash|aes-ecb|weak-rng|base64-as-encryption';     tasvs=@('TASVS-CRYPTO Cryptography'); da=@('DA4 Improper Cryptography Usage') }
    @{ rx='^(tls-bypass|tlspinning|tlsprotocols|tls\.|insecureschemes|scheme|crlocsp|backend|endpoints|dnsleakage|selfhost|truststore)|^electron\.cert'; tasvs=@('TASVS-NETWORK Network Communication'); da=@('DA7 Insecure Communication') }
    @{ rx='^(pe\.|pe-mitig|pe-imports|pe-exports|authenticode|codeintegrity|strongname|packer|obfusc)'; tasvs=@('TASVS-CODE Code Quality & Build Settings'); da=@('DA6 Security Misconfiguration','DA8 Poor Code Quality') }
    @{ rx='^(antidebug|timing|selfintegrity|antiinjection)';                              tasvs=@('TASVS-RESILIENCE Resilience / Anti-tampering'); da=@('DA8 Poor Code Quality') }
    @{ rx='^(registry|autostart|scheduledtask|wmipersistence|ifeo|apppaths|shimcache|unquoted|service|servicebin|taskbin|acl\.|installdir|folderacls|programdata|kerneldrivers|driver|dllsearch|proxydll|sxs|firewall|avexclusion|uac)'; tasvs=@('TASVS-PLATFORM Platform Interaction'); da=@('DA6 Security Misconfiguration','DA5 Improper Authorization') }
    @{ rx='^(namedpipe|pipe|rpc|mailslot|com\.|comobjects|comhijack|msixcom|namedobjects)'; tasvs=@('TASVS-PLATFORM Platform Interaction / IPC'); da=@('DA6 Security Misconfiguration') }
    @{ rx='^(deps\.cve|pkgmanifest\.cve|cve\.)|outdated-runtime';                          tasvs=@('TASVS-CODE Dependencies'); da=@('DA9 Using Components with Known Vulnerabilities') }
    @{ rx='^(logfiles|log\.|piiinlogs|telemetry|etw)';                                    tasvs=@('TASVS-STORAGE Data Storage & Privacy'); da=@('DA10 Insufficient Logging & Monitoring','DA3 Sensitive Data Exposure') }
    @{ rx='^(updateflow|update|poisonedupdate)';                                          tasvs=@('TASVS-NETWORK Network Communication'); da=@('DA7 Insecure Communication','DA9 Using Components with Known Vulnerabilities') }
    @{ rx='^(wv2|webview)';                                                               tasvs=@('TASVS-PLATFORM Platform Interaction'); da=@('DA1 Injection','DA6 Security Misconfiguration') }
    @{ rx='^(reflectionloading|nativeinterop|pinvoke|unsafenativeapis|zipslip|embeddedscripts|electron|rpcsurface)'; tasvs=@('TASVS-CODE Code Quality'); da=@('DA8 Poor Code Quality') }
    @{ rx='^(chain|protocol\.sink|msix\.alias|msix\.|manifest|uacmanifest)';              tasvs=@('TASVS-ARCH Architecture & Threat Modeling'); da=@('DA6 Security Misconfiguration') }
    @{ rx='^(fs\.|registry\.(diff|snapshot))';                                            tasvs=@('TASVS-PLATFORM Platform Interaction'); da=@('DA6 Security Misconfiguration') }
    @{ rx='^process\.(impactful-privileges|integrity-level|running-as-system|identity|dacl)'; tasvs=@('TASVS-PLATFORM Platform Interaction'); da=@('DA5 Improper Authorization') }
    @{ rx='^intercept\.tamper';                                                           tasvs=@('TASVS-NETWORK Network Communication'); da=@('DA5 Improper Authorization') }
    @{ rx='^intercept\.';                                                                 tasvs=@('TASVS-NETWORK Network Communication'); da=@('DA7 Insecure Communication') }
    @{ rx='^protocol-handler';                                                            tasvs=@('TASVS-PLATFORM Platform Interaction / IPC'); da=@('DA6 Security Misconfiguration') }
    @{ rx='^browser\.';                                                                   tasvs=@('TASVS-STORAGE Sensitive Data Storage'); da=@('DA3 Sensitive Data Exposure') }
    @{ rx='^electron\.ipc-handler-sink';                                                  tasvs=@('TASVS-PLATFORM Platform Interaction / IPC'); da=@('DA1 Injection') }
)

function Get-TcpkTasvsControl {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$RuleId)
    if ([string]::IsNullOrEmpty($RuleId)) { return @() }
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($m in $script:TcpkTasvsMap) {
        if ($RuleId -match $m.rx) {
            foreach ($t in $m.tasvs) { if (-not $out.Contains($t)) { $out.Add($t) } }
            foreach ($t in $m.da)    { if (-not $out.Contains($t)) { $out.Add($t) } }
        }
    }
    return $out.ToArray()
}

# Single display string (TASVS + Desktop Top 10) for a RuleId.
function Get-TcpkTasvsText {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$RuleId)
    (Get-TcpkTasvsControl -RuleId $RuleId) -join '; '
}
