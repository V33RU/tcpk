# Security-category + risk-class mapping for TCPK rule IDs. Pure lookup, computed at report
# time from a finding's RuleId (same model as the MITRE ATT&CK map in _Attack.ps1) -- the
# [TcpkFinding] class is unchanged. First/any matching prefix contributes; unioned.
# NB: the 'da' values still carry Desktop-App-Top-10 codes (DA1..DA10); de-branding those
# (a second standard) is tracked separately.

# Ordered list: RuleId regex -> { area = security category, da = risk-class item }.
$script:TcpkCategoryMap = @(
    @{ rx='^(callsites|deser|xxe)';                                                       area=@('Code Quality'); da=@('DA1 Injection','DA8 Poor Code Quality') }
    @{ rx='^csv\.';                                                                       area=@('Code Quality'); da=@('DA1 Injection') }
    @{ rx='^session\.';                                                                   area=@('Authentication & Session'); da=@('DA2 Broken Authentication','DA5 Improper Authorization') }
    @{ rx='^(jwt|authflags)';                                                             area=@('Authentication & Session'); da=@('DA2 Broken Authentication') }
    @{ rx='^(secrets|entropy|app-?config|plaintext|keymaterial|dpapi|tokencaches|webviewcreds|localdb|credentialmanager|memorysecrets|processenvsecrets)'; area=@('Sensitive Data Storage'); da=@('DA3 Sensitive Data Exposure') }
    @{ rx='registry.*(secret|value)';                                                     area=@('Sensitive Data Storage'); da=@('DA3 Sensitive Data Exposure') }
    @{ rx='^crypto\.|weak-symmetric|weak-hash|aes-ecb|weak-rng|base64-as-encryption';     area=@('Cryptography'); da=@('DA4 Improper Cryptography Usage') }
    @{ rx='^(tls-bypass|tlspinning|tlsprotocols|tls\.|insecureschemes|scheme|crlocsp|backend|endpoints|dnsleakage|selfhost|truststore)|^electron\.cert'; area=@('Network Communication'); da=@('DA7 Insecure Communication') }
    @{ rx='^(pe\.|pe-mitig|pe-imports|pe-exports|authenticode|codeintegrity|strongname|packer|obfusc)'; area=@('Code Quality & Build Settings'); da=@('DA6 Security Misconfiguration','DA8 Poor Code Quality') }
    @{ rx='^(antidebug|timing|selfintegrity|antiinjection)';                              area=@('Resilience / Anti-tampering'); da=@('DA8 Poor Code Quality') }
    @{ rx='^(registry|autostart|scheduledtask|wmipersistence|ifeo|apppaths|shimcache|unquoted|service|servicebin|taskbin|acl\.|install-?dir|folderacls|programdata|kerneldrivers|driver|dllsearch|proxydll|sxs|firewall|avexclusion|uac)'; area=@('Platform Interaction'); da=@('DA6 Security Misconfiguration','DA5 Improper Authorization') }
    @{ rx='^(namedpipe|pipe|rpc|mailslot|com\.|comobjects|comhijack|msixcom|namedobjects|window)'; area=@('Platform Interaction / IPC'); da=@('DA6 Security Misconfiguration') }
    @{ rx='^sharedmem';                                                                    area=@('Platform Interaction / IPC'); da=@('DA5 Improper Authorization') }
    @{ rx='^clipboard';                                                                    area=@('Sensitive Data Storage'); da=@('DA3 Sensitive Data Exposure') }
    @{ rx='^exploit\.(ifeo-hijack|runkey-persist|appinit-inject)';                                      area=@('Platform Interaction'); da=@('DA6 Security Misconfiguration') }
    @{ rx='^(deps\.cve|pkgmanifest\.cve|cve\.)|outdated-runtime';                          area=@('Dependencies'); da=@('DA9 Using Components with Known Vulnerabilities') }
    @{ rx='^(logfiles|log\.|piiinlogs|telemetry|etw)';                                    area=@('Data Storage & Privacy'); da=@('DA10 Insufficient Logging & Monitoring','DA3 Sensitive Data Exposure') }
    @{ rx='^(updateflow|update|poisonedupdate)';                                          area=@('Network Communication'); da=@('DA7 Insecure Communication','DA9 Using Components with Known Vulnerabilities') }
    @{ rx='^(wv2|webview)';                                                               area=@('Platform Interaction'); da=@('DA1 Injection','DA6 Security Misconfiguration') }
    @{ rx='^(reflectionloading|nativeinterop|pinvoke|unsafenativeapis|zipslip|embeddedscripts|electron|rpcsurface)'; area=@('Code Quality'); da=@('DA8 Poor Code Quality') }
    @{ rx='^(chain|protocol\.sink|msix\.alias|msix\.|manifest|uacmanifest)';              area=@('Architecture & Threat Modeling'); da=@('DA6 Security Misconfiguration') }
    @{ rx='^(fs\.|registry\.(diff|snapshot))';                                            area=@('Platform Interaction'); da=@('DA6 Security Misconfiguration') }
    @{ rx='^process\.(impactful-privileges|integrity-level|running-as-system|identity|dacl)'; area=@('Platform Interaction'); da=@('DA5 Improper Authorization') }
    @{ rx='^intercept\.tamper';                                                           area=@('Network Communication'); da=@('DA5 Improper Authorization') }
    @{ rx='^intercept\.';                                                                 area=@('Network Communication'); da=@('DA7 Insecure Communication') }
    @{ rx='^protocol-handler';                                                            area=@('Platform Interaction / IPC'); da=@('DA6 Security Misconfiguration') }
    @{ rx='^browser\.';                                                                   area=@('Sensitive Data Storage'); da=@('DA3 Sensitive Data Exposure') }
    @{ rx='^electron\.ipc-handler-sink';                                                  area=@('Platform Interaction / IPC'); da=@('DA1 Injection') }
    @{ rx='^appdomain\.';                                                                  area=@('Platform Interaction'); da=@('DA5 Improper Authorization') }
    @{ rx='^electron\.(wdac-bypass)';                                                      area=@('Code Quality & Build Settings'); da=@('DA6 Security Misconfiguration') }
    @{ rx='^electron\.(squirrel-updater|updater-sig-bypass|update-http)';                  area=@('Network Communication'); da=@('DA7 Insecure Communication','DA9 Using Components with Known Vulnerabilities') }
    @{ rx='^clickonce\.';                                                                  area=@('Network Communication'); da=@('DA7 Insecure Communication','DA9 Using Components with Known Vulnerabilities') }
    @{ rx='^msix\.psf';                                                                    area=@('Platform Interaction'); da=@('DA6 Security Misconfiguration') }
    @{ rx='^dllsearch\.(phantom|delayload-phantom|sideload)';                               area=@('Platform Interaction'); da=@('DA5 Improper Authorization') }
    @{ rx='^comhijack\.';                                                                   area=@('Platform Interaction'); da=@('DA5 Improper Authorization') }
    @{ rx='^wer\.';                                                                         area=@('Sensitive Data Storage'); da=@('DA3 Sensitive Data Exposure') }
    @{ rx='^crashreporter\.';                                                               area=@('Sensitive Data Storage'); da=@('DA3 Sensitive Data Exposure') }
    @{ rx='^dotnethost\.';                                                                  area=@('Platform Interaction'); da=@('DA5 Improper Authorization','DA6 Security Misconfiguration') }
    @{ rx='^scan\.';                                                                        area=@('Platform Interaction'); da=@('DA6 Security Misconfiguration') }
    @{ rx='^electron\.v8-bytecode';                                                         area=@('Code Quality and Build Settings'); da=@('DA6 Security Misconfiguration') }
    @{ rx='^memregion\.';                                                                   area=@('Platform Interaction'); da=@('DA6 Security Misconfiguration') }
    @{ rx='^(thread|token|virtualization)\.';                                               area=@('Platform Interaction'); da=@('DA5 Improper Authorization','DA6 Security Misconfiguration') }
    @{ rx='^handle\.';                                                                      area=@('Platform Interaction'); da=@('DA6 Security Misconfiguration') }
    @{ rx='^path\.writable';                                                                area=@('Platform Interaction'); da=@('DA5 Improper Authorization') }
    # servicedll.* is already reached by the '|service|' alternation on the platform line
    # above; appinit/appcert/loadpoint/jni are not, so they are named explicitly.
    @{ rx='^(appinit|appcert|loadpoint)\.';                                                 area=@('Platform Interaction'); da=@('DA5 Improper Authorization','DA6 Security Misconfiguration') }
    @{ rx='^installer\.';                                                                   area=@('Platform Interaction'); da=@('DA5 Improper Authorization','DA6 Security Misconfiguration') }
    @{ rx='^strings\.';                                                                     area=@('Code Quality & Build Settings'); da=@('DA6 Security Misconfiguration') }
    @{ rx='^loaded\.';                                                                      area=@('Platform Interaction'); da=@('DA5 Improper Authorization') }
    @{ rx='^gui\.';                                                                         area=@('Authentication & Session'); da=@('DA5 Improper Authorization') }
    @{ rx='^jni\.';                                                                         area=@('Platform Interaction'); da=@('DA5 Improper Authorization','DA8 Poor Code Quality') }
    @{ rx='^diag\.';                                                                        area=@('Code Quality & Build Settings'); da=@('DA3 Sensitive Data Exposure') }
    @{ rx='^grpc\.';                                                                        area=@('Network Communication'); da=@('DA6 Security Misconfiguration') }
    @{ rx='^wv2\.(sideload|fixed-version)';                                                 area=@('Platform Interaction'); da=@('DA5 Improper Authorization') }

    # --- active session / authorization probes (K19, K22, K23) ----------------------
    # Matched by EXACT rule id, not by prefix, and this is deliberate. Each of these three
    # cmdlets emits far more procedural rule ids than finding ones: refusals
    # (*.unsafe-method-refused, *.credential-mismatch), inconclusive results
    # (*.transport-error, expiry.not-yet-lapsed) and records of a control WORKING
    # (expiry.enforced, logout.revoked, authmatrix.matrix). A prefix like '^logout\.' would
    # tag all of them, which would put 'logout revoked the session correctly' into a
    # Broken Authentication bucket and inflate any compliance matrix built off this map.
    # Only rules that can actually emit LOW or higher appear below.
    @{ rx='^authmatrix\.vertical-escalation$';                                              area=@('Authentication & Session'); da=@('DA5 Improper Authorization') }
    @{ rx='^(authmatrix|expiry|logout)\.(no-auth-accepted|endpoint-open)$';                 area=@('Authentication & Session'); da=@('DA2 Broken Authentication') }
    @{ rx='^expiry\.expired-token-accepted$';                                               area=@('Authentication & Session'); da=@('DA2 Broken Authentication') }
    @{ rx='^logout\.(session-not-invalidated|token-never-dies|credential-survives)$';       area=@('Authentication & Session'); da=@('DA2 Broken Authentication') }
    @{ rx='^amsi\.';                                                                        area=@('Resiliency Against Reverse Engineering'); da=@('DA8 Poor Code Quality') }
    @{ rx='^injection\.';                                                                   area=@('Code Quality & Build Settings'); da=@('DA8 Poor Code Quality') }
    @{ rx='^sqli\.';                                                                        area=@('Code Quality'); da=@('DA1 Injection') }
    @{ rx='^creds\.';                                                                       area=@('Sensitive Data Storage'); da=@('DA3 Sensitive Data Exposure') }
    @{ rx='^devartifact\.';                                                                 area=@('Code Quality & Build Settings'); da=@('DA6 Security Misconfiguration') }
)

function Get-TcpkCategoryList {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$RuleId)
    if ([string]::IsNullOrEmpty($RuleId)) { return @() }
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($m in $script:TcpkCategoryMap) {
        if ($RuleId -match $m.rx) {
            foreach ($t in $m.area) { if (-not $out.Contains($t)) { $out.Add($t) } }
            foreach ($t in $m.da)    { if (-not $out.Contains($t)) { $out.Add($t) } }
        }
    }
    return $out.ToArray()
}

# Single display string (category + risk class) for a RuleId.
function Get-TcpkCategoryText {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$RuleId)
    (Get-TcpkCategoryList -RuleId $RuleId) -join '; '
}
