# MITRE ATT&CK technique mapping for TCPK rule IDs.
# Pure lookup -- computed at report time from a finding's RuleId (like CVSS band),
# so the [TcpkFinding] class is unchanged. First matching prefix wins extra
# techniques; multiple entries can match and are unioned.

# Ordered list: each entry maps a RuleId regex to one or more "Tid Name" strings.
$script:TcpkAttackMap = @(
    @{ rx = '^(dllsearch|pe-imports|proxydll|sxs|apppaths|ifeo|shimcache)';            tech = @('T1574 Hijack Execution Flow') }
    @{ rx = '^(unquoted|servicepermissions|servicebin|taskbin)';                        tech = @('T1543.003 Windows Service','T1574.009 Unquoted Path') }
    @{ rx = '^(autostart|run-key)';                                                     tech = @('T1547.001 Registry Run Keys') }
    @{ rx = '^scheduledtask|autostart.scheduled';                                       tech = @('T1053.005 Scheduled Task') }
    @{ rx = '^wmipersistence';                                                          tech = @('T1546.003 WMI Event Subscription') }
    @{ rx = '^(secrets|entropy|appconfigsecrets|plaintext|keymaterial)';                tech = @('T1552.001 Credentials In Files') }
    @{ rx = '^crypto\.';                                                                tech = @('T1552.001 Credentials In Files','T1600 Weaken Encryption') }
    @{ rx = '^jwt\.';                                                                   tech = @('T1552.001 Credentials In Files','T1528 Steal Application Access Token') }
    @{ rx = '^(dpapiblobs|tokencaches|webviewcreds|localdb)';                           tech = @('T1555 Credentials from Password Stores') }
    @{ rx = '^credentialmanager';                                                       tech = @('T1555.004 Windows Credential Manager') }
    @{ rx = '^(registryvalues|registry).*(secret|value)';                              tech = @('T1552.002 Credentials in Registry') }
    @{ rx = '^truststore';                                                              tech = @('T1553.004 Install Root Certificate') }
    @{ rx = '^avexclusion';                                                             tech = @('T1562.001 Disable or Modify Tools') }
    @{ rx = '^debugflags';                                                              tech = @('T1562 Impair Defenses','T1211 Exploitation for Defense Evasion') }
    @{ rx = '^firewall';                                                                tech = @('T1562.004 Disable or Modify System Firewall') }
    @{ rx = '^process\.dacl|antiinjection';                                             tech = @('T1055 Process Injection') }
    @{ rx = '^(packer|obfusc)';                                                         tech = @('T1027.002 Software Packing') }
    @{ rx = '^(antidebug|timing|selfintegrity)';                                        tech = @('T1622 Debugger Evasion','T1497 Virtualization/Sandbox Evasion') }
    @{ rx = '^(tlsbypass|tlspinning|tlsprotocols|insecureschemes|crlocsp|selfhost)';    tech = @('T1557 Adversary-in-the-Middle','T1040 Network Sniffing') }
    @{ rx = '^uac';                                                                     tech = @('T1548.002 Bypass User Account Control') }
    @{ rx = '^callsites';                                                               tech = @('T1059 Command and Scripting Interpreter') }
    @{ rx = '^(updateflow|poisonedupdate|cve\.)';                                       tech = @('T1195.002 Compromise Software Supply Chain') }
    @{ rx = 'outdated-runtime';                                                         tech = @('T1203 Exploitation for Client Execution') }
    @{ rx = '^kerneldrivers';                                                           tech = @('T1068 Exploitation for Privilege Escalation') }
    @{ rx = '^(comobjects|comhijack|msixcom)';                                          tech = @('T1559.001 Component Object Model','T1546.015 COM Hijacking') }
    @{ rx = '^(namedpipe|rpcsurface|mailslot|namedobjects)';                            tech = @('T1559 Inter-Process Communication') }
    @{ rx = '^(authenticode|strongname|codeintegrity)';                                tech = @('T1553.002 Code Signing') }
    @{ rx = '^authflags';                                                               tech = @('T1078 Valid Accounts','T1211 Exploitation for Defense Evasion') }
    @{ rx = '^(wv2|webview)';                                                           tech = @('T1185 Browser Session Hijacking') }
    @{ rx = '^(piiinlogs|logfiles|telemetry|etw)';                                      tech = @('T1005 Data from Local System') }
    @{ rx = '^(deserial|xxe)';                                                          tech = @('T1059 Command and Scripting Interpreter') }
    @{ rx = '^csv\.';                                                                   tech = @('T1059 Command and Scripting Interpreter','T1048 Exfiltration Over Alternative Protocol') }
)

function Get-TcpkAttackTechnique {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$RuleId)
    if ([string]::IsNullOrEmpty($RuleId)) { return @() }
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($m in $script:TcpkAttackMap) {
        if ($RuleId -match $m.rx) {
            foreach ($t in $m.tech) { if (-not $out.Contains($t)) { $out.Add($t) } }
        }
    }
    return $out.ToArray()
}

# Convenience: techniques as a single display string.
function Get-TcpkAttackText {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$RuleId)
    (Get-TcpkAttackTechnique -RuleId $RuleId) -join '; '
}

# --- OWASP Desktop Application Top 10 (2021) mapping -----------------------------
# Pure lookup, computed at report time from a finding's RuleId (same convention as
# ATT&CK / TASVS / CVSS), so the [TcpkFinding] class is unchanged. Returns the single
# best-fit (primary) DA category; FIRST matching entry wins, so order = most-specific
# first. Returns '' when no family matches.
$script:TcpkOwaspDaMap = @(
    @{ rx = 'session-override|argv-session';                                                                          da = 'DA2 Broken Authentication and Session Management' }
    @{ rx = '^(cve|deps|dependencycves|sbom|pkgmanifest|osv)\.|outdated-runtime';                                     da = 'DA9 Using Components with Known Vulnerabilities' }
    @{ rx = '^(tls|tlsbypass|tlspinning|tlsprotocols|scheme|insecureschemes|backend|crlocsp|dns|truststore)|cleartext|update\.url'; da = 'DA7 Insecure Communication' }
    @{ rx = '^crypto\.|weak-symmetric-crypto|^pem|weak-crypto';                                                       da = 'DA4 Improper Cryptography Usage' }
    @{ rx = '^(authflags|jwt|session|login)|auth-bypass';                                                             da = 'DA2 Broken Authentication and Session Management' }
    @{ rx = '^(deser|xxe|csv)\.|callsites\.(command-execution|ldap-query|ssrf|format-string|sql|xpath)|injection';    da = 'DA1 Injections' }
    @{ rx = '^(secrets|entropy|appconfigsecrets|dpapiblobs|tokencaches|webviewcreds|processenvsecrets|piiinlogs|memsecret|pii)|^browser\.|^strings\.|devartifact|internal-docs|mem\.hygiene|^pagefile|^memory|wer\.'; da = 'DA3 Sensitive Data Exposure' }
    @{ rx = '^(authenticode|strongname|codeintegrity|pe-|pe\.|peimports|peexports|native|antidebug|antiinjection|timing|selfintegrity|packer|obfusc|debugflags|procmit|integrity)|loaded\.(unsigned|non-system)|signing'; da = 'DA8 Poor Code Quality' }
    @{ rx = '^(installdir|folderacl|registry|servicepermissions|servicebin|unquoted|processtoken|process\.dacl|uac|programdata|scheduledtaskacl|kerneldrivers)';            da = 'DA5 Improper Authorization' }
    @{ rx = '^(firewall|namedpipe|named-object|com|comobjects|electron|avexclusion|autostart|scheduledtask|wmi|protocolhandlers|shimcache|apppaths|ifeo|selfhost|ports|sxs|rpcsurface|mailslot|wv2|webview|window)'; da = 'DA6 Security Misconfiguration' }
    @{ rx = '^(log|logfiles|etw)|telemetry';                                                                          da = 'DA10 Insufficient Logging and Monitoring' }
)

# Single primary OWASP Desktop Top 10 category for a RuleId (e.g. 'DA7 Insecure Communication').
function Get-TcpkOwaspDa {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$RuleId)
    if ([string]::IsNullOrEmpty($RuleId)) { return '' }
    foreach ($m in $script:TcpkOwaspDaMap) {
        if ($RuleId -match $m.rx) { return $m.da }
    }
    return ''
}
