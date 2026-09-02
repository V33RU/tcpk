function Test-TcpkHostNameResolution {
<#
.SYNOPSIS
    C21. Host-side name-resolution posture (LLMNR / NBT-NS / mDNS) and shipped-config
    bare-hostname exposure.

.DESCRIPTION
    LLMNR (Link-Local Multicast Name Resolution) and NBT-NS (NetBIOS Name Service) are
    Windows fallback name-resolution protocols that resolve unqualified names by
    broadcasting on the local segment. Any LAN attacker running Responder / Inveigh
    answers the broadcast, becomes the "server", and captures Net-NTLMv2 handshakes
    from every subsequent authentication attempt. If a shipped thick-client config
    names a backend with a BARE HOSTNAME (`db-server`, `app-01`, `licensing`), the
    Windows DNS client fails, falls through to LLMNR / NBT-NS, and the client speaks
    to the attacker's box (which can then MITM, downgrade auth, or capture creds).

    The default TCPK Test-TcpkDeviceComm.devcomm.llmnr-netbios rule flags whether the
    APP BINARY references LLMNR APIs. This complements it with the HOST-SIDE state
    (registry policy) and the SHIPPED-CONFIG bare-hostname surface:

    Rules:
      host.llmnr-enabled            MEDIUM  Confirmed  Registry: LLMNR not disabled
                                                        (HKLM\...\DNSClient\EnableMulticast
                                                        != 0). Reader-facing scoping only,
                                                        every default Windows box.
      host.nbtns-enabled            MEDIUM  Confirmed  Registry: at least one interface
                                                        under NetBT\Parameters\Interfaces
                                                        has NetbiosOptions != 2 (2 =
                                                        disabled), so NBT-NS is live.
      host.mdns-enabled             LOW     Confirmed  Registry: DNS Client mDNS
                                                        (EnableMDNS != 0). Included for
                                                        completeness on Win10 2004+.
      cfg.bare-hostname-endpoint    MEDIUM  Confirmed  A shipped config declares a
                                                        backend by BARE hostname (no
                                                        dot, no port suffix that is a
                                                        loopback range). Combined with
                                                        the two above this is the
                                                        Responder-catches primitive.

    Registry rules are OS-scoped, not target-scoped, so they read the local host state
    once. The config-side rule is per-file and requires a shipped install directory.

.PARAMETER Path
    Optional. Install directory or single config file. Only the cfg.bare-hostname-endpoint
    rule needs this; the three host.* rules run against the local machine regardless.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([string]$Path)

    if (-not (Assert-TcpkWindows 'Test-TcpkHostNameResolution')) { return }

    # ---- host.llmnr-enabled ---------------------------------------------------------
    # HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\EnableMulticast=0 disables
    # LLMNR. Any other state (including the key being absent) leaves it on. A registry
    # read failure is NOT reported as "not disabled" (that would fabricate a Confirmed
    # finding on an ACL-restricted host where TCPK has zero visibility); instead a
    # Hypothesis INFO record surfaces the unreadable state.
    $llmnrState = 'unknown'   # 'disabled' | 'enabled' | 'unknown'
    $llmnrEvidence = ''
    try {
        $regPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
        if (Test-Path -LiteralPath $regPath) {
            $val = (Get-ItemProperty -LiteralPath $regPath -Name 'EnableMulticast' -ErrorAction Stop).EnableMulticast
            if ($null -ne $val -and [int]$val -eq 0) {
                $llmnrState = 'disabled'; $llmnrEvidence = 'DNSClient policy EnableMulticast=0 (LLMNR disabled)'
            } else {
                $llmnrState = 'enabled';  $llmnrEvidence = "DNSClient policy present, EnableMulticast=$val (LLMNR not disabled)"
            }
        } else {
            $llmnrState = 'enabled'; $llmnrEvidence = 'DNSClient policy key absent (LLMNR default ON)'
        }
    } catch { $llmnrState = 'unknown'; $llmnrEvidence = "registry read failed: $($_.Exception.Message)" }
    if ($llmnrState -eq 'enabled') {
        New-TcpkFinding -Module 'os' -RuleId 'host.llmnr-enabled' `
            -Severity 'MEDIUM' -Confidence 'Confirmed' `
            -Title 'LLMNR is enabled on this host' `
            -File 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Evidence $llmnrEvidence `
            -Cwe @('CWE-290','CWE-522') `
            -Description ('LLMNR (Link-Local Multicast Name Resolution) resolves unqualified names by ' +
                'multicasting to the local segment. A LAN attacker running Responder / Inveigh answers ' +
                'the broadcast and captures every Net-NTLMv2 handshake that follows. Windows leaves this ' +
                'on by default; the group policy that turns it off (`EnableMulticast=0`) is absent on ' +
                'most non-managed hosts.') `
            -Fix 'Set HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\EnableMulticast=0 (DWORD). Or via GPO: Computer Configuration -> Administrative Templates -> Network -> DNS Client -> Turn off multicast name resolution -> Enabled.'
    } elseif ($llmnrState -eq 'unknown') {
        New-TcpkFinding -Module 'os' -RuleId 'host.llmnr-unreadable' `
            -Severity 'INFO' -Confidence 'Skipped' `
            -Title 'LLMNR posture unreadable' `
            -File 'HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' -Evidence $llmnrEvidence `
            -Description 'The scanner could not read the DNSClient policy registry key, so the LLMNR posture on this host is unassessed rather than enabled or disabled.'
    }

    # ---- host.nbtns-enabled ---------------------------------------------------------
    # HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_{guid}
    # NetbiosOptions:  0=default (interface-dependent), 1=enabled, 2=disabled.
    # If ANY interface is not 2, NBT-NS can be poisoned.
    $nbtEnabledIfaces = @()
    try {
        $ifRoot = 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces'
        if (Test-Path -LiteralPath $ifRoot) {
            foreach ($k in (Get-ChildItem -LiteralPath $ifRoot -ErrorAction SilentlyContinue)) {
                $opt = $null
                try { $opt = (Get-ItemProperty -LiteralPath $k.PSPath -Name 'NetbiosOptions' -ErrorAction SilentlyContinue).NetbiosOptions } catch { }
                if ($null -ne $opt -and [int]$opt -ne 2) {
                    $nbtEnabledIfaces += "$($k.PSChildName)=NetbiosOptions=$opt"
                }
            }
        }
    } catch { }
    if ($nbtEnabledIfaces.Count -gt 0) {
        New-TcpkFinding -Module 'os' -RuleId 'host.nbtns-enabled' `
            -Severity 'MEDIUM' -Confidence 'Confirmed' `
            -Title "NBT-NS is enabled on $($nbtEnabledIfaces.Count) interface(s)" `
            -File 'HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces' `
            -Evidence (($nbtEnabledIfaces | Select-Object -First 5) -join '; ') `
            -Cwe @('CWE-290','CWE-522') `
            -Description ('At least one network interface has NetBT (NetBIOS over TCP/IP) name service ' +
                'not disabled. Same primitive as LLMNR: any name-resolution fallback on the local segment ' +
                'gives an attacker a chance to become the responder and capture Net-NTLMv2. NetbiosOptions=2 ' +
                'per-interface disables it.') `
            -Fix 'For every listed interface set NetbiosOptions=2, or centrally via a DHCP scope-option 001/002 that instructs clients to disable NetBIOS over TCP/IP.'
    }

    # ---- host.mdns-enabled ---------------------------------------------------------
    # HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\EnableMDNS=0 disables the
    # Windows built-in mDNS resolver, which was introduced in Windows 10 build 19041 (2004).
    # On earlier releases (1809, 1909, LTSC 2019, Server 2019) the value does not exist AND
    # there is no built-in resolver to disable - firing this rule there is a false positive.
    # Skip entirely when the build is below 19041.
    $winBuild = 0
    try { $winBuild = [Environment]::OSVersion.Version.Build } catch { }
    if ($winBuild -ge 19041) {
        $mdnsState = 'unknown'; $mdnsEvidence = ''
        try {
            $dc = 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters'
            if (Test-Path -LiteralPath $dc) {
                $val = (Get-ItemProperty -LiteralPath $dc -Name 'EnableMDNS' -ErrorAction Stop).EnableMDNS
                if ($null -ne $val -and [int]$val -eq 0) {
                    $mdnsState = 'disabled'; $mdnsEvidence = 'Dnscache EnableMDNS=0 (mDNS disabled)'
                } else {
                    $mdnsState = 'enabled';  $mdnsEvidence = "Dnscache EnableMDNS=$val (mDNS not disabled)"
                }
            } else {
                $mdnsState = 'enabled'; $mdnsEvidence = "Dnscache\Parameters key absent (mDNS default ON on Win build $winBuild)"
            }
        } catch { $mdnsState = 'unknown'; $mdnsEvidence = "registry read failed: $($_.Exception.Message)" }
        if ($mdnsState -eq 'enabled') {
            New-TcpkFinding -Module 'os' -RuleId 'host.mdns-enabled' `
                -Severity 'LOW' -Confidence 'Confirmed' `
                -Title 'Windows built-in mDNS resolver is enabled' `
                -File 'HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' -Evidence $mdnsEvidence `
                -Cwe @('CWE-290') `
                -Description ('The Windows built-in mDNS resolver (Win10 2004 / build 19041 and later) accepts ' +
                    'multicast responses for .local names. Lower severity than LLMNR because most enterprise ' +
                    'back-ends do not use .local, but IoT device discovery does; a hostile responder can ' +
                    'intercept a companion apps device-lookup broadcast.') `
                -Fix 'Set HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\EnableMDNS=0 (DWORD) unless the app relies on Windows mDNS. Third-party mDNS (Bonjour, Avahi) is not affected by this switch.'
        }
        # unknown -> silent; a companion INFO record would be noisy across two host.* rules.
    }

    # ---- cfg.bare-hostname-endpoint (per-file, only when -Path was passed) ----------
    if (-not $Path) { return }
    if (-not (Test-Path -LiteralPath $Path)) { return }

    $item = Get-Item -LiteralPath $Path
    $files = @()
    $configExts = @('.json','.xml','.config','.ini','.yaml','.yml','.env','.toml','.cfg','.conf','.properties')
    if ($item.PSIsContainer) {
        try {
            $files = @(Get-ChildItem -LiteralPath $Path -Recurse -File -ErrorAction SilentlyContinue |
                       Where-Object { $configExts -contains $_.Extension.ToLowerInvariant() -and $_.Length -lt 1048576 })
        } catch { return }
    } elseif ($configExts -contains $item.Extension.ToLowerInvariant()) {
        $files = @($item)
    }
    if ($files.Count -eq 0) { return }

    # An endpoint token in a shipped config that a Windows resolver would fall through
    # DNS -> LLMNR / NBT-NS on:
    #   - bare hostname (1-15 chars, letters/digits/hyphen, no dot, no colon-port),
    #   - inside a URL scheme (http://, https://, ldap://, ftp://, tcp://, redis://,
    #     amqp://, mongodb://, mssql://, postgres://, mysql://, mqtt://), OR inside
    #     an "endpoint"-shaped key value ("Host": "db01").
    # Skip localhost, IPs, FQDNs (contain dot), and RFC1918 aliases we cannot resolve.
    $skipHosts = @('localhost','local','loopback','127.0.0.1','::1','0.0.0.0','host','server','example','test','me','you','user','admin')
    # Two match shapes: URI form (scheme://name) and key-value form ("Host": "name").
    # NB the URI form CONSUMES an optional userinfo ('user:pass@') between '://' and the
    # host segment so a credentialed URL like 'postgres://sa:pw@db01/mydb' still reports
    # 'db01' as the host, not 'sa'.
    $rxUri = '(?i)\b(https?|ldap|ldaps|ftp|ftps|sftp|tcp|udp|redis|amqp|amqps|mongodb|mssql|jdbc:sqlserver|postgres|postgresql|mysql|mqtt|mqtts|wss?)://(?:[^/@\s:]+(?::[^/@\s]*)?@)?([A-Za-z0-9-]{1,63})(?![A-Za-z0-9._-])'
    $rxKv  = '(?im)^\s*"?(host|hostname|server|endpoint|address|target|broker|db_host|database_host|api_host)"?\s*[:=]\s*"?([A-Za-z0-9-]{1,63})"?\s*(?:[,;}#\r\n]|$)'

    foreach ($f in $files) {
        $body = $null
        try { $body = [IO.File]::ReadAllText($f.FullName) } catch { continue }
        if (-not $body) { continue }
        $seen = New-Object 'System.Collections.Generic.HashSet[string]'

        foreach ($rx in @($rxUri, $rxKv)) {
            foreach ($m in [regex]::Matches($body, $rx)) {
                # NB: local is $name, not $host - $host is a PowerShell automatic variable
                # (the runspace host), and reassigning it inside a function shadows the
                # built-in for anything downstream that touches $host.UI.
                $name = $m.Groups[2].Value
                if (-not $name) { continue }
                $nameLc = $name.ToLowerInvariant()
                if ($skipHosts -contains $nameLc) { continue }
                if ($name -match '^\d+$') { continue }           # numeric literal, not a hostname
                if ($name -match '\.') { continue }              # FQDN, DNS resolves normally
                if ($seen.Contains($nameLc)) { continue }
                [void]$seen.Add($nameLc)

                # Evidence records surrounding context (up to 40 chars either side) so a KV
                # match reported inside a larger connectionString / YAML block isn't
                # attributed to the raw token but to its real containing statement.
                $ctxStart = [Math]::Max(0, $m.Index - 40)
                $ctxEnd   = [Math]::Min($body.Length, $m.Index + $m.Length + 40)
                $ctx = $body.Substring($ctxStart, $ctxEnd - $ctxStart).Replace("`r"," ").Replace("`n"," ").Trim()
                $where = if ($rx -eq $rxUri) {
                    "URI '$($m.Value)' near: ...$ctx..."
                } else {
                    "$($m.Groups[1].Value)='$name' near: ...$ctx..."
                }
                New-TcpkFinding -Module 'os' -RuleId 'cfg.bare-hostname-endpoint' `
                    -Severity 'MEDIUM' -Confidence 'Confirmed' `
                    -Title "$($f.Name) declares a backend by bare hostname: $name" `
                    -File $f.FullName -Evidence $where `
                    -Cwe @('CWE-290','CWE-522') `
                    -Description ("The shipped config names a backend by BARE hostname ('$name', no dot, no " +
                        'FQDN). If DNS does not resolve this name (deliberate config-per-site pattern), ' +
                        'Windows falls through to LLMNR / NBT-NS on the local segment. Any LAN attacker who ' +
                        'answers the broadcast becomes the "server" for this endpoint, captures the ' +
                        'authentication handshake, and can then downgrade / relay. Combined with the host.* ' +
                        'rules above, this is the classical thick-client-on-hostile-Wi-Fi LPE / credential ' +
                        'theft chain.') `
                    -Fix 'Use a fully-qualified backend name pinned in DNS, or an IP + certificate pin. If a per-site short-name pattern is intentional, disable LLMNR / NBT-NS on the target hosts (see host.llmnr-enabled / host.nbtns-enabled fixes).'
            }
        }
    }
}
