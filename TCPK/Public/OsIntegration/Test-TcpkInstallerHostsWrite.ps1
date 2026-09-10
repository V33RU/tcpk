function Test-TcpkInstallerHostsWrite {
<#
.SYNOPSIS
    C23. Installer scripts and MSI custom actions that write to
    %SystemRoot%\System32\drivers\etc\hosts.

.DESCRIPTION
    Real-world installer-hosts-write patterns:
      * Adding an entry that redirects a license / activation URL to 127.0.0.1
        (Adobe / JetBrains cracks, node-locked seat pirating - but also legitimate
        offline license servers).
      * Redirecting a telemetry / update endpoint to a vendor-controlled proxy.
      * Redirecting a device-discovery hostname to a fixed IP so the app finds a
        gateway that DHCP does not know about (industrial installers).
    In every case the hosts file is a permanent local MITM primitive: any process
    on the box resolving the affected name gets the installer-chosen answer for
    the lifetime of the OS, and if the DNS entry (or the target host) is ever
    compromised the app talks to the attacker instead of the intended endpoint.

    Rules:
      installer.hosts-file-write   HIGH   Confirmed  A shipped script or MSI
                                                     CustomAction writes to the
                                                     hosts file (Add-Content /
                                                     redirection append / MSI
                                                     WriteIniValues / a
                                                     custom-action .vbs / .js /
                                                     .ps1 that touches it).
      installer.hosts-file-read    LOW    Confirmed  A shipped script READS the
                                                     hosts file only. Reader-facing
                                                     scope info; the write rule is
                                                     the real primitive.

    Confidence is Confirmed for what the shipped file literally says. If the
    installer conditionally writes only during a specific SKU install, the
    finding still fires - the file is present in the release.

.PARAMETER Path
    Install directory or a single script / MSI-table file.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()] param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) { return }

    # The hosts file lives at a single well-known path (its location has been fixed
    # since Windows 2000). Match the classical spellings a shipped script would use:
    #   %WINDIR%\System32\drivers\etc\hosts
    #   %SystemRoot%\System32\drivers\etc\hosts
    #   $env:WINDIR\System32\drivers\etc\hosts
    #   C:\Windows\System32\drivers\etc\hosts
    # Also the SysWOW64 hosts twin, which Windows does NOT redirect for text files
    # but is often written by 32-bit installers anyway.
    # Pattern is concatenated into wrapper patterns that always start with (?is), so
    # do NOT put a leading inline flag here; a nested inline flag inside an already-
    # flagged construct is legal in .NET regex but reads badly and behaves poorly with
    # any consumer that only supports pattern-start flags. The wrapper's (?is) already
    # gives case-insensitive matching for the drive letter and 'System32' / 'SysWOW64'.
    $hostsPathRx = '(?:%(?:WINDIR|SystemRoot)%|\$env:(?:WINDIR|SystemRoot)|[A-Z]:\\Windows)(?:\\System32|\\SysWOW64)\\drivers\\etc\\hosts'

    # Extensions shipped by real installers that could contain a hosts-file write.
    $scriptExts = @('.ps1','.psm1','.bat','.cmd','.vbs','.js','.wsf','.wxs','.iss','.nsi','.nsh','.py')

    $files = @()
    $item = Get-Item -LiteralPath $Path
    if ($item.PSIsContainer) {
        try {
            $files = @(Get-ChildItem -LiteralPath $Path -Recurse -File -ErrorAction SilentlyContinue |
                       Where-Object { $scriptExts -contains $_.Extension.ToLowerInvariant() -and $_.Length -lt 1048576 })
        } catch { return }
    } elseif ($scriptExts -contains $item.Extension.ToLowerInvariant()) {
        $files = @($item)
    }
    if ($files.Count -eq 0) { return }

    # Write shapes we detect. Order matters: the first shape that matches wins,
    # so the strongest primitive (an explicit redirection append) is reported before
    # a weaker Add-Content match on the same line.
    #
    # 1. Batch / cmd  :  echo 1.2.3.4 host.example >> %windir%\system32\drivers\etc\hosts
    # 2. PowerShell   :  Add-Content   / Out-File / Set-Content / [IO.File]::AppendAllText
    # 3. VBScript     :  OpenTextFile( ..., 8, ... )    or   FileSystemObject.CopyFile
    # 4. Node/JS      :  fs.appendFileSync / fs.writeFileSync
    # 5. Python       :  open(..., 'a').write / 'w').write
    # 6. WiX          :  <util:HostsFile> / <RemoveHostsElement>  (WiX extensions)
    # 7. NSIS         :  FileWrite / FileWriteUTF16LE on an opened hosts handle
    # 8. Inno Setup   :  [Code] SaveStringToFile
    # 9. Any file     :  a bare 'hosts' path AND an operator suggesting append/write in
    #                    the same 200-char window
    $writeShapes = @(
        @{ Name='cmd-redirect';  Rx='(?is)(echo|type|copy)\b[^\r\n|;]{0,200}?(>>|>)\s*' + $hostsPathRx }
        @{ Name='ps-appendfile'; Rx='(?is)(Add-Content|Out-File|Set-Content|\[IO\.File\]::(AppendAllText|WriteAllText|AppendAllLines|WriteAllLines))\b[^\r\n;]{0,300}?' + $hostsPathRx }
        @{ Name='ps-appendfile'; Rx='(?is)' + $hostsPathRx + '[^\r\n;]{0,300}?(Add-Content|Out-File|Set-Content|\[IO\.File\]::(AppendAllText|WriteAllText|AppendAllLines|WriteAllLines))\b' }
        @{ Name='vbs-openwrite'; Rx='(?is)OpenTextFile\s*\(\s*"' + $hostsPathRx + '"\s*,\s*(2|8)\b' }
        @{ Name='node-append';   Rx='(?is)fs\.(appendFileSync|writeFileSync|createWriteStream)\s*\(\s*["' + "'" + '`][^"' + "'" + '`]{0,400}drivers[\\/]etc[\\/]hosts' }
        @{ Name='python-write';  Rx='(?is)open\s*\(\s*["' + "'" + '][^"' + "'" + ']{0,400}drivers[\\\\/]etc[\\\\/]hosts["' + "'" + ']\s*,\s*["' + "'" + '][aw][^"' + "'" + ']*["' + "'" + ']' }
        @{ Name='wix-hostsfile'; Rx='(?is)<util:(?:HostsFile|RemoveHostsElement)\b' }
        @{ Name='nsis-filewrite';Rx='(?is)FileOpen\b[^\r\n]{0,200}?' + $hostsPathRx + '[^\r\n]{0,200}?FileWrite' }
        @{ Name='inno-savestring';Rx='(?is)SaveStringToFile\s*\(\s*[^\r\n,]{0,200}drivers[\\\\/]etc[\\\\/]hosts[^\r\n)]{0,200}?,\s*[^\r\n)]+,\s*True' }
    )

    $readShapes = @(
        @{ Name='cmd-read';      Rx='(?is)(type|for\s+/f)\b[^\r\n|;]{0,200}?' + $hostsPathRx }
        @{ Name='ps-read';       Rx='(?is)(Get-Content|Select-String|\[IO\.File\]::(ReadAllText|ReadAllLines))\b[^\r\n;]{0,200}?' + $hostsPathRx }
    )

    foreach ($f in $files) {
        $body = $null
        try { $body = [IO.File]::ReadAllText($f.FullName) } catch { continue }
        if (-not $body) { continue }
        # Prefilter: cheap substring test avoids evaluating 9 regexes on every unrelated file.
        if ($body.IndexOf('hosts', [StringComparison]::OrdinalIgnoreCase) -lt 0) { continue }
        if (-not [regex]::IsMatch($body, 'drivers[\\/]etc[\\/]hosts', [Text.RegularExpressions.RegexOptions]::IgnoreCase) -and
            -not [regex]::IsMatch($body, '<util:(HostsFile|RemoveHostsElement)', [Text.RegularExpressions.RegexOptions]::IgnoreCase)) { continue }

        $fired = $false
        foreach ($shape in $writeShapes) {
            $m = [regex]::Match($body, $shape.Rx)
            if (-not $m.Success) { continue }
            $snip = $m.Value
            if ($snip.Length -gt 200) { $snip = $snip.Substring(0, 200) + '...' }
            $snip = ($snip -replace '[\r\n]+',' ').Trim()
            New-TcpkFinding -Module 'os' -RuleId 'installer.hosts-file-write' `
                -Severity 'HIGH' -Confidence 'Confirmed' `
                -Title "$($f.Name) writes to %WINDIR%\System32\drivers\etc\hosts ($($shape.Name))" `
                -File $f.FullName -Evidence $snip `
                -Cwe @('CWE-1188','CWE-346','CWE-441') `
                -Description ('A shipped installer script (or WiX / NSIS / Inno Setup instruction) writes to ' +
                    'the Windows hosts file. This is a permanent local MITM primitive: any process on the ' +
                    'machine resolving the affected name gets the installer-chosen answer for the lifetime ' +
                    'of the OS, and if the DNS entry or the target host is ever compromised, the app talks ' +
                    'to the attacker rather than the intended endpoint. Common motives are offline license ' +
                    'redirection, telemetry proxying, or fixed-IP device discovery, but the effect on trust ' +
                    'is the same regardless of intent.') `
                -Fix 'Do not modify hosts as an installer side-effect. Ship a DNS configuration alternative (a per-app DNS resolver, a config-file endpoint override, or a proper split-DNS deployment). If a local MITM is genuinely required (a fixture, a lab bench, a captive-portal seat), ship it as a runtime opt-in that the user has to enable and remove.'
            $fired = $true
            break
        }
        if ($fired) { continue }

        # Falls through to the read-only rule only if no write matched.
        foreach ($shape in $readShapes) {
            $m = [regex]::Match($body, $shape.Rx)
            if (-not $m.Success) { continue }
            $snip = ($m.Value -replace '[\r\n]+',' ').Trim()
            if ($snip.Length -gt 200) { $snip = $snip.Substring(0, 200) + '...' }
            New-TcpkFinding -Module 'os' -RuleId 'installer.hosts-file-read' `
                -Severity 'LOW' -Confidence 'Confirmed' `
                -Title "$($f.Name) reads the hosts file ($($shape.Name))" `
                -File $f.FullName -Evidence $snip `
                -Cwe @('CWE-200') `
                -Description ('The shipped script reads the hosts file. Not a defect on its own - installers ' +
                    'sometimes read the file to detect a conflicting entry before adding one. Reader-facing ' +
                    'scope info; pair with installer.hosts-file-write for the real primitive.') `
                -Fix 'No fix required for the read itself. If the installer proceeds to write, see the write rule.'
            break
        }
    }
}
