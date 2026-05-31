function Get-TcpkReconStrings {
<#
.SYNOPSIS
    R11. Extract + categorize interesting literal strings from first-party binaries.

.DESCRIPTION
    A recon aid for the GUI's Recon tab (NOT the HTML report). Reads the string
    literals out of the app's OWN binaries (framework + bundled-native libraries
    are skipped for speed and signal) and buckets them into categories a
    researcher scans first:

        Urls          http/https/ws/wss/ftp/file URLs
        FilePaths     drive paths, %ENV% paths, UNC paths
        RegistryKeys  HKLM/HKCU/HKCR/HKEY_ paths
        IpAddresses   IPv4 literals (version-number noise filtered)
        Emails        e-mail addresses
        Commands      references to cmd/powershell/rundll32/schtasks/certutil/...
        Interesting   lines mentioning password/secret/token/apikey/connstring/...

    Each list is de-duplicated (case-insensitive) and capped.

.PARAMETER Path
    File or directory.

.PARAMETER Cap
    Max items per category (default 120).

.OUTPUTS
    [pscustomobject] with one array per category (not [TcpkFinding]).
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [int]$Cap = 120
    )

    $urlRx   = [regex]'(?i)\b(?:https?|wss?|ftps?|file)://[A-Za-z0-9._~:/?#@!$&''()*+,;=%\-\[\]]{3,300}'
    $driveRx = [regex]'(?i)\b[a-z]:\\[^\s"''<>|?*\r\n]{2,180}'
    $envRx   = [regex]'%[A-Za-z0-9_()]{2,40}%\\[^\s"''<>|?*\r\n]{2,180}'
    $uncRx   = [regex]'\\\\[A-Za-z0-9._\-]{2,60}\\[^\s"''<>|?*\r\n]{2,180}'
    $regRx   = [regex]'(?i)\b(?:HKEY_[A-Z_]+|HKLM|HKCU|HKCR|HKU|HKCC)\\[A-Za-z0-9_\\ .\-]{3,200}'
    # IPv4 with optional :port. We keep only private/loopback/link-local IPs or
    # ip:port literals -- bare public quads in a .NET binary are almost always
    # version numbers (e.g. 1.2.3.0), not addresses.
    $ipRx    = [regex]'\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{2,5})?\b'
    $mailRx  = [regex]'[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{2,180}\.[A-Za-z]{2,18}'
    $cmdRx   = [regex]'(?i)\b(cmd\.exe|powershell(\.exe)?|pwsh|rundll32|regsvr32|schtasks|certutil|bitsadmin|wmic|mshta|cscript|wscript|net\.exe|sc\.exe|reg\.exe|netsh|vssadmin|taskkill|whoami|icacls)\b'
    # Secret-ish: keyword must be followed by an assignment (= or :) and a value.
    # This avoids matching substrings inside method names (AccessTokenAsync, etc.).
    $secRx   = [regex]'(?i)\b(password|passwd|pwd|secret|api[_-]?key|client[_-]?secret|access[_-]?key|account[_-]?key|connection[_-]?string|connstr|private[_-]?key)\b["'']?\s*[:=]\s*["'']?([^\s"'',;<>]{2,80})'

    $sets = @{
        Urls=@{}; FilePaths=@{}; RegistryKeys=@{}; IpAddresses=@{}; Emails=@{}; Commands=@{}; Interesting=@{}
    }
    function _add($bucket, $val) {
        if (-not $val) { return }
        $v = "$val".Trim()
        if ($v.Length -lt 3 -or $v.Length -gt 300) { return }
        $k = $v.ToLowerInvariant()
        if (-not $sets[$bucket].ContainsKey($k) -and $sets[$bucket].Count -lt $Cap) { $sets[$bucket][$k] = $v }
    }
    function _keepIp($s) {
        $hasPort = $s.Contains(':')
        $ip = $s.Split(':')[0]
        $o = $ip.Split('.')
        if ($o.Count -ne 4) { return $false }
        foreach ($x in $o) { if ([int]$x -gt 255) { return $false } }
        if ($o[0] -eq '0') { return $false }
        # Keep ip:port literals (real endpoints) and RFC1918/loopback/link-local.
        # Drop bare public quads -- in a .NET binary they are almost always versions.
        if ($hasPort) { return $true }
        if ($ip -match '^(10\.|127\.|192\.168\.|169\.254\.|172\.(1[6-9]|2[0-9]|3[01])\.)') { return $true }
        return $false
    }
    function _printable($s) { return ($s -match '^[\x20-\x7E]+$') }

    foreach ($pe in Get-TcpkPeFiles -Path $Path) {
        if (Test-TcpkIsFrameworkFile $pe.Name) { continue }
        if (Test-TcpkIsNativeNoise $pe.Name)   { continue }
        $text = Read-TcpkAllText -Path $pe.FullName
        if (-not $text) { continue }

        foreach ($m in $urlRx.Matches($text))   { _add 'Urls'         $m.Value }
        foreach ($m in $driveRx.Matches($text)) { _add 'FilePaths'    $m.Value }
        foreach ($m in $envRx.Matches($text))   { _add 'FilePaths'    $m.Value }
        foreach ($m in $uncRx.Matches($text))   { _add 'FilePaths'    $m.Value }
        foreach ($m in $regRx.Matches($text))   { _add 'RegistryKeys' $m.Value }
        foreach ($m in $ipRx.Matches($text))    { if (_keepIp $m.Value) { _add 'IpAddresses' $m.Value } }
        foreach ($m in $mailRx.Matches($text)) {
            $em = $m.Value
            # Skip SSH/crypto protocol identifiers that look like emails
            # (aes128-gcm@openssh.com, curve25519-sha256@libssh.org, *-cert-v01@...).
            if ($em -match '(?i)@(openssh\.com|libssh\.org)$') { continue }
            if ($em -match '(?i)(gcm|cbc|ctr|poly1305|sha2|sha256|sha512|nistp|cert-v0|hmac|curve|ecdsa|ssh-)') { continue }
            # Real emails have an all-lowercase domain + lowercase TLD. XAML resource
            # paths and .NET type references (name.xaml@Namespace.Type, Type@Vendor.Lib)
            # have a PascalCase "domain" -- reject those. NOTE: -cnotmatch (case
            # SENSITIVE) is required; the default -match is case-insensitive and would
            # let uppercase domains through.
            if ($em -cnotmatch '^[A-Za-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}$') { continue }
            if ($em -match '(?i)\.(xaml|cs|dll|exe|resx|baml|vb|cpp|h)@') { continue }
            if (_printable $em) { _add 'Emails' $em }
        }
        foreach ($m in $cmdRx.Matches($text))   { _add 'Commands'     $m.Value.ToLowerInvariant() }
        foreach ($m in $secRx.Matches($text))   { if (_printable $m.Value) { _add 'Interesting' $m.Value } }
    }

    [pscustomobject]@{
        Urls         = @($sets.Urls.Values         | Sort-Object)
        FilePaths    = @($sets.FilePaths.Values     | Sort-Object)
        RegistryKeys = @($sets.RegistryKeys.Values  | Sort-Object)
        IpAddresses  = @($sets.IpAddresses.Values   | Sort-Object)
        Emails       = @($sets.Emails.Values        | Sort-Object)
        Commands     = @($sets.Commands.Values      | Sort-Object)
        Interesting  = @($sets.Interesting.Values   | Sort-Object)
    }
}
