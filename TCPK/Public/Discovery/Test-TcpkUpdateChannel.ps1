function Test-TcpkUpdateChannel {
<#
.SYNOPSIS
    A53. Update-channel and update-state surfaces of a firmware-updater desktop app.

.DESCRIPTION
    Sibling of Test-TcpkUpdateFlow (F02), which decides whether the app SIGNS its updates.
    This one goes after the three things a real device-vendor updater UI (dropdown for
    "release channel", read-out of "current version", separate "connected device updates"
    submenu) always exposes and that are consistently under-tested:

      update.channel-selectable        MEDIUM  A release-channel value (beta, dev, nightly,
                                               canary, release, track, branch, ring) is present
                                               in the app's configuration. If the config file
                                               is user-writable this is a local attacker's
                                               path to unreleased or debug builds.

      update.endpoint-in-writable-config HIGH  The update URL sits in a config file whose DACL
                                               grants write to Users or Authenticated Users.
                                               Rewriting that file points every subsequent
                                               update check at an attacker-controlled origin,
                                               without touching the binary.

      update.state-in-writable-path    MEDIUM  A "current-version" or "installed" value sits in
                                               a Users-writable file. If the client compares
                                               versions itself, a local user can fake being on
                                               any version and force a downgrade or replay.

      update.device-fanout             INFO    The app references "connected device" and update
                                               together, so it pushes firmware to child devices.
                                               Scope only. The child-device signature model must
                                               be reviewed separately (this cmdlet cannot see
                                               the child).

    All grades are Confirmed for the writable-DACL findings (the ACL is observed) and Inferred
    for the string-based ones. The channel-selectable rule reports the finding at MEDIUM only
    when the enclosing file is user-writable, otherwise it degrades to INFO.

.PARAMETER Path
    Install directory.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { return }

    # A "release channel" value carries one of a small vocabulary. Anything else generates too
    # many false positives ("stable" appears in unrelated strings).
    $channelRx = '(?i)("(?:release[-_]?level|release[-_]?channel|update[-_]?channel|channel|branch|track|ring)"\s*[:=]\s*")(release|stable|beta|dev|nightly|canary|preview|insider|experimental|internal|alpha|rc|test)("|,|;|\})'

    # Update-URL patterns: look for likely update endpoints, http or https, whose SURROUNDING
    # config context is one of a small set of update-y keys.
    $urlRx = '(?ims)("(?:update[-_]?(?:url|endpoint|feed|server|host|source)|manifest[-_]?url|patch[-_]?url|firmware[-_]?url|checkForUpdatesUrl|versionCheck(?:Url)?)"\s*[:=]\s*")(https?://[^"''<>\s]+)'

    # Current-version / installed-version stored in the config, which the client presumably
    # trusts.
    $stateRx = '(?i)"(current[-_]?version|installed[-_]?version|last[-_]?version|version[-_]?installed)"\s*[:=]\s*"[0-9][^"]*"'

    # Textual co-occurrence for the fanout pattern: "connected device" and "update" together
    # within a shortish window is a decent signal in PE strings.
    $fanoutRx = '(?is)connected[- _]?device.{0,120}update|update.{0,120}connected[- _]?device'

    $configExtRx = '\.(config|json|xml|ini|toml|yaml|yml|manifest)$'
    $configs = @()
    try {
        $configs = Get-ChildItem -LiteralPath $Path -Recurse -File -ErrorAction SilentlyContinue |
                   Where-Object { $_.Extension -and ($_.Name -imatch $configExtRx) }
    } catch { return }

    # ACL check reused from what the other Discovery cmdlets do; keep it a private helper.
    function Test-UserWritable([string]$FullName) {
        try {
            $acl = Get-Acl -LiteralPath $FullName -ErrorAction SilentlyContinue
            if (-not $acl) { return $false }
            foreach ($a in $acl.Access) {
                if ("$($a.IdentityReference)" -match '(?i)Users|Everyone|Authenticated Users' -and
                    "$($a.FileSystemRights)" -match '(?i)Write|Modify|FullControl' -and
                    $a.AccessControlType -eq 'Allow') { return $true }
            }
        } catch { }
        return $false
    }

    foreach ($f in $configs) {
        $text = ''
        try { $text = [IO.File]::ReadAllText($f.FullName) } catch { continue }
        if (-not $text) { continue }
        $writable = Test-UserWritable $f.FullName

        # 1. release channel present in this config
        $mChan = [regex]::Match($text, $channelRx)
        if ($mChan.Success) {
            $sev = if ($writable) { 'MEDIUM' } else { 'INFO' }
            New-TcpkFinding -Module 'discovery' -RuleId 'update.channel-selectable' `
                -Severity $sev -Confidence 'Confirmed' `
                -Title "Release channel value in $($f.Name) ($($mChan.Groups[2].Value))" `
                -File $f.FullName -Evidence "match=$($mChan.Value.Substring(0, [Math]::Min(120, $mChan.Length))) writable=$writable" `
                -Cwe @('CWE-494') `
                -Description ("A release-channel key ($(($mChan.Value -split ':|=')[0].Trim('\" '))) with " +
                    "value $($mChan.Groups[2].Value) is present in the app's config. If this file is user-writable " +
                    "(observed: $writable), a local user can switch the app to an unreleased or debug channel " +
                    "and receive builds that would not normally reach them.") `
                -Fix 'Do not read the release channel from a client-side config a normal user can edit. Enforce channel selection on the update server side per authenticated user or per product entitlement.'
        }

        # 2. update endpoint in this config, plus DACL check
        foreach ($m in [regex]::Matches($text, $urlRx)) {
            $url = $m.Groups[2].Value
            $isHttp = $url -match '^http://'
            $sev = if ($writable -or $isHttp) { 'HIGH' } else { 'MEDIUM' }
            $rule = if ($writable) { 'update.endpoint-in-writable-config' }
                    elseif ($isHttp) { 'update.endpoint-plaintext' }
                    else { 'update.endpoint-in-config' }
            $conf = if ($writable) { 'Confirmed' } else { 'Inferred' }
            New-TcpkFinding -Module 'discovery' -RuleId $rule `
                -Severity $sev -Confidence $conf `
                -Title "Update endpoint in $($f.Name): $url" `
                -File $f.FullName -Evidence "url=$url writable=$writable http=$isHttp" `
                -Cwe @('CWE-494','CWE-829') `
                -Description ("The update endpoint is defined in $($f.Name). writable=$writable http=$isHttp. " +
                    "A user-writable config lets a local attacker rewrite the URL and redirect every " +
                    "subsequent update fetch, without touching the code-signed binary. An http:// endpoint " +
                    "lets a network attacker do the same over the wire.") `
                -Fix 'Ship the update endpoint compiled into a signed binary and never read it from an editable file. Where the endpoint must be configurable (per-tenant clouds), put the file under an ACL that only SYSTEM and the vendor service account can write.'
        }

        # 3. state stored in config
        if ($text -match $stateRx) {
            $sev = if ($writable) { 'MEDIUM' } else { 'LOW' }
            New-TcpkFinding -Module 'discovery' -RuleId 'update.state-in-writable-path' `
                -Severity $sev -Confidence 'Confirmed' `
                -Title "Installed-version state persisted in $($f.Name)" `
                -File $f.FullName -Evidence "writable=$writable" `
                -Cwe @('CWE-345') `
                -Description ("The client-side ""installed version"" is persisted in $($f.Name). writable=$writable. " +
                    "If the update decision is made client-side by comparing this value against a server " +
                    "response, a local user can lie about the current version and receive an arbitrary payload " +
                    "or force a downgrade below the current build.") `
                -Fix 'Compare versions server-side, keyed on authenticated identity or device certificate. Never trust a client-supplied "current version".'
        }
    }

    # 4. connected-device fanout: scan all PEs, one INFO finding max
    $fanoutReported = $false
    try {
        foreach ($pe in @(Get-TcpkPeFiles -Path $Path)) {
            if ($fanoutReported) { break }
            if (Test-TcpkIsFrameworkFile $pe.Name) { continue }
            $s = Read-TcpkAllText -Path $pe.FullName
            if ($s -and ($s -match $fanoutRx)) {
                New-TcpkFinding -Module 'discovery' -RuleId 'update.device-fanout' `
                    -Severity 'INFO' -Confidence 'Inferred' `
                    -Title "Assembly references pushing updates to connected devices: $($pe.Name)" `
                    -File $pe.FullName `
                    -Description ('The binary contains the "connected device" + "update" pattern, so the app ' +
                        'likely pushes firmware to child devices as well as updating itself. Testing scope is ' +
                        'doubled: this cmdlet only sees the desktop side. Signing, downgrade protection and ' +
                        'auth of the CHILD update path must be reviewed separately.') `
                    -Fix 'No fix required from this scope finding. Confirm the child-device update path uses signed images and per-device authentication.'
                $fanoutReported = $true
            }
        }
    } catch { }
}
