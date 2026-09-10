function Test-TcpkUninstallStringHijack {
<#
.SYNOPSIS
    C22. Unquoted UninstallString / QuietUninstallString / ModifyPath under
    HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\<id> (and WOW64 twin).

.DESCRIPTION
    Same primitive as the classic unquoted-service-path LPE, different registry root.
    Installer engines (MSI, InstallShield, InnoSetup, Squirrel) write these three
    registry values to describe how the app is uninstalled. When the OS Programs and
    Features shell invokes them, the command is passed through CreateProcess with
    lpApplicationName=NULL, so the same Windows path-tokenisation rule applies:

        C:\Program Files\Vendor Corp\App\uninstall.exe

    becomes an attempt to run:

        C:\Program.exe        (with args 'Files\Vendor', 'Corp\App\uninstall.exe')

    If a low-privilege user can drop C:\Program.exe (or any ancestor-with-space +
    .exe), the uninstall runs the planted binary in the identity of whoever clicked
    Uninstall (frequently a local admin).

    The value must:
      * contain at least one space
      * not start with a double-quote
      * not be a single unspaced .exe path (no split possible)
      * the first-word ancestor (%SystemDrive%\Program.exe for the example above)
        must sit on a directory a non-admin can write, OR that ancestor already
        exists as an .exe file (rarer but still a match).

    Rules:
      installer.uninstall-string-hijack   HIGH   Confirmed   any of the three values
                                                              parses as an unquoted
                                                              path with an ancestor
                                                              that is either writable
                                                              or already planted.
      installer.uninstall-string-unquoted MEDIUM Confirmed   the value is unquoted
                                                              and has a space, but
                                                              no writable ancestor
                                                              was found. Reader-facing
                                                              scope info.

.PARAMETER NameLike
    Optional. Uninstall-id (DisplayName) substring filter. Default '*' matches all.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()] param([string[]]$NameLike = @())

    if (-not (Assert-TcpkWindows 'Test-TcpkUninstallStringHijack')) { return }

    # Reuse the same file-rights mask + broad-principal helper the driver / profile
    # rules use. WriteAttributes / AppendData are deliberately not in the mask.
    $fileDangerMask =
        0x00000002 -bor 0x00000040 -bor 0x00010000 -bor
        0x00040000 -bor 0x00080000 -bor 0x10000000 -bor 0x40000000
    $riskySids   = @('S-1-1-0','S-1-5-11','S-1-5-32-545','S-1-5-4','S-1-5-32-547')
    $riskyNameRx = '(?i)\b(Everyone|Authenticated Users|Users|INTERACTIVE|BUILTIN\\(Users|Power Users))\b'

    function _AceIsRisky([Security.AccessControl.AccessRule]$ace) {
        if ($ace.AccessControlType -ne 'Allow') { return $false }
        $sid = $null
        try {
            if ($ace.IdentityReference -is [Security.Principal.SecurityIdentifier]) { $sid = $ace.IdentityReference.Value }
            else { $sid = ($ace.IdentityReference.Translate([Security.Principal.SecurityIdentifier])).Value }
        } catch { }
        $matched = $false
        if ($sid -and ($riskySids -contains $sid)) { $matched = $true }
        elseif ($ace.IdentityReference.Value -match $riskyNameRx) { $matched = $true }
        if (-not $matched) { return $false }
        $rights = 0
        try { if ($ace.PSObject.Properties['FileSystemRights']) { $rights = [int]$ace.FileSystemRights } } catch { }
        return (($rights -band $fileDangerMask) -ne 0)
    }

    # Enumerate every ancestor directory of the first-word prefix, up to the drive
    # root. Windows tries each in order when tokenising an unquoted path, so the
    # highest-value plant slot is the leftmost writable directory in that walk.
    function _AncestorPlantSlots([string]$Cmd) {
        # Take the first whitespace-terminated token (before any argv).
        $first = ($Cmd -split '\s+', 2)[0]
        if (-not $first) { return @() }
        # Strip a trailing '.exe' - not required for Windows to try C:\Program.exe.
        $out = @()
        $cur = $first
        while ($cur -and $cur -match '\\') {
            $parent = Split-Path -Parent $cur
            if (-not $parent) { break }
            $out += ,@{ Ancestor = $cur; ParentDir = $parent }
            $cur = $parent
        }
        return $out
    }

    $roots = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    )
    foreach ($root in $roots) {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        $keys = $null
        try { $keys = @(Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue) } catch { continue }
        foreach ($k in $keys) {
            $props = $null
            try { $props = Get-ItemProperty -LiteralPath $k.PSPath -ErrorAction SilentlyContinue } catch { continue }
            if (-not $props) { continue }
            $display = "$($props.DisplayName)"
            if ($NameLike -and $NameLike.Count -gt 0) {
                $hit = $false
                foreach ($n in $NameLike) { if ($display -like "*$n*" -or $k.PSChildName -like "*$n*") { $hit = $true; break } }
                if (-not $hit) { continue }
            }

            foreach ($valueName in 'UninstallString','QuietUninstallString','ModifyPath') {
                $cmd = "$($props.$valueName)"
                if (-not $cmd) { continue }
                # Trim leading MsiExec / rundll32 wrappers - those are quoted by the OS
                # and use their own arg parsing, so they are not affected by the
                # unquoted-path rule. Same idea as the service check filtering out
                # single-exe paths.
                if ($cmd -match '^\s*(MsiExec|rundll32|regsvr32|cmd\.exe)') { continue }
                if ($cmd -notmatch ' ') { continue }
                if ($cmd -match '^\s*"') { continue }
                if ($cmd -match '^\s*[A-Za-z]:\\[^ ]+\.exe\s*$') { continue }

                # Walk ancestor plant slots. First hit wins for the HIGH escalation.
                $writableHit = $null
                foreach ($slot in (_AncestorPlantSlots $cmd)) {
                    $parent = "$($slot.ParentDir)"
                    if (-not (Test-Path -LiteralPath $parent)) { continue }
                    $acl = $null
                    try { $acl = Get-Acl -LiteralPath $parent -ErrorAction Stop } catch { continue }
                    $bad = @($acl.Access | Where-Object { _AceIsRisky $_ })
                    if ($bad.Count -gt 0) {
                        $grant = ($bad | ForEach-Object { "$($_.IdentityReference) -> $($_.FileSystemRights)" } |
                                  Select-Object -First 3) -join '; '
                        $writableHit = @{ Ancestor = $slot.Ancestor; Parent = $parent; Grant = $grant }
                        break
                    }
                }

                if ($writableHit) {
                    New-TcpkFinding -Module 'os' -RuleId 'installer.uninstall-string-hijack' `
                        -Severity 'HIGH' -Confidence 'Confirmed' `
                        -Title "Uninstall-string hijack primitive: $display ($valueName)" `
                        -File $k.PSPath -Evidence "$valueName=$cmd | plant-slot=$($writableHit.Ancestor) via $($writableHit.Parent) [$($writableHit.Grant)]" `
                        -Cwe @('CWE-428','CWE-732') `
                        -Description ('The Uninstall registry entry stores an unquoted path with an embedded ' +
                            'space. Windows path tokenisation will try to run the shortest interpretation ' +
                            "of the first token before falling back to the actual .exe, and the ancestor " +
                            "'$($writableHit.Ancestor)' resolves against a folder ('$($writableHit.Parent)') " +
                            'whose DACL grants a non-admin principal a right that permits creating an .exe. ' +
                            'When the user clicks Uninstall in Programs and Features, the planted binary ' +
                            'runs in the security context of whoever clicked (usually a local admin).') `
                        -Fix "Rewrite the value to a quoted path: reg add `"$($k.PSPath -replace '.*::','')`" /v $valueName /d '`"<full path>`"' /f. If the vendor writes this value, patch the installer."
                } else {
                    New-TcpkFinding -Module 'os' -RuleId 'installer.uninstall-string-unquoted' `
                        -Severity 'MEDIUM' -Confidence 'Confirmed' `
                        -Title "Uninstall-string unquoted: $display ($valueName)" `
                        -File $k.PSPath -Evidence "$valueName=$cmd" `
                        -Cwe @('CWE-428') `
                        -Description ('The Uninstall entry stores an unquoted path with a space but no ' +
                            'writable ancestor directory was found on this host. On a differently-permissioned ' +
                            'host (a shared build machine, a lab, a downgraded volume ACL) the same value ' +
                            'would escalate to installer.uninstall-string-hijack. Reader-facing scope info.') `
                        -Fix 'Same fix as the hijack rule: rewrite the value with a fully quoted path in the installer author flow.'
                }
            }
        }
    }
}
