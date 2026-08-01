# Rights maps for the ServiceDll check. Defined at module scope (not inside the function)
# so the test suite can assert their exact contents: the composite-mask false positive
# these maps avoid is the whole reason the check is usable on a live machine.
#
# DELIBERATE OMISSIONS (each one is a false-positive guard, do not "complete" these maps):
#
#   FILE_ALL_ACCESS (0x1F01FF) / KEY_ALL_ACCESS (0xF003F) are NOT listed. Get-TcpkSddlLowPrivGrants
#   ORs every map value into one danger mask and reports any ACE that intersects it. A composite
#   constant carries the READ bits too, so listing it would match a plain read-only ACE -- which
#   is exactly what Users holds on every DLL in System32. The write bits inside those composites
#   are already listed individually, so an ACE that really does grant full control still matches.
#
#   FILE_WRITE_EA (0x10) and FILE_WRITE_ATTRIBUTES (0x100) are NOT listed: neither one lets a
#   caller change a single byte of DLL content.
#
#   FILE_APPEND_DATA (0x4) is NOT listed in the FILE map: appending to a mapped PE does not
#   redirect execution, and claiming "replaceable" off an append-only grant would overstate it.
#
#   FILE_ADD_SUBDIRECTORY (0x4) is NOT listed in the DIRECTORY map even though it shares the
#   0x4 bit with APPEND_DATA. The default ACL on C:\ grants Users "Create folders / append data",
#   so listing it would flag the parent directory of anything installed at the root of a volume.
#   Planting a DLL needs FILE_ADD_FILE, not a new subdirectory.
$script:TcpkServiceDllFileRights = [ordered]@{
    WRITE_DATA    = 0x0002       # overwrite the DLL in place
    DELETE        = 0x10000      # delete it, then recreate (needs ADD_FILE on the parent too)
    WRITE_DAC     = 0x40000      # grant yourself write
    WRITE_OWNER   = 0x80000      # take ownership, then grant yourself write
    GENERIC_ALL   = 0x10000000   # SDDL "GA"
    GENERIC_WRITE = 0x40000000   # SDDL "GW"
}
$script:TcpkServiceDllDirRights = [ordered]@{
    ADD_FILE      = 0x0002       # plant a new file next to (or in place of a deleted) DLL
    DELETE_CHILD  = 0x0040       # delete the existing DLL regardless of its own ACL
    WRITE_DAC     = 0x40000
    WRITE_OWNER   = 0x80000
    GENERIC_ALL   = 0x10000000
    GENERIC_WRITE = 0x40000000
}
$script:TcpkServiceDllKeyRights = [ordered]@{
    KEY_SET_VALUE      = 0x0002  # repoint ServiceDll
    KEY_CREATE_SUB_KEY = 0x0004  # create Parameters where it does not exist yet
    WRITE_DAC          = 0x40000
    WRITE_OWNER        = 0x80000
    GENERIC_ALL        = 0x10000000
    GENERIC_WRITE      = 0x40000000
}

function Test-TcpkServiceDll {
<#
.SYNOPSIS
    C24. svchost ServiceDll hijack: writable service DLL, writable DLL directory, or a
    service registry key that lets a non-admin repoint ServiceDll.

.DESCRIPTION
    A shared-process Windows service does not run an ImagePath executable of its own --
    svchost.exe loads its code from the ServiceDll value under
    HKLM:\SYSTEM\CurrentControlSet\Services\<name>\Parameters. Test-TcpkServicePermissions
    covers the SCM security descriptor and Test-TcpkServiceBinaryAcl covers the ImagePath
    executable; neither one looks at ServiceDll, so this check covers that path.

    Three separate primitives are checked, because they are separate:

      1. THE DLL FILE      Can a low-privileged principal overwrite, delete, or re-ACL the
                           DLL itself? That replaces the code svchost loads.
      2. THE DLL DIRECTORY Can a low-privileged principal add a file to, or delete a child
                           of, the containing directory? DELETE_CHILD, WRITE_DAC, WRITE_OWNER
                           and GENERIC_ALL reach the existing DLL, so those are HIGH. ADD_FILE
                           and GENERIC_WRITE cannot overwrite an existing file, so they are
                           reported one severity lower (MEDIUM) and the finding text names the
                           rights that were actually granted.
      3. THE SERVICE KEY   Can a low-privileged principal write the service key or its
                           Parameters subkey? KEY_SET_VALUE there repoints ServiceDll at a
                           DLL of their choosing, which defeats a perfectly locked-down DLL.

    Each hit is read directly from the object's own ACL (Get-Acl -> SDDL ->
    Get-TcpkSddlLowPrivGrants), so a finding means a specific well-known low-privilege SID
    holds a specific right, not that a name matched a regex.

    DEFAULT-PERMISSIVE DIRECTORIES. A volume root, %ProgramData% (and everything Windows
    inherits it into), and %WINDIR%\Temp ship with an ACL that already grants Authenticated
    Users FILE_ADD_FILE. A service DLL parked in one of those genuinely is plantable by a
    standard user, so the finding is NOT suppressed -- but its text says the grant is the
    Windows default rather than a vendor misconfiguration, because that decides what the fix
    is (relocate the DLL, or set an explicit ACL on the vendor subfolder).

    ATTRIBUTION. This enumerates every service on the machine, which is not the same thing
    as auditing one application. With -Path, only services whose ServiceDll resolves inside
    that install tree are reported, and those are attributable to the audited vendor.
    Without -Path, every service is reported and each finding says in its own text that the
    service may belong to someone else. Do not send an unscoped finding to a vendor without
    confirming they own the service.

    LIMITS -- what this check does NOT do:
      * It does not prove the service is actually svchost-hosted. ImagePath is recorded in
        the evidence so a reader can see the host, but a ServiceDll on a non-svchost service
        is reported the same way.
      * It reads CurrentControlSet only, not the other control sets or a mounted offline hive.
      * A ServiceDll value that is not a rooted path is counted but not reported: svchost's
        effective DLL search order cannot be proven from the registry alone, so calling it a
        search-order hijack would be a guess. The count appears in the enumeration summary.
      * A ServiceDll path that does not exist on disk is counted as missing and NOT reported,
        even though a phantom DLL in a writable directory is a plant primitive. Proving that
        needs the load-order reasoning this check deliberately refuses to guess at, so the
        count is surfaced in the summary and the case is left to a dedicated check.
      * Registry ACLs are per key. A key-writable finding means the whole key is writable;
        there is no per-value granularity to report.
      * UNDER-REPORTING: only the well-known low-privilege SIDs recognised by
        Get-TcpkSddlLowPrivGrants are matched (Everyone, Authenticated Users, Users,
        INTERACTIVE, ANONYMOUS, Guests). An ACE granting write to a custom local group or to
        one named non-admin user is NOT reported. A clean result means "no well-known
        low-privilege SID holds these rights", not "the ACL is correct".
      * OVER-REPORTING: the DACL is read as written. Deny ACEs are not subtracted and the
        INHERIT_ONLY flag is not honoured, so an ACE that applies only to child objects, or
        one that a preceding deny ACE overrides, still reports. Confirm a hit with
        `icacls <path>` (or Effective Access) before filing it.
      * Directory and key findings are deduped per (object, SID). Many services share one
        directory (System32 above all), so one finding names one service while the same
        grant may reach several; the finding text says so.
      * The walk is capped by -MaxServices. If the machine has more service keys than the
        cap, the enumeration summary says WALK TRUNCATED and names the total, because a
        truncated walk is not a clean one.
      * Runs read-only. Nothing is opened for write, and no service is started or stopped.
        The registry walk is non-recursive (one level of subkeys under Services), so the
        junction-loop concern that Get-TcpkChildItemSafe exists for does not apply here.
      * A 32-bit PowerShell on a 64-bit OS is refused outright (Skipped finding): file-system
        redirection would silently resolve System32 paths to SysWOW64 and the ACLs reported
        would be the wrong file's.
      * On a non-Windows host the cmdlet warns and returns without emitting any finding, per
        the module-wide Assert-TcpkWindows convention.

.PARAMETER Path
    Install directory (or a file inside it) of the audited application. When supplied, only
    services whose resolved ServiceDll lives inside that tree are reported. Omit for a
    machine-wide survey.

.PARAMETER MaxServices
    Cap on service keys inspected (default 2000; a normal Windows install has well under
    1000). Bounds the walk on a machine with an unusual number of services.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param(
        [string]$Path,
        [ValidateRange(1, 20000)][int]$MaxServices = 2000
    )

    if (-not (Assert-TcpkWindows 'Test-TcpkServiceDll')) { return }

    # WOW64 file-system redirection would make every System32 ServiceDll path resolve to the
    # SysWOW64 copy, so the ACL reported would belong to a different file than the one svchost
    # loads. Refuse rather than emit confidently wrong data.
    $is64Os = $false
    $is64Proc = $false
    try { $is64Os = [System.Environment]::Is64BitOperatingSystem } catch { }
    try { $is64Proc = [System.Environment]::Is64BitProcess } catch { }
    # New-TcpkSkippedFinding is NOT used for these: it hardcodes -Module 'runtime', which would
    # file this check's non-run records under the wrong module and leave the 'os' bucket with no
    # record that the check refused. Emitted directly with -Module 'os' instead, same as
    # Test-TcpkAvExclusions in this bucket. Confidence and RuleId are unchanged.
    if ($is64Os -and -not $is64Proc) {
        New-TcpkFinding -Module 'os' -RuleId 'servicedll.unreadable' `
            -Severity 'INFO' -Confidence 'Skipped' `
            -Title 'ServiceDll check skipped under 32-bit PowerShell' `
            -File 'HKLM:\SYSTEM\CurrentControlSet\Services' `
            -Evidence 'This is a 32-bit process on a 64-bit OS. WOW64 redirection would resolve System32 ServiceDll paths to SysWOW64 and report the wrong file ACL. Re-run in 64-bit PowerShell.'
        return
    }

    # ---- attribution scope ----------------------------------------------------------
    $scopeRoot = ''
    if ($Path) {
        $item = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
        if (-not $item) {
            New-TcpkFinding -Module 'os' -RuleId 'servicedll.unreadable' `
                -Severity 'INFO' -Confidence 'Skipped' `
                -Title 'ServiceDll check skipped: -Path does not exist' `
                -File "$Path" `
                -Evidence "Cannot scope the enumeration: '$Path' was not found."
            return
        }
        if ($item.PSIsContainer) { $scopeRoot = "$($item.FullName)" } else { $scopeRoot = "$($item.DirectoryName)" }
        $scopeRoot = $scopeRoot.TrimEnd('\', '/')
    }

    $scopeNote = 'This enumeration is machine-wide, so THIS SERVICE MAY BE UNRELATED TO THE AUDITED APPLICATION. Confirm the service belongs to the audited vendor before reporting it to them; re-run with -Path <install dir> to restrict the check to the audited install tree.'
    if ($scopeRoot) {
        $scopeNote = "The ServiceDll resolves inside the audited install tree ($scopeRoot), so this is attributable to the audited application."
    }

    # In-tree test. Compares canonical full paths with an explicit separator boundary so
    # 'C:\App' does not match 'C:\AppData'.
    function _InScope([string]$file) {
        if (-not $scopeRoot) { return $true }
        if (-not $file) { return $false }
        $fp = ''
        try { $fp = [System.IO.Path]::GetFullPath($file) } catch { return $false }
        if ($fp.Equals($scopeRoot, [System.StringComparison]::OrdinalIgnoreCase)) { return $true }
        return $fp.StartsWith($scopeRoot + '\', [System.StringComparison]::OrdinalIgnoreCase)
    }

    # ---- ACL reader ------------------------------------------------------------------
    # Cached: hundreds of services share System32 as their DLL directory, and re-reading
    # that ACL once per service is pure waste. Returns @{ Ok; Grants }.
    $aclCache = @{}
    function _Grants([string]$target, $map, [string]$tag) {
        if (-not $target) { return [pscustomobject]@{ Ok = $false; Grants = @() } }
        $ck = ($tag + '|' + $target).ToLowerInvariant()
        if ($aclCache.ContainsKey($ck)) { return $aclCache[$ck] }

        $acl = $null
        try { $acl = Get-Acl -LiteralPath $target -ErrorAction Stop } catch { }
        if (-not $acl) {
            $res = [pscustomobject]@{ Ok = $false; Grants = @() }
            $aclCache[$ck] = $res
            return $res
        }

        $sddl = ''
        try { $sddl = "$($acl.GetSecurityDescriptorSddlForm([System.Security.AccessControl.AccessControlSections]::Access))" } catch { }
        if (-not $sddl) { try { $sddl = "$($acl.Sddl)" } catch { } }

        $g = @()
        try { $g = @(Get-TcpkSddlLowPrivGrants -Sddl $sddl -RightsMap $map) } catch { $g = @() }
        $res = [pscustomobject]@{ Ok = $true; Grants = $g }
        $aclCache[$ck] = $res
        return $res
    }

    # ---- OS-default-permissive directories -------------------------------------------
    # NOT a suppression. These directories ship with a permissive ACL from Windows itself:
    #   * a volume root (C:\)  -- the default DACL grants Authenticated Users DCLCRPCR,
    #     which for a directory includes FILE_ADD_FILE (0x2).
    #   * %ProgramData% and everything under it -- the default DACL grants Authenticated
    #     Users add-file / add-subdirectory with container inheritance, so every vendor
    #     subfolder created without an explicit ACL inherits it.
    #   * %WINDIR%\Temp -- world-writable by design.
    # A service DLL parked in one of these really is plantable by a standard user, so the
    # finding stays. What changes is that the text says the grant is the Windows default
    # rather than something the vendor configured, because that decides who has to fix it
    # (the vendor must relocate or re-ACL; there is no misconfiguration to point at).
    $defaultPermissiveRoots = @()
    foreach ($ev in @('ProgramData', 'SystemRoot')) {
        $rv = ''
        try { $rv = [System.Environment]::GetEnvironmentVariable($ev) } catch { }
        if (-not $rv) { continue }
        if ($ev -eq 'SystemRoot') { $rv = [System.IO.Path]::Combine($rv, 'Temp') }
        $defaultPermissiveRoots += $rv.TrimEnd('\', '/')
    }
    function _DefaultAclNote([string]$dir) {
        if (-not $dir) { return '' }
        $d = $dir.TrimEnd('\', '/')
        # A volume root trims to 'C:' (length 2, second char ':').
        if ($d.Length -eq 2 -and $d.EndsWith(':')) {
            return ' NOTE: this directory is a volume root, whose default Windows ACL already grants Authenticated Users FILE_ADD_FILE. The grant is the OS default, not a vendor misconfiguration; the fix is to relocate the DLL under Program Files, not to argue about the ACL.'
        }
        foreach ($r in $defaultPermissiveRoots) {
            if ($d.Equals($r, [System.StringComparison]::OrdinalIgnoreCase) -or
                $d.StartsWith($r + '\', [System.StringComparison]::OrdinalIgnoreCase)) {
                return " NOTE: this directory is inside $r, which ships with a permissive default ACL that Windows inherits into subfolders. The grant is the OS default, not a vendor misconfiguration; the fix is to relocate the DLL under Program Files or set an explicit ACL on the vendor subfolder."
            }
        }
        return ''
    }

    # ---- read ServiceDll -------------------------------------------------------------
    # Parameters\ServiceDll is the documented location; a few services keep it directly on
    # the service key, so both are read and the location is recorded in the evidence.
    function _ReadServiceDll([string]$keyPath) {
        foreach ($sub in @('\Parameters', '')) {
            $p = $keyPath + $sub
            $v = $null
            try { $v = (Get-ItemProperty -LiteralPath $p -Name 'ServiceDll' -ErrorAction Stop).ServiceDll } catch { continue }
            if ($v -is [array]) { $v = $v | Select-Object -First 1 }
            if ("$v".Trim()) {
                $where = 'ServiceDll (service key)'
                if ($sub) { $where = 'Parameters\ServiceDll' }
                return [pscustomobject]@{ Raw = "$v"; Source = $where }
            }
        }
        return $null
    }

    # Non-recursive: one level of subkeys under Services, so there is no tree to walk and the
    # junction-loop hazard Get-TcpkChildItemSafe guards against does not exist on this path.
    #
    # SilentlyContinue + -ErrorVariable rather than -ErrorAction Stop. A single unreadable
    # service subkey raises a NON-terminating error; -Stop promotes it to terminating, the
    # catch fires, and every key already emitted is thrown away -- turning a hive that is
    # 99% readable into a false 'hive could not be enumerated' skip that hides the whole
    # check. Keep what was read, and only skip when nothing came back at all.
    $svcRoot = 'HKLM:\SYSTEM\CurrentControlSet\Services'
    $svcErr  = $null
    $svcKeys = @()
    try {
        $svcKeys = @(Get-ChildItem -LiteralPath $svcRoot -ErrorAction SilentlyContinue -ErrorVariable svcErr)
    } catch {
        $svcKeys = @()
    }
    if (-not $svcKeys.Count) {
        $hiveWhy = "Get-ChildItem on $svcRoot returned no subkeys. ServiceDll coverage did not run -- this is NOT a clean result."
        # NOTE the $null guard: @($null).Count is 1 in PowerShell, so a bare @($svcErr).Count
        # would report a phantom error when -ErrorVariable never populated.
        if ($null -ne $svcErr -and @($svcErr).Count -gt 0) { $hiveWhy = $hiveWhy + " First error: $(@($svcErr)[0].Exception.Message)" }
        New-TcpkFinding -Module 'os' -RuleId 'servicedll.unreadable' `
            -Severity 'INFO' -Confidence 'Skipped' `
            -Title 'Service registry hive could not be enumerated' `
            -File $svcRoot -Evidence $hiveWhy
        return
    }

    # Truncation must be visible: keysSeen alone cannot be told apart from a complete walk,
    # and an audit that silently stopped at the cap is not a clean audit.
    $totalKeys     = @($svcKeys).Count
    $keyEnumErrors = 0
    if ($null -ne $svcErr) { $keyEnumErrors = @($svcErr).Count }
    $truncated     = ($totalKeys -gt $MaxServices)

    # Sample cap for the summary line. The exact counts below are never capped, and the list
    # is capped at exactly the number rendered so its length can never be read as a count.
    $sampleCap     = 15

    $keysSeen      = 0
    $withDll       = 0
    $unrooted      = 0
    $missing       = 0
    $considered    = 0
    $aclDenied     = 0
    $aclTried      = 0
    $rows          = New-Object 'System.Collections.Generic.List[object]'
    $seen          = New-Object 'System.Collections.Generic.HashSet[string]'

    foreach ($k in ($svcKeys | Select-Object -First $MaxServices)) {
        $keysSeen++
        $svcName = "$($k.PSChildName)"
        $keyPath = "$($k.PSPath)"

        $rec = _ReadServiceDll $keyPath
        if (-not $rec) { continue }
        $withDll++

        # REG_EXPAND_SZ: expand before any path test. The registry provider often hands back
        # an already-expanded value, and expanding twice is a no-op, so this is safe either way.
        $raw = "$($rec.Raw)".Trim().Trim('"')
        $resolved = $raw
        try { $resolved = [System.Environment]::ExpandEnvironmentVariables($raw) } catch { }

        $rooted = $false
        try { $rooted = [System.IO.Path]::IsPathRooted($resolved) } catch { }
        if (-not $rooted) {
            # Counted, not reported: see the LIMITS section in the help.
            $unrooted++
            continue
        }
        if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) { $missing++; continue }
        if (-not (_InScope $resolved)) { continue }
        $considered++

        $imagePath = ''
        try { $imagePath = "$((Get-ItemProperty -LiteralPath $keyPath -Name 'ImagePath' -ErrorAction Stop).ImagePath)" } catch { }
        if ($imagePath.Length -gt 160) { $imagePath = $imagePath.Substring(0, 160) + '...' }
        $hostNote = "host=$imagePath"
        if (-not $imagePath) { $hostNote = 'host=(ImagePath unreadable)' }

        # Bounded sample for the enumeration summary; exact counts above are never capped.
        if ($rows.Count -lt $sampleCap) {
            $rows.Add([pscustomobject]@{ Service = $svcName; Dll = $resolved })
        }

        # GetDirectoryName, not Split-Path: Split-Path -Path applies wildcard expansion, so a
        # ServiceDll path containing [ or ] resolves to nothing and the directory check is
        # silently skipped. GetDirectoryName is literal.
        $dllDir = ''
        try { $dllDir = [System.IO.Path]::GetDirectoryName($resolved) } catch { }
        if (-not $dllDir) { $dllDir = '' }

        # --- 1. the DLL file itself ---------------------------------------------------
        $aclTried++
        $fileRes = _Grants $resolved $script:TcpkServiceDllFileRights 'file'
        if (-not $fileRes.Ok) { $aclDenied++ }
        foreach ($g in $fileRes.Grants) {
            if (-not $seen.Add("file|$($resolved.ToLowerInvariant())|$($g.Sid)")) { continue }
            New-TcpkFinding -Module 'os' -RuleId 'servicedll.writable' `
                -Severity 'HIGH' -Confidence 'Confirmed' `
                -Title "Service DLL is writable by $($g.Account): $svcName" `
                -File $resolved `
                -Evidence "$svcName -> $($rec.Source)='$raw' -> $resolved; $($g.Account) ($($g.Sid)) -> $($g.Granted -join ', '); $hostNote" `
                -Cwe @('CWE-732', 'CWE-427', 'CWE-269') `
                -Description ("A low-privileged principal holds write-class rights on the DLL this service " +
                    "loads. A shared-process service runs that DLL inside svchost under the service account, " +
                    "which is normally LocalSystem, so replacing the file is direct code execution as SYSTEM " +
                    "at the next service start. $scopeNote") `
                -Fix 'Restrict the DLL to SYSTEM and Administrators for write, Users for read and execute only. Remove the explicit low-privilege grant; do not rely on the service key ACL to compensate.'
        }

        # --- 2. the directory that holds it -------------------------------------------
        if ($dllDir) {
            $aclTried++
            $dirRes = _Grants $dllDir $script:TcpkServiceDllDirRights 'dir'
            if (-not $dirRes.Ok) { $aclDenied++ }
            foreach ($g in $dirRes.Grants) {
                if (-not $seen.Add("dir|$($dllDir.ToLowerInvariant())|$($g.Sid)")) { continue }

                # ADD_FILE (and GENERIC_WRITE, which expands to add-file/add-subdirectory but
                # NOT delete-child) cannot overwrite an existing file, so those are planting
                # primitives rather than replacement primitives. DELETE_CHILD, WRITE_DAC,
                # WRITE_OWNER and GENERIC_ALL do reach the existing DLL, so those stay HIGH.
                # The weak-case sentence names the rights actually granted: it used to say
                # "ADD_FILE alone" unconditionally, which was simply false text on a
                # GENERIC_WRITE-only ACE, where ADD_FILE is not in the granted list at all.
                $strong    = @('DELETE_CHILD', 'WRITE_DAC', 'WRITE_OWNER', 'GENERIC_ALL')
                $strongHit = @(@($g.Granted) | Where-Object { $strong -contains $_ })
                $grantedTxt = (@($g.Granted) -join ', ')
                $sev = 'MEDIUM'
                $why = "The granted rights ($grantedTxt) add files to the directory but cannot overwrite the existing DLL, so this is a planting primitive: it reaches the service only if the DLL is later deleted, renamed, or resolves a dependency from this directory."
                if ($strongHit.Count) {
                    $sev = 'HIGH'
                    $why = "These rights ($($strongHit -join ', ')) reach the existing DLL: the current file can be deleted or re-ACLed and a replacement put in its place, regardless of the ACL on the DLL itself."
                }
                $why = $why + (_DefaultAclNote $dllDir)

                New-TcpkFinding -Module 'os' -RuleId 'servicedll.writable' `
                    -Severity $sev -Confidence 'Confirmed' `
                    -Title "Service DLL directory is writable by $($g.Account): $svcName" `
                    -File $dllDir `
                    -Evidence "$svcName -> $resolved; directory $dllDir; $($g.Account) ($($g.Sid)) -> $grantedTxt; $hostNote; reported once per (directory, SID) -- other services whose DLL lives here are affected by the same grant" `
                    -Cwe @('CWE-732', 'CWE-427') `
                    -Description ("A low-privileged principal can write into the directory holding this " +
                        "service's DLL. $why The service DLL runs inside svchost as the service account, " +
                        "normally LocalSystem. $scopeNote") `
                    -Fix 'Restrict the directory to SYSTEM and Administrators for write (inherit from Program Files or System32). Standard users should have read and execute only.'
            }
        }

        # --- 3. the service key and its Parameters subkey ------------------------------
        # A locked-down DLL is worthless if the value naming it can be rewritten.
        foreach ($sub in @('', '\Parameters')) {
            $kp = $keyPath + $sub
            if (-not (Test-Path -LiteralPath $kp)) { continue }
            $aclTried++
            $keyRes = _Grants $kp $script:TcpkServiceDllKeyRights 'key'
            if (-not $keyRes.Ok) { $aclDenied++; continue }

            $display = $kp -replace 'Microsoft\.PowerShell\.Core\\Registry::', ''
            $label = 'service key'
            if ($sub) { $label = 'Parameters subkey' }

            foreach ($g in $keyRes.Grants) {
                if (-not $seen.Add("key|$($display.ToLowerInvariant())|$($g.Sid)")) { continue }
                New-TcpkFinding -Module 'os' -RuleId 'servicedll.key-writable' `
                    -Severity 'HIGH' -Confidence 'Confirmed' `
                    -Title "Service $label is writable by $($g.Account): $svcName" `
                    -File $display `
                    -Evidence "$svcName $label; $($g.Account) ($($g.Sid)) -> $($g.Granted -join ', '); current ServiceDll=$resolved; $hostNote" `
                    -Cwe @('CWE-732', 'CWE-427', 'CWE-269') `
                    -Description ("A low-privileged principal can write this service's registry key. " +
                        "KEY_SET_VALUE there is enough to repoint ServiceDll at any DLL the attacker " +
                        "controls, and WRITE_DAC or WRITE_OWNER gets there in one extra step. This " +
                        "bypasses a correctly locked-down DLL entirely, because the attacker changes " +
                        "WHICH DLL is loaded rather than its contents. svchost loads it as the service " +
                        "account, normally LocalSystem. $scopeNote") `
                    -Fix 'Restrict the service key and its Parameters subkey to SYSTEM and Administrators for write. Service configuration must not be modifiable by the accounts the service protects against.'
            }
        }
    }

    # ---- enumeration summary ----------------------------------------------------------
    # Emitted even when nothing was flagged, so a clean run is distinguishable from a run
    # that never looked. Counts are exact; the service list is a capped sample.
    # The sample list is capped at $sampleCap and is NEVER the count of anything: $considered
    # is the exact figure, and the ellipsis is driven from $considered, not from the list
    # length, so a capped list can never be mistaken for a total.
    $sample = ''
    if ($rows.Count) {
        $sample = (($rows | ForEach-Object { "$($_.Service)=$($_.Dll)" }) -join '; ')
        if ($considered -gt $rows.Count) { $sample = $sample + " ... (sample capped at $sampleCap of $considered)" }
    }
    $scopeLabel = 'machine-wide (no -Path given; services may belong to other vendors)'
    if ($scopeRoot) { $scopeLabel = "restricted to $scopeRoot" }

    $evidence = "service keys present=$totalKeys; service keys read=$keysSeen (cap $MaxServices); " +
        "with a ServiceDll value=$withDll; " +
        "in scope and resolving to a file=$considered; ServiceDll path not found on disk=$missing; " +
        "ServiceDll value not a rooted path (counted, not reported)=$unrooted; " +
        "ACL checks attempted=$aclTried, denied=$aclDenied (per service; repeat paths are served from cache); " +
        "subkeys that errored during enumeration=$keyEnumErrors; scope=$scopeLabel"
    $title = "svchost ServiceDll surface: $considered service DLL(s) in scope, $withDll on the machine"
    if ($truncated) {
        $evidence = $evidence + "; WALK TRUNCATED: $totalKeys service keys exist but only $keysSeen were read because -MaxServices is $MaxServices. The unread keys were NOT checked. Re-run with -MaxServices $totalKeys or higher."
        $title = $title + ' (WALK TRUNCATED)'
    }
    if ($sample) { $evidence = $evidence + '; sample: ' + $sample }

    $summaryFix = 'No action. Review the counts: a non-zero denied count means part of the surface was not covered by this run, and re-running elevated will cover it.'
    if ($truncated) { $summaryFix = "Re-run with -MaxServices $totalKeys or higher: this run stopped at the cap and the remaining service keys were never examined. " + $summaryFix }

    New-TcpkFinding -Module 'os' -RuleId 'servicedll.enumerated' `
        -Severity 'INFO' -Confidence 'Confirmed' `
        -Title $title `
        -File $svcRoot -Evidence $evidence -Cwe @('CWE-732') `
        -Description ('Coverage record for the ServiceDll check: which shared-process services were ' +
            'examined and how many could not be resolved or ACL-read. A service whose ServiceDll path ' +
            'did not resolve, or whose ACL could not be read, was NOT checked -- those counts are here ' +
            'so an unchecked service is not mistaken for a clean one. Only well-known low-privilege ' +
            'SIDs are matched, so a zero here is not proof the ACLs are correct.') `
        -Fix $summaryFix

    if ($aclTried -gt 0 -and $aclDenied -eq $aclTried) {
        New-TcpkFinding -Module 'os' -RuleId 'servicedll.unreadable' `
            -Severity 'INFO' -Confidence 'Skipped' `
            -Title 'No ServiceDll ACL could be read' `
            -File $svcRoot `
            -Evidence "Get-Acl was denied for all $aclTried objects examined. No conclusion about ServiceDll writability can be drawn from this run."
    }
}
