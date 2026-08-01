function Test-TcpkRegistryLoadPoints {
<#
.SYNOPSIS
    C26. Registry DLL load points registered BY THE AUDITED APPLICATION: credential
    providers, shell extensions, print monitors, print processors, netsh helpers and
    WER runtime-exception helper modules.

.DESCRIPTION
    Windows has many registry locations whose only purpose is to make some other
    process load a DLL. TCPK already covers COM InprocServer32 (Test-TcpkComHijack)
    and Image File Execution Options (Test-TcpkIfeoHijack). This check covers six
    more families:

      credential provider   HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\
                            Authentication\Credential Providers\{CLSID}
                            The CLSID is resolved through Software\Classes\CLSID\
                            {CLSID}\InprocServer32. Host: LogonUI / winlogon, SYSTEM.
      shell extension       HKLM and HKCU Software\Classes\<class>\shellex\
                            ContextMenuHandlers\*, plus
                            ...\Explorer\ShellIconOverlayIdentifiers\*.
                            Same CLSID resolution. Host: explorer.exe, user identity.
      print monitor         HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors\*
                            value 'Driver'. Host: spoolsv.exe, SYSTEM.
      print processor       HKLM\SYSTEM\CurrentControlSet\Control\Print\Environments\
                            *\Print Processors\*  value 'Driver'. Host: spoolsv, SYSTEM.
      netsh helper          HKLM\SOFTWARE\Microsoft\Netsh -- each VALUE is a DLL name
                            loaded by netsh.exe.
      WER helper module     HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\
                            RuntimeExceptionHelperModules -- each VALUE NAME is a DLL
                            path loaded into a faulting process, including elevated ones.

    THE ATTRIBUTION FILTER IS THE POINT OF THIS CHECK. Every one of these keys is
    machine-wide. Enumerating them all and reporting them would be a worse Autoruns:
    a wall of third-party and OS state that the audited vendor cannot fix. So:

      * A load point becomes an individual finding ONLY when its resolved DLL sits
        INSIDE the -Path tree. Be precise about what that proves: the observable
        fact is that a machine-wide load point points at a file the audited
        application ships. WHO wrote the registry value is not observed, so a third
        party that registered a DLL living in the audited tree looks the same. It is
        still the only slice of this surface the vendor can act on, which is why it
        is the filter.
      * Every other load point is COUNTED and reported as one INFO census line
        (loadpoint.census) with per-family counts and a small capped sample. It is
        context for the analyst, never an individual finding.

    For each in-tree load point the DLL file and its immediate parent directory are
    DACL-checked. A writable one is HIGH: the load point is registered and its target is
    plantable, so a non-admin can get code into the host process -- SYSTEM for credential
    providers and the print families. "Writable" means an allow ACE for a well-known
    low-privilege SID carrying WriteData, DeleteSubdirectoriesAndFiles, Delete, WriteDac,
    WriteOwner, GenericWrite or GenericAll. AppendData is deliberately NOT counted: on a
    directory it only creates subdirectories, and every drive root grants it to
    BUILTIN\Users by default.

    WHAT THIS CHECK DOES NOT DO (do not read more into a finding than this):
      * It does not prove the host process currently loads the DLL. It reads
        registration state only; nothing is launched and no process is inspected.
      * The DLL must be REGISTERED to be seen. A load point the installer only writes
        at first run, or one registered under a different user's HKCU, is invisible here.
      * Bare DLL names (normal for print monitors, print processors and netsh helpers)
        are assumed to live in %SystemRoot%\System32. The real loader search order is
        not replicated, so a bare name that actually resolves elsewhere is counted as
        unresolved and cannot be attributed to the application.
      * Shell-extension coverage is a fixed parent list, not a sweep of Classes: HKLM
        for *, Directory, Directory\Background, AllFilesystemObjects and Drive, HKCU for
        * and Directory, plus the ShellIconOverlayIdentifiers key (native and
        Wow6432Node). Per-file-type and per-progid shellex registrations, and shellex
        families other than ContextMenuHandlers, are not enumerated. The shellex parent
        list is the 64-bit registry view only: HKLM\SOFTWARE\Wow6432Node\Classes\...\
        shellex is NOT read, so a 32-bit-only context-menu handler is invisible.
      * CLSID resolution reads HKLM\SOFTWARE\Classes\CLSID and its Wow6432Node view for
        every family, and additionally HKCU\SOFTWARE\Classes\CLSID for the two shell
        families only -- explorer.exe resolves through the current user's HKCR merge, but
        LogonUI/spoolsv do not, so consulting the auditing user's HKCU for those would
        resolve a DLL the host process would never load.
        HKCU\SOFTWARE\Classes\Wow6432Node\CLSID is not read.
      * Path comparison is a lowercased prefix match on
        [System.IO.Path]::GetFullPath(). That does not expand 8.3 short names and does
        not resolve junctions or symlinks, so a load point recorded as
        C:\PROGRA~1\Vendor\x.dll will NOT match a long-form -Path and is counted
        out-of-tree.
      * The ACL test is a DACL read of the DLL and its immediate parent only. It does
        not compute effective access, does not evaluate deny ACEs that may override an
        allow, and does not walk the rest of the parent chain, so a writable
        grandparent that would allow a directory rename is not detected.
      * A -Path that does not exist produces NO output at all (module convention), not
        a Skipped finding. Unreadable registry locations DO produce a Skipped
        loadpoint.census finding, so a denied hive is never silently a clean result.

    Bounded: each registry family is enumerated once. Enumeration counts stay exact even
    after the -MaxKeys cap stops the expensive per-entry work, the census marks which
    families were capped, and the census sample is capped independently of the counts.
    If -MaxKeys also truncates the list of in-tree findings actually emitted, a Skipped
    loadpoint.app-registered finding says how many were suppressed.

    Read-only: opens registry keys and reads ACLs, modifies nothing.

.PARAMETER Path
    The audited application's install directory (or a file inside it). A load point is
    reported individually only when its resolved DLL is inside this tree. A path that
    does not exist returns nothing.

.PARAMETER MaxKeys
    Per-family cap on how many enumerated keys/values are resolved and ACL-checked, AND
    the cap on how many in-tree findings are emitted in total. Exact enumeration counts
    are still reported in the census, and both kinds of truncation are reported rather
    than being silent. Default 300.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [ValidateRange(20, 5000)][int]$MaxKeys = 300
    )

    if (-not (Assert-TcpkWindows 'Test-TcpkRegistryLoadPoints')) { return }

    $item = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
    if (-not $item) { return }
    $root = $item.FullName
    if (-not $item.PSIsContainer) { $root = $item.DirectoryName }
    if (-not $root) { return }
    $rootNorm = $root.TrimEnd('\').ToLowerInvariant()

    # --- FP guard: a -Path that is a system root makes the attribution filter useless.
    # Everything on the machine would look "in tree" and this would turn into the
    # Autoruns dump the filter exists to prevent. Refuse attribution, still emit census.
    $tooBroad = @()
    foreach ($b in @($env:SystemRoot, "$env:SystemRoot\System32", $env:ProgramFiles,
                     ${env:ProgramFiles(x86)}, $env:ProgramData, "$env:SystemDrive\",
                     "$env:PUBLIC", "$env:LOCALAPPDATA", "$env:APPDATA", "$env:TEMP")) {
        if ($b) { $tooBroad += $b.TrimEnd('\').ToLowerInvariant() }
    }
    $attribute = $true
    if ($tooBroad -contains $rootNorm) { $attribute = $false }

    # Rights that actually allow planting or replacing content. Deliberately excludes:
    #   WriteAttributes / WriteEA -- commonly granted, cannot be used to swap a DLL.
    #   AppendData (0x4) -- on a DIRECTORY this bit is FILE_ADD_SUBDIRECTORY ("create
    #     folders"), which creates a subdirectory and cannot put a file over the
    #     registered DLL; on a FILE it appends to an existing image, which does not
    #     change what the loader maps as code. The default DACL of every drive root
    #     grants BUILTIN\Users exactly this bit as an EFFECTIVE (not inherit-only) ACE,
    #     so including it would flag the parent of any DLL sitting at a drive root as
    #     plantable. FILE_ADD_FILE (WriteData, 0x2) is the real plant primitive and is
    #     kept.
    # DeleteSubdirectoriesAndFiles (FILE_DELETE_CHILD, 0x40) IS included: it lets a
    # low-privilege principal delete the registered DLL even when the DLL's own DACL
    # forbids it, and then drop a replacement. It is not part of Modify, so it is a
    # genuine gap rather than a duplicate of Delete.
    # Generic bits are included because an SDDL ACE can carry GA/GW unmapped.
    $dangerRights = [ordered]@{
        WriteData                    = 0x00000002
        DeleteSubdirectoriesAndFiles = 0x00000040
        Delete                       = 0x00010000
        WriteDac                     = 0x00040000
        WriteOwner                   = 0x00080000
        GenericAll                   = 0x10000000
        GenericWrite                 = 0x40000000
    }
    $dangerMask = 0
    foreach ($rv in $dangerRights.Values) { $dangerMask = $dangerMask -bor [int]$rv }

    # Defined up here on purpose. PowerShell resolves a variable inside a nested function
    # at CALL time, and _ClsidDll (which validates against this pattern) is first called
    # from the credential-provider block, before the shell-extension block runs. Leaving
    # the definition next to its first textual use would make $clsidRx $null there, and
    # '-notmatch $null' matches everything.
    $clsidRx = '^\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}$'

    $records = New-Object 'System.Collections.Generic.List[object]'
    $stats   = [ordered]@{}
    # Unreadable locations: the exact total is counted on the object, while the printable
    # list is capped, so a hive that denies hundreds of subkeys cannot balloon the evidence.
    $unread     = New-Object 'System.Collections.Generic.List[string]'
    $unreadStat = [pscustomobject]@{ Total = 0 }

    function _NoteUnread([string]$What) {
        $unreadStat.Total++
        if ($unread.Count -lt 50) { [void]$unread.Add($What) }
    }

    function _Stat([string]$Source) {
        if (-not $stats.Contains($Source)) {
            $stats[$Source] = [pscustomobject]@{
                Source = $Source; Entries = 0; Processed = 0; Resolved = 0; InTree = 0
                Capped = $false
            }
        }
        return $stats[$Source]
    }

    # Missing vs denied. Test-Path on a registry key the caller cannot OPEN returns
    # $false with no error, which is indistinguishable from "key does not exist" -- that
    # is exactly how a denied hive (HKLM\SYSTEM\...\Print on a hardened host) turns into
    # a silent zero-count clean result. Returns 'ok' / 'denied' / 'missing' as STRINGS;
    # callers must compare with -eq, never with if(), because every one of these is
    # truthy.
    function _KeyState([string]$KeyPath) {
        try {
            $null = Get-Item -LiteralPath $KeyPath -ErrorAction Stop
            return 'ok'
        } catch {
            $ex = $_.Exception
            while ($ex) {
                if (($ex -is [System.Security.SecurityException]) -or
                    ($ex -is [System.UnauthorizedAccessException])) { return 'denied' }
                $ex = $ex.InnerException
            }
            return 'missing'
        }
    }

    # Enumerate child keys of a registry path. Records an unreadable location rather than
    # letting a denied read look like an empty key. Enumeration itself stays on
    # SilentlyContinue so a single denied subkey does not discard the subkeys already
    # returned.
    function _Kids([string]$KeyPath, [string]$Source) {
        $state = _KeyState $KeyPath
        if ($state -eq 'denied') { _NoteUnread "$Source : $KeyPath (key open denied)"; return @() }
        if ($state -ne 'ok') { return @() }
        $enumErr = $null
        $kids = @()
        try {
            $kids = @(Get-ChildItem -LiteralPath $KeyPath -ErrorAction SilentlyContinue -ErrorVariable enumErr)
        } catch {
            $enumErr = $_
        }
        if ($enumErr) { _NoteUnread "$Source : $KeyPath (subkey read denied)" }
        return $kids
    }

    function _KeyValue([string]$KeyPath, [string]$Name) {
        $k = $null
        try { $k = Get-Item -LiteralPath $KeyPath -ErrorAction Stop } catch { return '' }
        $v = $null
        try { $v = $k.GetValue($Name) } catch { return '' }
        if ($null -eq $v) { return '' }
        # REG_MULTI_SZ / REG_BINARY come back as arrays; "$v" would join the elements with
        # spaces and produce a path-shaped string that never existed. Take the first
        # element instead and let resolution reject it if it is not a path.
        if ($v -is [System.Array]) {
            if ($v.Length -eq 0) { return '' }
            $v = $v[0]
        }
        return "$v"
    }

    # [System.IO.Path]::GetFileName THROWS on .NET Framework when the string contains an
    # invalid path character, and these strings come from the registry. A throw here would
    # take down the whole check while building a finding title.
    function _Leaf([string]$P) {
        if (-not $P) { return '' }
        try { return [System.IO.Path]::GetFileName($P) } catch { return $P }
    }

    # Resolve a registry-supplied DLL reference to a full path.
    #   BareInSystem  bare names are the documented convention for print monitors /
    #                 print processors / netsh helpers, which the loader takes from
    #                 System32. For COM servers a bare name is left unresolved instead
    #                 of guessing a location that would show up as evidence.
    function _ResolveDll([string]$Raw, [bool]$BareInSystem) {
        if ([string]::IsNullOrWhiteSpace($Raw)) { return '' }
        $s = $Raw.Trim().Trim('"').Trim()
        if (-not $s) { return '' }
        try { $s = [System.Environment]::ExpandEnvironmentVariables($s) } catch { }
        # IsPathRooted / GetFullPath THROW on .NET Framework for an invalid path
        # character. Registry data is attacker-influenced and routinely junk, so reject
        # such a value as unresolved instead of letting it terminate the check.
        foreach ($ch in [System.IO.Path]::GetInvalidPathChars()) {
            if ($s.IndexOf($ch) -ge 0) { return '' }
        }
        if (-not [System.IO.Path]::IsPathRooted($s)) {
            if (-not $BareInSystem) { return '' }
            if (-not $env:SystemRoot) { return '' }
            try { $s = Join-Path (Join-Path $env:SystemRoot 'System32') $s } catch { return '' }
        }
        try { $s = [System.IO.Path]::GetFullPath($s) } catch { }
        return $s
    }

    # AllowHkcu: only the shell families may resolve through the auditing user's HKCU.
    # explorer.exe reads HKCR, which merges HKCU\SOFTWARE\Classes over HKLM for the
    # logged-on user, so an HKCU-only CLSID really is what it loads. LogonUI (credential
    # providers) and spoolsv (print families) run as SYSTEM and never see this user's
    # hive, so resolving through it there would attribute a DLL the host process would
    # never load. $Clsid is also validated: it is a registry key NAME, and an unvalidated
    # one containing a backslash would build a different key path than the one reported.
    function _ClsidDll([string]$Clsid, [bool]$AllowHkcu) {
        if (-not $Clsid) { return '' }
        if ($Clsid -notmatch $clsidRx) { return '' }
        $hives = @('HKLM:\SOFTWARE\Classes\CLSID', 'HKLM:\SOFTWARE\Classes\Wow6432Node\CLSID')
        if ($AllowHkcu) { $hives += 'HKCU:\SOFTWARE\Classes\CLSID' }
        foreach ($hive in $hives) {
            $kp = "$hive\$Clsid\InprocServer32"
            if (-not (Test-Path -LiteralPath $kp)) { continue }
            $v = _KeyValue $kp ''
            if ($v) { return $v }
        }
        return ''
    }

    function _InTree([string]$FullPath) {
        if (-not $FullPath) { return $false }
        $p = $FullPath.TrimEnd('\').ToLowerInvariant()
        if ($p -eq $rootNorm) { return $true }
        return $p.StartsWith($rootNorm + '\')
    }

    # DACL check. Uses the shared SDDL parser (well-known SIDs, so it does not depend on
    # the display language), then drops grants that exist only as INHERIT-ONLY ACEs --
    # those apply to children created later, not to this object, and treating them as
    # writable is a classic false positive. If the .Access view cannot be correlated at
    # all (SID translation failure) the SDDL verdict is kept rather than silently dropped.
    function _LowPrivWritable([string]$ItemPath) {
        if (-not $ItemPath) { return '' }
        if (-not (Test-Path -LiteralPath $ItemPath)) { return '' }
        $acl = $null
        try { $acl = Get-Acl -LiteralPath $ItemPath -ErrorAction Stop } catch { return '' }
        $sddl = ''
        try { $sddl = "$($acl.Sddl)" } catch { }
        if (-not $sddl) { return '' }
        $grants = @(Get-TcpkSddlLowPrivGrants -Sddl $sddl -RightsMap $dangerRights)
        if ($grants.Count -eq 0) { return '' }

        $effective = @()
        foreach ($g in $grants) {
            $ok = $false
            $sawRule = $false
            foreach ($ace in @($acl.Access)) {
                if ("$($ace.AccessControlType)" -ne 'Allow') { continue }
                $rsid = ''
                try { $rsid = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value } catch { $rsid = '' }
                if (-not $rsid -or $rsid -ne $g.Sid) { continue }
                $sawRule = $true
                $prop = 0
                try { $prop = [int]$ace.PropagationFlags } catch { $prop = 0 }
                if (($prop -band [int][System.Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0) { continue }
                $mask = 0
                try { $mask = [int]$ace.FileSystemRights } catch { $mask = 0 }
                if (($mask -band $dangerMask) -eq 0) { continue }
                $ok = $true
                break
            }
            if ($ok -or (-not $sawRule)) { $effective += $g }
        }
        if ($effective.Count -eq 0) { return '' }
        return (($effective | ForEach-Object { "$($_.Account) [$($_.Sid)] -> $($_.Granted -join ',')" }) -join '; ')
    }

    function _Add([string]$Source, [string]$KeyPath, [string]$Entry, [string]$Raw, [string]$Dll) {
        $records.Add([pscustomobject]@{
            Source   = $Source
            KeyPath  = $KeyPath
            Entry    = $Entry
            Raw      = $Raw
            Dll      = $Dll
            InTree   = (_InTree $Dll)
        })
    }

    # --- 1. Credential providers -------------------------------------------------
    $cpRoot = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers'
    $src = 'credential-provider'
    $st = _Stat $src
    $all = @(_Kids $cpRoot $src)
    $st.Entries = $all.Count
    if ($all.Count -gt $MaxKeys) { $st.Capped = $true }
    foreach ($k in @($all | Select-Object -First $MaxKeys)) {
        $st.Processed++
        $clsid = "$($k.PSChildName)"
        # $false: LogonUI/winlogon run as SYSTEM and do not read this user's HKCU.
        $raw = _ClsidDll $clsid $false
        $dll = _ResolveDll $raw $false
        if ($dll) { $st.Resolved++ }
        _Add $src "$cpRoot\$clsid" $clsid $raw $dll
    }

    # --- 2. Shell extensions -----------------------------------------------------
    # Fixed parent list: the shellex classes that apply to every file / folder, which is
    # where an application-registered handler is loaded into explorer.exe most often.
    $shellexParents = @(
        'HKLM:\SOFTWARE\Classes\*\shellex\ContextMenuHandlers'
        'HKCU:\SOFTWARE\Classes\*\shellex\ContextMenuHandlers'
        'HKLM:\SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers'
        'HKCU:\SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers'
        'HKLM:\SOFTWARE\Classes\Directory\Background\shellex\ContextMenuHandlers'
        'HKLM:\SOFTWARE\Classes\AllFilesystemObjects\shellex\ContextMenuHandlers'
        'HKLM:\SOFTWARE\Classes\Drive\shellex\ContextMenuHandlers'
    )
    $src = 'shell-context-menu'
    $st = _Stat $src
    $budget = $MaxKeys
    # The budget only stops the EXPENSIVE work (CLSID resolution + ACL reads). The outer
    # loop keeps enumerating every parent so Entries stays an exact enumeration count --
    # the census and the docstring both promise that, and breaking out here would have
    # made "entries" silently mean "entries until the cap was hit".
    foreach ($parent in $shellexParents) {
        $all = @(_Kids $parent $src)
        $st.Entries += $all.Count
        foreach ($k in $all) {
            if ($budget -le 0) { $st.Capped = $true; break }
            $budget--
            $st.Processed++
            # The handler CLSID is normally the key's default value; some installers use
            # the CLSID as the key NAME and leave the default empty.
            $clsid = _KeyValue "$($parent)\$($k.PSChildName)" ''
            if ($clsid) { $clsid = $clsid.Trim() }
            if ($clsid -notmatch $clsidRx) {
                $clsid = ''
                if ("$($k.PSChildName)" -match $clsidRx) { $clsid = "$($k.PSChildName)" }
            }
            $raw = ''
            # $true: explorer.exe resolves through HKCR, which merges this user's HKCU.
            if ($clsid) { $raw = _ClsidDll $clsid $true }
            $dll = _ResolveDll $raw $false
            if ($dll) { $st.Resolved++ }
            _Add $src "$($parent)\$($k.PSChildName)" "$($k.PSChildName)" $raw $dll
        }
    }

    $overlayRoots = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers'
        'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers'
    )
    $src = 'shell-icon-overlay'
    $st = _Stat $src
    $budget = $MaxKeys
    foreach ($parent in $overlayRoots) {
        $all = @(_Kids $parent $src)
        $st.Entries += $all.Count
        foreach ($k in $all) {
            if ($budget -le 0) { $st.Capped = $true; break }
            $budget--
            $st.Processed++
            $clsid = _KeyValue "$($parent)\$($k.PSChildName)" ''
            if ($clsid) { $clsid = $clsid.Trim() }
            if ($clsid -notmatch $clsidRx) { $clsid = '' }
            $raw = ''
            if ($clsid) { $raw = _ClsidDll $clsid $true }
            $dll = _ResolveDll $raw $false
            if ($dll) { $st.Resolved++ }
            _Add $src "$($parent)\$($k.PSChildName)" "$($k.PSChildName)" $raw $dll
        }
    }

    # --- 3. Print monitors -------------------------------------------------------
    $monRoot = 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Monitors'
    $src = 'print-monitor'
    $st = _Stat $src
    $all = @(_Kids $monRoot $src)
    $st.Entries = $all.Count
    if ($all.Count -gt $MaxKeys) { $st.Capped = $true }
    foreach ($k in @($all | Select-Object -First $MaxKeys)) {
        $st.Processed++
        $raw = _KeyValue "$monRoot\$($k.PSChildName)" 'Driver'
        $dll = _ResolveDll $raw $true
        if ($dll) { $st.Resolved++ }
        _Add $src "$monRoot\$($k.PSChildName)" "$($k.PSChildName)" $raw $dll
    }

    # --- 4. Print processors -----------------------------------------------------
    $envRoot = 'HKLM:\SYSTEM\CurrentControlSet\Control\Print\Environments'
    $src = 'print-processor'
    $st = _Stat $src
    $budget = $MaxKeys
    # As above: keep walking every print environment so Entries stays exact; only the
    # per-entry resolution is budgeted.
    foreach ($e in @(_Kids $envRoot $src)) {
        $ppRoot = "$envRoot\$($e.PSChildName)\Print Processors"
        $all = @(_Kids $ppRoot $src)
        $st.Entries += $all.Count
        foreach ($k in $all) {
            if ($budget -le 0) { $st.Capped = $true; break }
            $budget--
            $st.Processed++
            $raw = _KeyValue "$ppRoot\$($k.PSChildName)" 'Driver'
            $dll = _ResolveDll $raw $true
            if ($dll) { $st.Resolved++ }
            _Add $src "$ppRoot\$($k.PSChildName)" "$($e.PSChildName)\$($k.PSChildName)" $raw $dll
        }
    }

    # --- 5. Netsh helpers --------------------------------------------------------
    # Values, not subkeys: each value's DATA is the helper DLL name.
    $netshRoot = 'HKLM:\SOFTWARE\Microsoft\Netsh'
    $src = 'netsh-helper'
    $st = _Stat $src
    $netshState = _KeyState $netshRoot
    if ($netshState -eq 'denied') { _NoteUnread "$src : $netshRoot (key open denied)" }
    if ($netshState -eq 'ok') {
        $nk = $null
        try { $nk = Get-Item -LiteralPath $netshRoot -ErrorAction Stop } catch { _NoteUnread "$src : $netshRoot (key open denied)" }
        if ($nk) {
            $names = @()
            try { $names = @($nk.GetValueNames()) } catch { _NoteUnread "$src : $netshRoot (value read denied)" }
            # The key's own default value is not a helper registration, so drop it BEFORE
            # counting. Counting it and skipping it later made Entries disagree with the
            # number of entries that could ever be processed.
            $names = @($names | Where-Object { "$_" -ne '' })
            $st.Entries = $names.Count
            if ($names.Count -gt $MaxKeys) { $st.Capped = $true }
            foreach ($n in @($names | Select-Object -First $MaxKeys)) {
                $st.Processed++
                $raw = _KeyValue $netshRoot $n
                $dll = _ResolveDll $raw $true
                if ($dll) { $st.Resolved++ }
                _Add $src $netshRoot $n $raw $dll
            }
        }
    }

    # --- 6. WER runtime exception helper modules ---------------------------------
    # Here the value NAME is the DLL path; the data is a flag.
    $werRoot = 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\RuntimeExceptionHelperModules'
    $src = 'wer-helper'
    $st = _Stat $src
    $werState = _KeyState $werRoot
    if ($werState -eq 'denied') { _NoteUnread "$src : $werRoot (key open denied)" }
    if ($werState -eq 'ok') {
        $wk = $null
        try { $wk = Get-Item -LiteralPath $werRoot -ErrorAction Stop } catch { _NoteUnread "$src : $werRoot (key open denied)" }
        if ($wk) {
            $names = @()
            try { $names = @($wk.GetValueNames()) } catch { _NoteUnread "$src : $werRoot (value read denied)" }
            $names = @($names | Where-Object { "$_" -ne '' })
            $st.Entries = $names.Count
            if ($names.Count -gt $MaxKeys) { $st.Capped = $true }
            foreach ($n in @($names | Select-Object -First $MaxKeys)) {
                $st.Processed++
                $dll = _ResolveDll $n $false
                if ($dll) { $st.Resolved++ }
                _Add $src $werRoot $n $n $dll
            }
        }
    }

    # --- Attribution -------------------------------------------------------------
    foreach ($r in $records) {
        if (-not $r.InTree) { continue }
        $sRec = _Stat $r.Source
        $sRec.InTree++
    }

    $hostMap = @{
        'credential-provider' = @{ Sev = 'MEDIUM'; Host = 'LogonUI.exe / winlogon.exe as SYSTEM on the secure desktop' }
        'shell-context-menu'  = @{ Sev = 'LOW';    Host = 'explorer.exe and any process that shows a shell context menu, as the logged-on user' }
        'shell-icon-overlay'  = @{ Sev = 'LOW';    Host = 'explorer.exe, as the logged-on user' }
        'print-monitor'       = @{ Sev = 'MEDIUM'; Host = 'spoolsv.exe as SYSTEM' }
        'print-processor'     = @{ Sev = 'MEDIUM'; Host = 'spoolsv.exe as SYSTEM' }
        'netsh-helper'        = @{ Sev = 'LOW';    Host = 'netsh.exe, under whatever identity runs it (often an administrator)' }
        'wer-helper'          = @{ Sev = 'MEDIUM'; Host = 'any faulting process, including elevated ones, via WER' }
    }

    # Declared out here, not inside the else: the census block below reads it on both
    # branches, and the module deliberately runs without Set-StrictMode, so an undefined
    # $suppressed would silently compare as $null instead of failing loudly.
    $suppressed = 0

    if (-not $attribute) {
        New-TcpkSkippedFinding -RuleId 'loadpoint.app-registered' `
            -Title 'Registry load-point attribution skipped: -Path is a system-wide directory' `
            -Reason ("-Path resolved to '$root', which is a system or profile root. Attribution " +
                'works by testing whether a load point''s DLL sits inside the audited ' +
                'application''s install tree, and with a root this broad every unrelated ' +
                'load point would match. Re-run with the application''s own install directory. ' +
                'The census below still enumerates what is registered.')
    } else {
        $reported = 0
        foreach ($r in $records) {
            if (-not $r.InTree) { continue }
            # 'continue', not 'break': the remainder still has to be counted so the
            # truncation can be reported instead of vanishing.
            if ($reported -ge $MaxKeys) { $suppressed++; continue }
            $reported++

            $meta = $hostMap["$($r.Source)"]
            $sev = 'LOW'
            $hostText = 'a Windows host process'
            if ($meta) { $sev = $meta.Sev; $hostText = $meta.Host }

            $exists = Test-Path -LiteralPath $r.Dll -PathType Leaf
            $dllDir = ''
            try { $dllDir = [System.IO.Path]::GetDirectoryName($r.Dll) } catch { }

            New-TcpkFinding -Module 'os' -RuleId 'loadpoint.app-registered' `
                -Severity $sev -Confidence 'Confirmed' `
                -Title "App-registered $($r.Source) load point: $(_Leaf $r.Dll)" `
                -File $r.Dll `
                -Evidence ("key=$($r.KeyPath); entry=$($r.Entry); registered-value=$($r.Raw); " +
                    "resolved=$($r.Dll); dll-present=$exists; loaded-by=$hostText") `
                -Cwe @('CWE-427') `
                -Description ('This registry load point resolves to a DLL inside the audited ' +
                    'application''s install tree, so the file Windows is told to load into ' +
                    $hostText + ' is one the vendor ships. That is attack surface the vendor ' +
                    'owns: any memory-safety or logic bug in the DLL is reachable from that host ' +
                    'process, and the registration itself is a persistence and code-injection ' +
                    'primitive if an attacker can influence what the entry points at. Two limits ' +
                    'on this finding: the check reads registration state from the registry only ' +
                    'and does not observe the host process loading the DLL, and path containment ' +
                    'shows the DLL ships in the tree, not which installer wrote the registry ' +
                    'value.') `
                -Fix ('Confirm the load point is genuinely required. If it is, keep the DLL and its ' +
                    'directory writable only by SYSTEM and Administrators, sign the DLL, and remove ' +
                    'the registration on uninstall. If it is not required, do not register it.')

            $fileGrants = ''
            if ($exists) { $fileGrants = _LowPrivWritable $r.Dll }
            $dirGrants = ''
            if ($dllDir) { $dirGrants = _LowPrivWritable $dllDir }
            if (-not $fileGrants -and -not $dirGrants) { continue }

            $what = 'DLL file'
            if (-not $fileGrants) { $what = 'DLL directory' }
            elseif ($dirGrants) { $what = 'DLL file and its directory' }

            $planting = 'replace the registered DLL'
            if (-not $exists) { $planting = 'create the missing registered DLL' }

            New-TcpkFinding -Module 'os' -RuleId 'loadpoint.writable' `
                -Severity 'HIGH' -Confidence 'Confirmed' `
                -Title "App-registered $($r.Source) load point is plantable: $(_Leaf $r.Dll)" `
                -File $r.Dll `
                -Evidence ("key=$($r.KeyPath); resolved=$($r.Dll); dll-present=$exists; " +
                    "file-grants=[$fileGrants]; dir-grants=[$dirGrants]; loaded-by=$hostText") `
                -Cwe @('CWE-732', 'CWE-427') `
                -Description ('This load point points into the audited install tree and the ' + $what +
                    ' is writable by a low-privilege principal. A non-admin can ' + $planting + ' and ' +
                    'Windows will load it into ' + $hostText + ', which for the credential-provider ' +
                    'and print families means SYSTEM. Deny ACEs and effective-access are not ' +
                    'evaluated here; the grant reported is a matching allow ACE on the object itself ' +
                    '(inherit-only ACEs are excluded).') `
                -Fix ('Restrict the DLL and its containing directory to SYSTEM and Administrators. ' +
                    'A load point must never point into a directory a standard user can write.')
        }
    }

    # --- Census ------------------------------------------------------------------
    # out-of-tree / unresolved are computed over the PROCESSED records, not over the exact
    # enumeration counts -- resolving an entry is what tells you which bucket it belongs
    # in, and resolution is what -MaxKeys caps. The exact per-family enumeration counts are
    # reported alongside as entries=, and cap-hit families are named, so a capped run
    # cannot be mistaken for a complete one. The sample list is capped separately so a
    # machine with hundreds of shell extensions cannot balloon the evidence string.
    $sample = New-Object 'System.Collections.Generic.List[string]'
    $outOfTree = 0
    $unresolved = 0
    foreach ($r in $records) {
        if (-not $r.Dll) { $unresolved++; continue }
        if ($r.InTree) { continue }
        $outOfTree++
        if ($sample.Count -lt 12) {
            $sample.Add("$($r.Source):$(_Leaf $r.Dll)")
        }
    }
    $perSource = @()
    $entriesTotal = 0
    $cappedSources = @()
    foreach ($key in $stats.Keys) {
        $s = $stats[$key]
        $entriesTotal += [int]$s.Entries
        $line = "$($s.Source) entries=$($s.Entries) processed=$($s.Processed) resolved=$($s.Resolved) in-tree=$($s.InTree)"
        # -eq $true, not if($s.Capped): keep the comparison explicit so this cannot rot
        # into a truthiness test if the field ever becomes a string.
        if ($s.Capped -eq $true) { $line += ' CAPPED'; $cappedSources += $s.Source }
        $perSource += $line
    }
    $sampleText = 'none'
    if ($sample.Count -gt 0) { $sampleText = ($sample -join ', ') }
    $cappedText = 'none'
    if ($cappedSources.Count -gt 0) { $cappedText = ($cappedSources -join ',') }

    New-TcpkFinding -Module 'os' -RuleId 'loadpoint.census' `
        -Severity 'INFO' -Confidence 'Confirmed' `
        -Title "Registry DLL load-point census: $entriesTotal registered, $($records.Count) examined, $outOfTree outside the audited tree" `
        -File $root `
        -Evidence (($perSource -join ' | ') +
            "; entries-total=$entriesTotal; processed-total=$($records.Count); " +
            "out-of-tree=$outOfTree; unresolved=$unresolved; " +
            "attribution-enabled=$attribute; max-keys=$MaxKeys; capped-families=$cappedText; " +
            "sample(max 12)=$sampleText") `
        -Cwe @('CWE-427') `
        -Description ('Context, not a finding. These six registry families exist to make some ' +
            'other process load a DLL, and they are machine-wide: most entries belong to Windows ' +
            'or to unrelated software, and the audited vendor cannot fix them. They are counted ' +
            'here so the report shows what was examined, while only load points resolving inside ' +
            'the audited install tree are raised as individual findings. "entries" is the exact ' +
            'number of registrations enumerated; "processed" is how many of them were resolved ' +
            'and ACL-checked before the -MaxKeys cap, so out-of-tree and unresolved are counts ' +
            'over the processed set, not over every entry. A family listed in capped-families ' +
            'was truncated: raise -MaxKeys to cover it. "unresolved" counts ' +
            'entries whose DLL reference could not be turned into a path (an unregistered CLSID, ' +
            'or a bare name outside the System32 convention); those cannot be attributed either ' +
            'way.') `
        -Fix 'No action. Review the sampled entries manually if the host is expected to be clean.'

    if ($suppressed -gt 0) {
        New-TcpkSkippedFinding -RuleId 'loadpoint.app-registered' `
            -Title 'Registry load-point findings truncated by -MaxKeys' `
            -Reason ("$suppressed in-tree load point(s) were found but not emitted: -MaxKeys is " +
                "$MaxKeys and that many findings were already reported. Silence on those entries " +
                'is a cap, not a clean result. Re-run with a higher -MaxKeys to see them all.')
    }

    if ($unreadStat.Total -gt 0) {
        $shown = @($unread | Select-Object -First 10)
        New-TcpkSkippedFinding -RuleId 'loadpoint.census' `
            -Title 'Registry load-point enumeration incomplete' `
            -Reason ("$($unreadStat.Total) registry location(s) could not be read, so the census " +
                'undercounts and an in-tree load point registered under one of them would be ' +
                'missed. Unreadable (first 10 of ' + $unreadStat.Total + ', list retained up to ' +
                '50): ' + ($shown -join '; ') +
                '. Re-run elevated if these are HKLM\SYSTEM keys.')
    }
}
