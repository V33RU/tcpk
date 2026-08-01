function Test-TcpkAppInitDlls {
<#
.SYNOPSIS
    C25. AppInit_DLLs and AppCertDlls global injection registrations (read-only).

.DESCRIPTION
    Two legacy Windows mechanisms load an arbitrary DLL into processes without the
    process asking for it:

      AppInit_DLLs   HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows
                     Every DLL listed there is loaded into every process that links
                     user32.dll, gated by LoadAppInit_DLLs and (since Windows 8)
                     RequireSignedAppInit_DLLs. On a 64-bit OS both the 64-bit and
                     the 32-bit (WOW6432Node) registry view are read, because they
                     govern processes of different bitness independently. On a
                     32-bit OS the two views are the same physical key, so only one
                     is read and findings are not emitted twice.

      AppCertDlls    HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls
                     Every DLL listed there is loaded into every process that calls
                     the CreateProcess family. Not gated by Secure Boot.

    ATTRIBUTION. Findings are split deliberately, because these are not the same
    kind of problem:

      VENDOR-REPORTABLE  a configured AppInit or AppCert DLL that lives inside the
                         audited application's install directory, or whose name
                         matches -NameLike. The application registered itself as a
                         global injection point, so every other process on the
                         machine now loads vendor code. That is the vendor's own
                         design decision and the vendor can remove it.

      ENVIRONMENT STATE  everything else. Populating these keys requires ADMIN,
                         AppInit_DLLs is neutralised by default when Secure Boot is
                         on, and Microsoft has deprecated it. The audited
                         application's vendor cannot fix a populated AppInit_DLLs
                         and it is NOT an application defect. It is reported because
                         a populated key on an audited machine means the target
                         process, along with every other process on the box, is
                         being injected right now, which is a compromise indicator
                         worth surfacing. The finding text says this in plain words
                         so nobody files it against the vendor.

    Severity inputs: LoadAppInit_DLLs = 1 with RequireSignedAppInit_DLLs = 0 raises
    it, and a configured DLL path (or, if the file is absent, its parent directory)
    that a low-privileged group can write raises it further, because then a
    non-admin can control what gets injected everywhere.

    LIMITS, stated so the docstring does not overstate the code:
      * Reads the registry only. It does not enumerate loaded modules in any
        process, so it does not prove that a listed DLL was actually mapped into
        the target. It proves the machine is configured to map it.
      * RequireSignedAppInit_DLLs is often absent. When absent the effective value
        is an OS default (0 on Windows 7 and earlier, 1 on Windows 8 and later),
        derived from the CurrentBuildNumber value. When that inferred value is what
        decides the verdict (LoadAppInit_DLLs = 1) the finding is marked
        Confidence = Inferred rather than Confirmed; when the list is not loaded the
        inference does not affect the verdict and the finding stays Confirmed. If
        the build cannot be read, the requirement is reported as unknown and never
        used to raise severity.
      * Secure Boot state comes from Confirm-SecureBootUEFI, which is unavailable
        on BIOS machines and on some SKUs. Unknown is reported as unknown and never
        used to lower severity.
      * Writability is decided from the allow-ACEs of the file (or, for an absent
        file, its parent directory) that grant a well-known low-privilege SID a
        planting right. Three consequences, stated rather than hidden:
          - Deny ACEs are NOT evaluated, so a path explicitly denied to Users could
            still be reported as writable.
          - When the file EXISTS only the file's own ACL is read. FILE_DELETE_CHILD
            granted on the parent directory also permits replacement and is NOT
            detected, so a missing writability finding is not proof of a safe path.
          - If the ACL cannot be read at all (Get-Acl denied, path gone), the entry
            is treated as not writable. That is a silent negative chosen to avoid a
            false positive, not evidence that the path is locked down.
      * An AppInit entry that is not a rooted path is resolved by the normal DLL
        search order at load time. This check does not reproduce that search, so
        such an entry is reported as unresolved rather than guessed at.
      * Signature validity of a listed DLL is not checked.
      * At most 32 AppInit entries and 32 AppCert values are RESOLVED, ACL-checked
        and attributed per key. The exact entry count is reported separately from
        that sample and is what severity is decided from, but an entry past the cap
        is counted only: it is not resolved, not ACL-checked and not attributed to
        the vendor. A key with more than 32 entries is already anomalous and the
        evidence states "showing N" so the truncation is visible.
      * If one registry view cannot be opened while another can, the check reports
        which views it actually read. A clean result from this check covers only the
        views named in its evidence.

    Read-only. Opens registry keys for read and calls Get-Acl. Nothing is modified.

.PARAMETER Path
    Optional install directory of the audited application. A configured DLL that
    resolves underneath it is reported as vendor-attributable instead of as
    environment state.

.PARAMETER NameLike
    Optional vendor/package substrings. A configured DLL whose FILE NAME matches one
    is also treated as vendor-attributable. The match is deliberately restricted to
    the file name: matching the whole path would attribute an unrelated machine-wide
    DLL to the audited vendor whenever a term happened to appear in a directory
    component (a user profile name, a temp folder, an unrelated product folder).
    Directory-level attribution is the job of -Path, which is anchored.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param(
        [string]$Path,
        [string[]]$NameLike = @()
    )

    if (-not (Assert-TcpkWindows 'Test-TcpkAppInitDlls')) { return }

    $terms = Get-TcpkNameTerms -NameLike $NameLike

    $appDir = ''
    if ($Path) {
        $pathItem = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
        if ($pathItem) {
            if ($pathItem.PSIsContainer) { $appDir = $pathItem.FullName } else { $appDir = $pathItem.DirectoryName }
        }
    }

    # Bounds. A sane machine has 0-2 entries; these caps only stop a hostile or
    # corrupt value from ballooning the run. Exact counts are kept separately from
    # the capped sample lists so severity is never decided from a truncated view.
    $maxEntries = 32

    # Rights that let a low-privileged principal REPLACE or PLANT the DLL. Read and
    # attribute rights are deliberately excluded: FILE_WRITE_ATTRIBUTES or
    # FILE_WRITE_EA alone cannot swap the file contents, and including them produced
    # noise on ordinary Program Files ACLs. For a directory the same bit values mean
    # FILE_ADD_FILE / FILE_ADD_SUBDIRECTORY, which is exactly the plant primitive.
    $plantRights = [ordered]@{
        'WriteData/AddFile'          = 0x00000002
        'AppendData/AddSubdirectory' = 0x00000004
        'Delete'                     = 0x00010000
        'WriteDac'                   = 0x00040000
        'WriteOwner'                 = 0x00080000
        'GenericWrite'               = 0x40000000
        'GenericAll'                 = 0x10000000
    }

    # Returns '' when nothing low-privileged can plant here, else a description of
    # who and what. Uses the shared SDDL parser so SID handling cannot drift from
    # the process/thread DACL checks.
    function _PlantGrants([string]$target) {
        if (-not $target) { return '' }
        if (-not (Test-Path -LiteralPath $target)) { return '' }
        $acl = $null
        try { $acl = Get-Acl -LiteralPath $target -ErrorAction Stop } catch { return '' }
        if (-not $acl) { return '' }
        $sddl = ''
        try { $sddl = "$($acl.Sddl)" } catch { return '' }
        $grants = @(Get-TcpkSddlLowPrivGrants -Sddl $sddl -RightsMap $plantRights)
        if (-not $grants.Count) { return '' }
        $parts = @()
        foreach ($g in ($grants | Select-Object -First 4)) {
            $parts += "$($g.Account) -> $($g.Granted -join ', ')"
        }
        $text = ($parts -join '; ')
        # The list above is capped at 4. Say so when it was truncated, otherwise a
        # reader would take a capped sample for the complete set of grants.
        if ($grants.Count -gt $parts.Count) {
            $text += " (+$($grants.Count - $parts.Count) more low-privilege grant(s) not shown)"
        }
        return $text
    }

    # --- OS build, used only to explain an ABSENT RequireSignedAppInit_DLLs ------
    $buildNum = -1
    try {
        $cv = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
        if ($cv -and $cv.CurrentBuildNumber) { $buildNum = [int]"$($cv.CurrentBuildNumber)" }
    } catch { $buildNum = -1 }

    # --- Secure Boot. Unknown stays unknown and never lowers a severity ----------
    # $null = could not determine (BIOS machine, cmdlet absent, access denied).
    $secureBoot = $null
    if (Get-Command Confirm-SecureBootUEFI -ErrorAction SilentlyContinue) {
        try { $secureBoot = [bool](Confirm-SecureBootUEFI -ErrorAction Stop) } catch { $secureBoot = $null }
    }
    $sbText = 'unknown'
    if ($secureBoot -eq $true)  { $sbText = 'on' }
    if ($secureBoot -eq $false) { $sbText = 'off' }

    # --- Registry views ---------------------------------------------------------
    # On a 64-bit OS the native key and WOW6432Node govern 64-bit and 32-bit
    # processes independently, so both are read. On a 32-bit OS both views resolve
    # to the same physical key, so only one is read -- otherwise every finding would
    # be emitted twice.
    $views = @()
    $is64 = $false
    try { $is64 = [System.Environment]::Is64BitOperatingSystem } catch { $is64 = $false }
    if ($is64) {
        $views += @{ Label = '64-bit view'; View = [Microsoft.Win32.RegistryView]::Registry64 }
        $views += @{ Label = '32-bit view (WOW6432Node)'; View = [Microsoft.Win32.RegistryView]::Registry32 }
    } else {
        $views += @{ Label = '32-bit OS (single view)'; View = [Microsoft.Win32.RegistryView]::Default }
    }

    $anyKeyRead   = $false
    $anyConfigured = $false
    # Which views were actually opened. A clean result must name only the views it
    # really read: claiming "empty in 64-bit view, 32-bit view" when the second view
    # was denied is exactly the silence-mistaken-for-clean case this check exists to
    # avoid.
    $readLabels   = @()
    $unreadLabels = @()

    foreach ($v in $views) {
        $baseKey = $null
        $winKey  = $null
        try {
            $baseKey = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $v.View)
            $winKey  = $baseKey.OpenSubKey('SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows')
        } catch {
            $winKey = $null
        }
        if (-not $winKey) {
            if ($baseKey) { try { $baseKey.Dispose() } catch { } }
            $unreadLabels += $v.Label
            continue
        }
        $anyKeyRead = $true
        $readLabels += $v.Label

        $keyPath = "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows ($($v.Label))"

        $rawAppInit = ''
        $loadFlag   = -1
        $reqRaw     = $null
        try { $rawAppInit = "$($winKey.GetValue('AppInit_DLLs'))" } catch { $rawAppInit = '' }
        try {
            $lv = $winKey.GetValue('LoadAppInit_DLLs')
            if ($null -ne $lv) { $loadFlag = [int]$lv }
        } catch { $loadFlag = -1 }
        try { $reqRaw = $winKey.GetValue('RequireSignedAppInit_DLLs') } catch { $reqRaw = $null }

        try { $winKey.Dispose() } catch { }
        if ($baseKey) { try { $baseKey.Dispose() } catch { } }

        $entries = @(Split-TcpkAppInitValue -Raw $rawAppInit)
        if (-not $entries.Count) { continue }
        $anyConfigured = $true

        $entryCount   = $entries.Count
        $sampleEntries = @($entries | Select-Object -First $maxEntries)

        # Effective signing requirement. Explicit value wins; an absent value is an
        # OS default, and that inference is carried into the finding confidence.
        $reqEffective = -1
        $reqSource    = 'unknown (RequireSignedAppInit_DLLs absent and OS build unreadable)'
        $reqInferred  = $false
        if ($null -ne $reqRaw) {
            try { $reqEffective = [int]$reqRaw } catch { $reqEffective = -1 }
            $reqSource = "explicit value $reqEffective"
        } elseif ($buildNum -ge 9200) {
            $reqEffective = 1
            $reqInferred  = $true
            $reqSource    = "absent; OS default 1 on build $buildNum (Windows 8+)"
        } elseif ($buildNum -gt 0) {
            $reqEffective = 0
            $reqInferred  = $true
            $reqSource    = "absent; OS default 0 on build $buildNum (Windows 7 and earlier)"
        }

        # Resolve entries once; reused by the writability pass below.
        $resolvedRecords = @()
        foreach ($e in $sampleEntries) {
            $resolvedRecords += [pscustomobject]@{
                Entry    = $e
                Resolved = (Resolve-TcpkAppInitEntry -Entry $e)
            }
        }
        $unrooted = @($resolvedRecords | Where-Object { -not $_.Resolved })

        # Severity for the configured-key finding.
        #   LoadAppInit_DLLs = 0  -> listed but not loaded, so LOW.
        #   Loaded            -> MEDIUM.
        #   Loaded, signing not required -> HIGH: any unsigned DLL is accepted.
        $sev = 'LOW'
        if ($loadFlag -eq 1) { $sev = 'MEDIUM' }
        if ($loadFlag -eq 1 -and $reqEffective -eq 0) { $sev = 'HIGH' }

        # FP guard: with Secure Boot on, Windows 8+ ignores AppInit_DLLs entirely.
        # Reporting HIGH on a mechanism the firmware has switched off is wrong, so
        # the ceiling drops to LOW. Unknown Secure Boot state changes nothing.
        $sbNote = "Secure Boot: $sbText."
        if ($secureBoot -eq $true) {
            $sev = 'LOW'
            $sbNote = 'Secure Boot is ON, so Windows 8+ ignores AppInit_DLLs entirely; severity is capped for that reason.'
        }

        $conf = 'Confirmed'
        if ($reqInferred -and $loadFlag -eq 1) { $conf = 'Inferred' }

        # An absent LoadAppInit_DLLs means 0, i.e. the list is configured but nothing
        # is loaded from it. Spell that out rather than printing the -1 sentinel.
        $loadText = "$loadFlag"
        if ($loadFlag -lt 0) { $loadText = 'absent (OS default 0, list not loaded)' }

        # Title is bounded: a hostile value could otherwise put kilobytes into it.
        $entryText = ($sampleEntries -join ' | ')
        if ($entryText.Length -gt 120) { $entryText = $entryText.Substring(0, 120) + '...' }

        # Evidence carries the raw value, but bounded: a registry string can be very
        # large and the exact entry count above is what the severity was decided from.
        $rawShown = $rawAppInit
        if ($rawShown.Length -gt 512) { $rawShown = $rawShown.Substring(0, 512) + '... (truncated)' }

        $ev = "AppInit_DLLs=$rawShown; entries=$entryCount (showing $($sampleEntries.Count)); " +
              "LoadAppInit_DLLs=$loadText; RequireSignedAppInit_DLLs: $reqSource; SecureBoot=$sbText"
        if ($unrooted.Count) {
            # Bounded for the same reason as the raw value above: each unresolved entry
            # is attacker-influenced text straight out of the registry.
            $unrootedText = (($unrooted | ForEach-Object { $_.Entry }) -join ', ')
            if ($unrootedText.Length -gt 512) { $unrootedText = $unrootedText.Substring(0, 512) + '... (truncated)' }
            $ev += "; unresolved ($($unrooted.Count) of $($sampleEntries.Count) shown entries are not rooted paths, " +
                   "resolved by DLL search order at load time): $unrootedText"
        }

        New-TcpkFinding -Module 'os' -RuleId 'appinit.configured' `
            -Severity $sev -Confidence $conf `
            -Title "AppInit_DLLs is populated ($($v.Label)): $entryText" `
            -File $keyPath -Evidence $ev `
            -Cwe @('CWE-426', 'CWE-427') `
            -Description ('AppInit_DLLs lists DLLs that Windows loads into every process linking ' +
                'user32.dll, which includes the audited application. ' + $sbNote + ' ' +
                'This is MACHINE STATE, NOT A DEFECT IN THE AUDITED APPLICATION: writing this key ' +
                'requires administrative rights, the mechanism is deprecated by Microsoft, and the ' +
                'application vendor cannot remove the entry or defend against it. It is reported ' +
                'because a populated key means the target process is being injected on this host. ' +
                'Treat an entry nobody deliberately installed as a compromise indicator. This check ' +
                'reads the registry only; it does not prove the DLL was mapped into a live process.') `
            -Fix 'Identify the owner of each listed DLL. If it is not an expected product, clear AppInit_DLLs and investigate how it was set. Otherwise set LoadAppInit_DLLs to 0 and RequireSignedAppInit_DLLs to 1; Microsoft has deprecated this mechanism.'

        foreach ($rec in $resolvedRecords) {
            $resolved = $rec.Resolved
            if (-not $resolved) { continue }

            # VENDOR-REPORTABLE half: the audited application registered itself as a
            # global injection point.
            if (Test-TcpkAppInitVendorOwned -Resolved $resolved -Entry $rec.Entry -AppDir $appDir -Terms $terms) {
                New-TcpkFinding -Module 'os' -RuleId 'appinit.app-registers-dll' `
                    -Severity 'HIGH' -Confidence 'Confirmed' `
                    -Title "Audited application registers a global AppInit_DLLs hook: $resolved" `
                    -File $keyPath -Evidence "AppInit_DLLs entry '$($rec.Entry)' resolves to $resolved, inside the audited application scope; LoadAppInit_DLLs=$loadText" `
                    -Cwe @('CWE-426', 'CWE-427') `
                    -Description ('Unlike the other findings from this check, this one IS attributable to ' +
                        'the application vendor. The application ships a DLL that is registered in ' +
                        'AppInit_DLLs, so Windows loads vendor code into every process on the machine ' +
                        'that links user32.dll. Any memory-safety or load-order defect in that DLL ' +
                        'becomes a machine-wide defect, and the DLL''s own file and directory ACLs ' +
                        'become a machine-wide code-execution surface.') `
                    -Fix 'Remove the AppInit_DLLs registration. Microsoft deprecated this mechanism; use a supported hooking or detours model scoped to the processes that actually need it.'
            }

            # Writability. Missing file plus writable parent is the plant case and
            # is reported with that distinction visible in the evidence.
            $grantText = ''
            $subject   = ''
            $mode      = ''
            if (Test-Path -LiteralPath $resolved) {
                $grantText = _PlantGrants $resolved
                $subject   = $resolved
                $mode      = 'file can be replaced'
            } else {
                $parent = ''
                try { $parent = [System.IO.Path]::GetDirectoryName($resolved) } catch { $parent = '' }
                if ($parent) {
                    $grantText = _PlantGrants $parent
                    $subject   = $parent
                    $mode      = 'file is absent and the parent directory accepts new files, so the DLL can be planted'
                }
            }
            if (-not $grantText) { continue }

            $wsev = 'HIGH'
            # Same Secure Boot guard: if the loader ignores AppInit_DLLs, a writable
            # entry is not a live injection path on this host.
            if ($secureBoot -eq $true) { $wsev = 'MEDIUM' }
            if ($loadFlag -ne 1) { $wsev = 'MEDIUM' }

            $wtitle = "AppInit_DLLs entry can be replaced by a low-privileged group: $resolved"
            if ($subject -ne $resolved) { $wtitle = "AppInit_DLLs entry is missing and can be planted by a low-privileged group: $resolved" }

            New-TcpkFinding -Module 'os' -RuleId 'appinit.dll-writable' `
                -Severity $wsev -Confidence 'Confirmed' `
                -Title $wtitle `
                -File $subject `
                -Evidence "AppInit_DLLs entry '$($rec.Entry)' -> $resolved; $mode; grants on ${subject}: $grantText; LoadAppInit_DLLs=$loadText; SecureBoot=$sbText" `
                -Cwe @('CWE-732', 'CWE-427') `
                -Description ('A DLL registered for machine-wide injection sits at a path a ' +
                    'low-privileged group can write. That converts an admin-only configuration into ' +
                    'a non-admin code-execution primitive: an unprivileged user replaces or plants ' +
                    'the file and Windows loads their code into every user32-linked process, ' +
                    'including elevated ones and including the audited application. Deny ACEs are ' +
                    'not evaluated by this check.') `
                -Fix 'Restrict the DLL and its directory to SYSTEM and Administrators, or remove the AppInit_DLLs registration entirely.'
        }
    }

    # --- AppCertDlls ------------------------------------------------------------
    # Loaded into every process that calls the CreateProcess family. Not gated by
    # Secure Boot and not gated by a Load flag, so a populated key is always live.
    # No WOW6432Node redirection applies to HKLM\SYSTEM.
    $acPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls'
    $smPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
    $acKeyRead = $false
    $acValues = @()
    if (Test-Path -LiteralPath $acPath) {
        $acKeyRead = $true
        $props = $null
        try { $props = Get-ItemProperty -LiteralPath $acPath -ErrorAction Stop } catch { $acKeyRead = $false }
        # Exact note-property names rather than a 'PS*' wildcard: a registry value
        # legitimately named PSHook would otherwise be silently dropped.
        $psNoise = @('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider')
        if ($props) {
            foreach ($p in $props.PSObject.Properties) {
                if ($psNoise -contains $p.Name) { continue }
                if (-not "$($p.Value)") { continue }
                $acValues += [pscustomobject]@{ Name = $p.Name; Value = "$($p.Value)" }
            }
        }
    } elseif (Test-Path -LiteralPath $smPath) {
        # Parent is readable and the subkey genuinely does not exist. That is the
        # Windows default, and it is a successful read rather than a failure.
        # Test-Path alone cannot tell "absent" from "denied", hence the parent probe.
        $acKeyRead = $true
    }

    $acTotal = $acValues.Count
    foreach ($ac in ($acValues | Select-Object -First $maxEntries)) {
        $anyConfigured = $true
        $acResolved = Resolve-TcpkAppInitEntry -Entry $ac.Value

        $acGrants = ''
        $acSubject = ''
        if ($acResolved) {
            if (Test-Path -LiteralPath $acResolved) {
                $acGrants = _PlantGrants $acResolved
                $acSubject = $acResolved
            } else {
                $acParent = ''
                try { $acParent = [System.IO.Path]::GetDirectoryName($acResolved) } catch { $acParent = '' }
                if ($acParent) {
                    $acGrants = _PlantGrants $acParent
                    $acSubject = $acParent
                }
            }
        }

        $acSev = 'MEDIUM'
        if ($acGrants) { $acSev = 'HIGH' }

        # Same bound as the AppInit raw value: a REG_SZ can hold ~1 MB and a hostile
        # or corrupt one must not be copied wholesale into the finding.
        $acRawShown = "$($ac.Value)"
        if ($acRawShown.Length -gt 512) { $acRawShown = $acRawShown.Substring(0, 512) + '... (truncated)' }
        $acResolvedShown = $acResolved
        if (-not $acResolvedShown) { $acResolvedShown = '(not a rooted path)' }
        elseif ($acResolvedShown.Length -gt 512) { $acResolvedShown = $acResolvedShown.Substring(0, 512) + '... (truncated)' }

        # A registry value NAME is attacker-influenced too and can be thousands of
        # characters, so it is bounded before it reaches the title or the evidence.
        $acName = "$($ac.Name)"
        if ($acName.Length -gt 120) { $acName = $acName.Substring(0, 120) + '...' }

        $acEv = "$acName=$acRawShown; resolved=$acResolvedShown; values-in-key=$acTotal (processing at most $maxEntries)"
        if ($acGrants) { $acEv += "; low-privilege grants on ${acSubject}: $acGrants" }
        if ($acResolved -and -not (Test-Path -LiteralPath $acResolved)) { $acEv += '; file absent (plantable if the directory is writable)' }
        if (-not $acResolved) { $acEv += '; entry is not a rooted path, so it is resolved by the DLL search order at load time and was not ACL-checked' }

        # Title is bounded for the same reason as the AppInit one.
        $acShown = "$($ac.Value)"
        if ($acShown.Length -gt 120) { $acShown = $acShown.Substring(0, 120) + '...' }

        $acVendor = (Test-TcpkAppInitVendorOwned -Resolved $acResolved -Entry $ac.Value -AppDir $appDir -Terms $terms)
        $acDesc = ('AppCertDlls lists DLLs that Windows loads into every process that calls the ' +
            'CreateProcess family. Unlike AppInit_DLLs this is not disabled by Secure Boot and has ' +
            'no enable flag, so a populated value is live. This is MACHINE STATE, NOT A DEFECT IN ' +
            'THE AUDITED APPLICATION: the key requires administrative rights to write and the ' +
            'application vendor cannot remove or defend against the entry. It is reported because ' +
            'it means the target process is being injected on this host, and because the key is ' +
            'empty on a default Windows install, so any value is worth explaining. This check reads ' +
            'the registry only; it does not prove the DLL was mapped into a live process.')
        if ($acVendor) {
            $acDesc = ('The audited application registered its own DLL in AppCertDlls, so Windows ' +
                'loads vendor code into every process on this machine that calls the CreateProcess ' +
                'family. This one IS attributable to the vendor: any defect in that DLL, or a weak ' +
                'ACL on it, becomes a machine-wide code-execution surface. This check reads the ' +
                'registry only; it does not prove the DLL was mapped into a live process.')
            $acSev = 'HIGH'
        }

        New-TcpkFinding -Module 'os' -RuleId 'appcert.configured' `
            -Severity $acSev -Confidence 'Confirmed' `
            -Title "AppCertDlls is populated: $acName -> $acShown" `
            -File 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls' `
            -Evidence $acEv `
            -Cwe @('CWE-426', 'CWE-427') `
            -Description $acDesc `
            -Fix 'Identify the owner of the DLL. If it is not an expected product, remove the value and investigate how it was set. If the application registered it, remove the registration and scope the hook to the processes that need it. Where the DLL path is writable by a low-privileged group, restrict it to SYSTEM and Administrators.'
    }

    # --- Could not read something -> say so rather than implying a clean result --
    # Reported whenever EITHER key set was unreadable, because a partial read is
    # exactly the case where silence would be mistaken for a clean machine.
    if (-not $anyKeyRead -or -not $acKeyRead) {
        $unread = @()
        if (-not $anyKeyRead) { $unread += 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows (AppInit_DLLs)' }
        if (-not $acKeyRead)  { $unread += 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDlls' }
        if ($unreadLabels.Count) { $unread += ('AppInit registry view(s): ' + ($unreadLabels -join ', ')) }
        New-TcpkSkippedFinding -RuleId 'appinit.not-readable' `
            -Title 'Global DLL-injection registry keys could not be read' `
            -Reason ("Could not open: " + ($unread -join '; ') + ". Silence from this check does not mean the machine is clean; re-run with rights to read these keys.")
        return
    }

    # --- Clean: record that the check ran and found nothing ----------------------
    if (-not $anyConfigured) {
        # Only the views that were genuinely opened may be claimed as empty. A view
        # that could not be opened is named as NOT covered, and the clean result
        # drops to Inferred, because it then rests on an incomplete read.
        $viewText  = ($readLabels -join ', ')
        $cleanConf = 'Confirmed'
        $cleanEv   = "AppInit_DLLs empty in: $viewText. AppCertDlls values: 0. Secure Boot: $sbText."
        if ($unreadLabels.Count) {
            $cleanConf = 'Inferred'
            $cleanEv += ' NOT covered by this result (view could not be opened): ' + ($unreadLabels -join ', ') + '.'
        }
        New-TcpkFinding -Module 'os' -RuleId 'appinit.clean' `
            -Severity 'INFO' -Confidence $cleanConf `
            -Title 'No AppInit_DLLs or AppCertDlls injection registrations' `
            -File 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows' `
            -Evidence $cleanEv `
            -Cwe @('CWE-426') `
            -Description ('Neither global DLL-injection registration is populated in the registry ' +
                'views this check could read, so the audited process is not being injected through ' +
                'them. Recorded so a silent check is not mistaken for a check that did not run. ' +
                'This describes machine state, not the application. It covers only the views named ' +
                'in the evidence.') `
            -Fix 'No action. Keep LoadAppInit_DLLs at 0 and leave AppCertDlls empty.'
    }
}

# Module-scope helpers for Test-TcpkAppInitDlls. Not exported (the module exports only
# the function whose name matches the file), but reachable from the test suite through
# the module scope so the false-positive boundaries below can be tested directly
# instead of via a registry key no test is allowed to write.

# AppInit_DLLs is historically a SPACE-delimited list; newer builds also accept commas.
# Splitting a space-delimited value blindly destroys any path containing a space
# ("C:\Program Files\vendor\hook.dll" would become two bogus entries, and the second
# one would then be ACL-checked against a path that does not exist). So the space split
# is only accepted when EVERY resulting token still ends in .dll. Otherwise the raw
# value is treated as a single entry, which is the reading that cannot invent a path.
function Split-TcpkAppInitValue {
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyString()][string]$Raw)

    $v = "$Raw".Trim()
    if (-not $v) { return @() }
    if ($v.Contains(',')) {
        return @($v -split ',' | ForEach-Object { $_.Trim().Trim('"') } | Where-Object { $_ })
    }
    $tokens = @($v -split '\s+' | Where-Object { $_ })
    if ($tokens.Count -le 1) { return @($v.Trim('"')) }
    foreach ($t in $tokens) {
        if ($t -notmatch '(?i)\.dll"?$') { return @($v.Trim('"')) }
    }
    return @($tokens | ForEach-Object { $_.Trim('"') })
}

# Expand environment variables and return the entry only when it is a ROOTED path.
# A bare name ("evil.dll") is resolved by the loader's own DLL search order at load
# time; this function deliberately returns '' for that case rather than guessing at a
# directory, because guessing would produce an ACL verdict about the wrong file.
function Resolve-TcpkAppInitEntry {
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyString()][string]$Entry)

    $e = "$Entry".Trim().Trim('"').Trim()
    if (-not $e) { return '' }
    $ex = $e
    try { $ex = [System.Environment]::ExpandEnvironmentVariables($e) } catch { $ex = $e }
    $rooted = $false
    try { $rooted = [System.IO.Path]::IsPathRooted($ex) } catch { $rooted = $false }
    if (-not $rooted) { return '' }
    return $ex
}

# Attribution predicate: does this registered DLL belong to the AUDITED APPLICATION
# (vendor-reportable) rather than to the machine (environment state)? True only when the
# path sits underneath the audited install directory, or when the caller supplied
# -NameLike terms and one of them matches the FILE NAME. With neither an install
# directory nor terms this always returns false, which is the correct default: an
# unattributed entry must not be filed against a vendor who did not put it there.
#
# FP guard on the term half: the term is matched against the file name only, never the
# whole path. Matching the whole path escalates an unrelated machine-wide hook to a
# HIGH vendor-reportable finding whenever a term happens to occur in a directory
# component -- "C:\Users\acme\AppData\Local\Temp\hook.dll" under -NameLike 'acme' is a
# user profile name, not evidence that the Acme vendor registered the hook. Anchored
# directory attribution is what -Path is for, and it is checked first.
function Test-TcpkAppInitVendorOwned {
    [CmdletBinding()]
    param(
        [AllowNull()][AllowEmptyString()][string]$Resolved,
        [AllowNull()][AllowEmptyString()][string]$Entry,
        [AllowNull()][AllowEmptyString()][string]$AppDir,
        [AllowNull()][string[]]$Terms = @()
    )

    $text = "$Resolved"
    if (-not $text) { $text = "$Entry" }
    if (-not $text) { return $false }

    if ($AppDir) {
        # StartsWith rather than -like: an install path can legitimately contain
        # [ or ] or ?, which -like would read as wildcard metacharacters. The trailing
        # separator matters too, so "C:\App" does not claim "C:\AppMalware\evil.dll".
        $dirPrefix = $AppDir.TrimEnd('\') + '\'
        if ($text.StartsWith($dirPrefix, [System.StringComparison]::OrdinalIgnoreCase)) { return $true }
    }
    $t = @($Terms | Where-Object { $_ -and $_ -ne '*' })
    if ($t.Count) {
        # File name only. Split on both separators by hand rather than calling
        # [System.IO.Path]::GetFileName: that method throws on invalid path
        # characters under .NET Framework, and under PowerShell Core on Linux it
        # does not treat '\' as a separator, which would make this predicate behave
        # differently in the cross-platform test run than it does on the target.
        $leaf = $text
        $cut  = [Math]::Max($text.LastIndexOf('\'), $text.LastIndexOf('/'))
        if ($cut -ge 0 -and $cut -lt ($text.Length - 1)) { $leaf = $text.Substring($cut + 1) }
        if (Test-TcpkTermMatch -Text $leaf -Terms $t) { return $true }
    }
    return $false
}
