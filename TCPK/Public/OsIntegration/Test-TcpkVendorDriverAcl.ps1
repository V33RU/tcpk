function Test-TcpkVendorDriverAcl {
<#
.SYNOPSIS
    C19. Vendor kernel driver (.sys) attack surface: DACL on the shipped file, the parent
    folder, the service registry key, and INF / installer-script signals that would arm
    the primitive.

.DESCRIPTION
    Test-TcpkKernelDrivers (C14) reports that a .sys is shipped and reports its
    Authenticode status. Test-TcpkInstallDirAcl (C05) reports that an install path is
    user-writable. Test-TcpkServiceBinaryAcl (C18) reports that a service EXE is
    user-writable. None of them combine those three facts on a KERNEL driver: a .sys
    that is a kernel PE AND sitting on a user-writable file or folder AND registered as
    Type 1/2 service is a direct SYSTEM-level LPE at next boot.

    This cmdlet closes that gap. Every rule is gated on the shape check
    driver.kernel-pe-confirmed (real MZ/PE + IMAGE_SUBSYSTEM_NATIVE + at least one
    import resolved against a kernel module) so a .sys extension alone cannot fire it.

    Rules (rule id / severity / confidence):
      driver.kernel-pe-confirmed          INFO    Confirmed  Shape gate: .sys is a real kernel PE
      driver.sys-file-dacl-writable       HIGH    Confirmed  Users/Auth Users write on the .sys itself
      driver.sys-folder-dacl-writable     HIGH    Confirmed  Users/Auth Users write on the parent folder
      driver.service-regkey-dacl-writable HIGH    Confirmed  Users/Auth Users write on Services\<Name>
      driver.imagepath-outside-system32   INFO    Confirmed  Type 1/2 service ImagePath outside System32\drivers
      driver.inf-registers-kernel-service MEDIUM  Confirmed  INF install section registers a boot/system/auto driver
      driver.inf-missing-catalog          MEDIUM  Confirmed  INF Version section names no CatalogFile
      driver.installer-disables-dse       HIGH    Inferred   Shipped script calls 'bcdedit /set testsigning on'
      driver.vendor-known-package         INFO    Confirmed  Basename matches a curated vendor dictionary
      driver.jungo-windriver-shipped      HIGH    Confirmed  windrvr6.sys shipped (Jungo WinDriver, BYOVD staple)

    dangerRights mask (files):
      WriteData (0x2), DeleteSubdirectoriesAndFiles (0x40), Delete (0x10000),
      WriteDac (0x40000), WriteOwner (0x80000), GenericAll (0x10000000),
      GenericWrite (0x40000000)
    Excludes WriteAttributes / WriteEA (commonly granted, not a plant primitive) and
    AppendData/FILE_ADD_SUBDIRECTORY (creates a subfolder, cannot replace the .sys).

.PARAMETER Path
    Install directory or a single .sys file.

.PARAMETER NameLike
    Optional. Vendor / product substring for matching an installed service in
    HKLM\SYSTEM\CurrentControlSet\Services when the .sys basename does not match
    any registered service.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [string[]]$NameLike
    )

    if (-not (Assert-TcpkWindows 'Test-TcpkVendorDriverAcl')) { return }
    if (-not (Test-Path -LiteralPath $Path)) { return }

    # ---- file rights mask -----------------------------------------------------------
    # Reused verbatim from Test-TcpkRegistryLoadPoints.ps1:155-165 rationale. Excludes
    # WriteAttributes / WriteEA (not a plant primitive) and AppendData (FILE_ADD_SUBDIRECTORY
    # on a directory).
    $fileDangerMask =
        0x00000002 -bor 0x00000040 -bor 0x00010000 -bor
        0x00040000 -bor 0x00080000 -bor 0x10000000 -bor 0x40000000

    # ---- registry rights mask -------------------------------------------------------
    # SetValue (0x2), CreateSubKey (0x4), Delete (0x10000), ChangePermissions (0x40000),
    # TakeOwnership (0x80000), plus generic bits that might survive an unmapped SDDL.
    # Deliberately excludes QueryValues (0x1), EnumerateSubKeys (0x8), Notify (0x10),
    # ReadPermissions (0x20000) - all read-only. Do NOT AND against FullControl (0xF003F);
    # that value includes the read-only bits and would fire on any ReadKey ACE.
    $regDangerMask =
        0x00000002 -bor 0x00000004 -bor 0x00010000 -bor
        0x00040000 -bor 0x00080000 -bor 0x10000000 -bor 0x40000000

    # ---- risky principals -----------------------------------------------------------
    # Compare on both the friendly name (locale-dependent) and the SID (portable).
    $riskySids = @(
        'S-1-1-0',      # Everyone
        'S-1-5-11',     # Authenticated Users
        'S-1-5-32-545', # BUILTIN\Users
        'S-1-5-4',      # INTERACTIVE
        'S-1-5-32-547'  # BUILTIN\Power Users
    )
    $riskyNameRx = '(?i)\b(Everyone|Authenticated Users|Users|INTERACTIVE|BUILTIN\\(Users|Power Users))\b'

    function _AceIsRisky([Security.AccessControl.AccessRule]$ace, [int]$mask) {
        if ($ace.AccessControlType -ne 'Allow') { return $false }
        $id = $null
        try { $id = $ace.IdentityReference } catch { return $false }
        $sid = $null
        try {
            if ($id -is [Security.Principal.SecurityIdentifier]) { $sid = $id.Value }
            else { $sid = ($id.Translate([Security.Principal.SecurityIdentifier])).Value }
        } catch { }
        $matched = $false
        if ($sid -and ($riskySids -contains $sid)) { $matched = $true }
        elseif ($id.Value -match $riskyNameRx)      { $matched = $true }
        if (-not $matched) { return $false }
        # Right property differs: FileSystemRights on files, RegistryRights on registry.
        $rightsVal = 0
        try {
            if ($ace.PSObject.Properties['FileSystemRights']) { $rightsVal = [int]$ace.FileSystemRights }
            elseif ($ace.PSObject.Properties['RegistryRights']) { $rightsVal = [int]$ace.RegistryRights }
        } catch { }
        return (($rightsVal -band $mask) -ne 0)
    }

    # ---- vendor driver dictionary ---------------------------------------------------
    # basename (lower) -> vendor label. Curated from vendor INF and driver-catalog sources.
    # Deliberately excludes in-box Windows drivers (winusb.sys, usbser.sys) which are the OS.
    $vendorDict = @{
        'silabser.sys'      = 'Silicon Labs CP210x USB-to-UART'
        'cp210xvcp.sys'     = 'Silicon Labs CP210x VCP'
        'ch34xser.sys'      = 'WCH CH340/CH341 USB-to-UART'
        'ch341ser.sys'      = 'WCH CH341 USB-to-UART'
        'ch341s64.sys'      = 'WCH CH341 USB-to-UART (x64)'
        'ftdibus.sys'       = 'FTDI D2XX bus'
        'ftser2k.sys'       = 'FTDI VCP'
        'stlink.sys'        = 'STMicroelectronics ST-LINK'
        'st-link_dbg.sys'   = 'STMicroelectronics ST-LINK debugger'
        'jlinkcdc.sys'      = 'Segger J-Link CDC'
        'jlink_x86_x64_usb.sys' = 'Segger J-Link USB (x86/x64)'
        'jlinkwinusb.sys'   = 'Segger J-Link WinUSB'
        'nrfconnect.sys'    = 'Nordic nRF Connect'
        'mchpcdc.sys'       = 'Microchip CDC'
        'atmelusb.sys'      = 'Atmel USB'
        'rzudd.sys'         = 'Razer devices (BYOVD known)'
        'asusio.sys'        = 'ASUS Aura Sync IO (BYOVD known)'
        'gdrv.sys'          = 'Gigabyte AORUS (BYOVD known)'
        'iomap64.sys'       = 'MSI Live Update (BYOVD known)'
    }

    # ---- enumerate .sys candidates --------------------------------------------------
    $sysFiles = @()
    try {
        $item = Get-Item -LiteralPath $Path -ErrorAction Stop
        if ($item.PSIsContainer) {
            $sysFiles = @(Get-ChildItem -LiteralPath $Path -Recurse -File -Filter '*.sys' -ErrorAction SilentlyContinue)
        } elseif ($item.Extension -ieq '.sys') {
            $sysFiles = @($item)
        }
    } catch { }

    $seenFolders = @{}
    $kernelSysConfirmed = New-Object 'System.Collections.Generic.List[object]'

    foreach ($s in $sysFiles) {
        # ---- shape gate --------------------------------------------------------------
        $pe = $null
        try { $pe = Read-TcpkPe -Path $s.FullName } catch { }
        if (-not $pe) { continue }
        $peInfo = $null
        try { $peInfo = Get-TcpkPeInfo -Path $s.FullName } catch { }
        $subsystem = if ($peInfo) { "$($peInfo.Subsystem)" } else { '' }
        if ($subsystem -notmatch '(?i)Native') { continue }
        # Import corroboration: at least one import from a kernel module.
        $kernelImports = @('ntoskrnl.exe','hal.dll','wdfldr.sys','storport.sys','netio.sys','ndis.sys','fltmgr.sys','ksecdd.sys')
        $importedFrom  = @()
        foreach ($imp in $pe.Imports) {
            $mod = "$($imp.Module)".ToLowerInvariant()
            if ($kernelImports -contains $mod) { $importedFrom += $mod }
        }
        if ($importedFrom.Count -eq 0) { continue }

        $kernelSysConfirmed.Add($s) | Out-Null

        # ---- driver.kernel-pe-confirmed ---------------------------------------------
        New-TcpkFinding -Module 'os' -RuleId 'driver.kernel-pe-confirmed' `
            -Severity 'INFO' -Confidence 'Confirmed' `
            -Title "Kernel PE confirmed: $($s.Name) (Subsystem=Native, imports $(($importedFrom | Select-Object -Unique) -join ','))" `
            -File $s.FullName -Evidence "Subsystem=Native; kernel imports=$(($importedFrom | Select-Object -Unique) -join ',')" `
            -Description ("Shape gate for the driver.* rules. The .sys is a real kernel-mode PE " +
                "(MZ/PE header valid, IMAGE_SUBSYSTEM_NATIVE, at least one import resolves against " +
                "ntoskrnl / hal / wdfldr / storport / netio / ndis / fltmgr / ksecdd). Other rules " +
                "under this cmdlet only apply to files that clear this gate.") `
            -Fix 'No fix required. This finding scopes the DACL rules that follow.'

        # ---- driver.sys-file-dacl-writable ------------------------------------------
        try {
            $acl = Get-Acl -LiteralPath $s.FullName -ErrorAction Stop
            $bad = @($acl.Access | Where-Object { _AceIsRisky $_ $fileDangerMask })
            if ($bad.Count -gt 0) {
                $grant = ($bad | ForEach-Object { "$($_.IdentityReference) -> $($_.FileSystemRights) (inherited=$($_.IsInherited))" } | Select-Object -First 4) -join '; '
                New-TcpkFinding -Module 'os' -RuleId 'driver.sys-file-dacl-writable' `
                    -Severity 'HIGH' -Confidence 'Confirmed' `
                    -Title "Kernel driver is non-admin writable: $($s.Name)" `
                    -File $s.FullName -Evidence $grant `
                    -Cwe @('CWE-732','CWE-1188','CWE-427') `
                    -Description ("A confirmed kernel .sys carries an Allow ACE granting a non-admin principal " +
                        "(Users / Authenticated Users / Everyone / INTERACTIVE) one of the file rights that permit " +
                        "replacing the file bytes (WriteData, DeleteSubdirectoriesAndFiles on the parent, Delete, " +
                        "WriteDac, WriteOwner, GenericAll, GenericWrite). An attacker replaces the bytes; at next " +
                        "boot the modified driver loads with kernel privileges. WriteAttributes and AppendData are " +
                        "excluded from the mask because they do not permit a swap.") `
                    -Fix 'Restrict the .sys DACL to admin-only write (SYSTEM + BUILTIN\Administrators). Remove explicit grants to Users / Authenticated Users; inherit from a protected parent (e.g. Program Files) rather than declaring an explicit ACE.'
            }
        } catch { }

        # ---- driver.sys-folder-dacl-writable ----------------------------------------
        $dir = Split-Path -Parent $s.FullName
        if ($dir -and -not $seenFolders.ContainsKey($dir.ToLowerInvariant())) {
            $seenFolders[$dir.ToLowerInvariant()] = $true
            try {
                $facl = Get-Acl -LiteralPath $dir -ErrorAction Stop
                $badF = @($facl.Access | Where-Object { _AceIsRisky $_ $fileDangerMask })
                if ($badF.Count -gt 0) {
                    $grant = ($badF | ForEach-Object { "$($_.IdentityReference) -> $($_.FileSystemRights) (inherited=$($_.IsInherited))" } | Select-Object -First 4) -join '; '
                    New-TcpkFinding -Module 'os' -RuleId 'driver.sys-folder-dacl-writable' `
                        -Severity 'HIGH' -Confidence 'Confirmed' `
                        -Title "Parent folder of a kernel driver is non-admin writable: $(Split-Path -Leaf $dir)" `
                        -File $dir -Evidence "$grant | child driver: $($s.Name)" `
                        -Cwe @('CWE-732','CWE-1188','CWE-427') `
                        -Description ("The directory that hosts a confirmed kernel .sys carries an Allow ACE " +
                            "granting a non-admin principal write on the folder. FILE_ADD_FILE (WriteData) OR " +
                            "FILE_DELETE_CHILD (DeleteSubdirectoriesAndFiles) is enough to swap the driver even " +
                            "when the .sys DACL itself would refuse: the attacker deletes the driver and drops a " +
                            "replacement with a new DACL. IsInherited is recorded so a maintainer can trace whether " +
                            "the noise came from a broad parent grant.") `
                        -Fix 'Restrict the folder to admin-only write. If the grant is inherited, fix the closest ancestor rather than adding a deny ACE.'
                }
            } catch { }
        }

        # ---- driver.jungo-windriver-shipped -----------------------------------------
        if ($s.Name.ToLowerInvariant() -eq 'windrvr6.sys') {
            $version = $null
            try { $version = (Get-Item -LiteralPath $s.FullName).VersionInfo.CompanyName } catch { }
            New-TcpkFinding -Module 'os' -RuleId 'driver.jungo-windriver-shipped' `
                -Severity 'HIGH' -Confidence 'Confirmed' `
                -Title "Jungo WinDriver (windrvr6.sys) shipped in the install tree" `
                -File $s.FullName -Evidence "windrvr6.sys; CompanyName=$version" `
                -Cwe @('CWE-1188','CWE-782') `
                -Description ("windrvr6.sys is Jungo WinDriver. Historically it exposes broad IOCTL primitives " +
                    "(arbitrary physical memory read/write, arbitrary MSR / port I/O) that map directly to " +
                    "SYSTEM privilege escalation and DKOM. It has been catalogued in BYOVD lists for years. " +
                    "Bundling it with an application widens the local attack surface even when the app itself " +
                    "does not need those primitives.") `
                -Fix 'Remove windrvr6.sys and re-architect around a purpose-built minimal driver, or a user-mode driver framework (UMDF). If it must ship, restrict its device object DACL to a specific account and remove all not-needed IOCTLs.'
        }

        # ---- driver.vendor-known-package --------------------------------------------
        $baseLower = $s.Name.ToLowerInvariant()
        if ($vendorDict.ContainsKey($baseLower)) {
            New-TcpkFinding -Module 'os' -RuleId 'driver.vendor-known-package' `
                -Severity 'INFO' -Confidence 'Confirmed' `
                -Title "Vendor driver identified: $($s.Name) - $($vendorDict[$baseLower])" `
                -File $s.FullName -Evidence "basename match: $baseLower -> $($vendorDict[$baseLower])" `
                -Description ("The .sys basename matches an entry in the TCPK vendor dictionary. This is scope " +
                    "information: it names the vendor toolchain the app depends on, so a tester knows which " +
                    "IOCTL surface (and public advisories) to review. Basename match alone does not imply " +
                    "vulnerability.") `
                -Fix 'Track the vendor driver in the SBOM and monitor the vendor advisory feed. If the driver is on a public BYOVD list, replace it.'
        }
    }

    if ($kernelSysConfirmed.Count -eq 0) { }  # nothing else to check that depends on a real driver being present

    # ---- INF-based rules ------------------------------------------------------------
    # Static parse of every INF under the install tree. Cheap: INFs are small.
    $infs = @()
    try {
        $infs = @(Get-ChildItem -LiteralPath $Path -Recurse -File -Filter '*.inf' -ErrorAction SilentlyContinue)
    } catch { }

    foreach ($inf in $infs) {
        $infText = $null
        try { $infText = [IO.File]::ReadAllText($inf.FullName) } catch { continue }
        if (-not $infText) { continue }

        # driver.inf-registers-kernel-service
        # Correlate ServiceType and StartType INSIDE THE SAME section body. INF service-install
        # sections are usually named [*_Service_Inst], but any [Name] block that carries both
        # a ServiceType kernel/fs value AND a StartType is a real install directive. Split the
        # INF into sections and evaluate each.
        $sections = [regex]::Matches($infText, '(?ms)^\s*\[([^\]\r\n]+)\]\s*\r?\n(.*?)(?=^\s*\[[^\]\r\n]+\]|\z)')
        $reportedSection = $false
        foreach ($sec in $sections) {
            if ($reportedSection) { break }
            $secName = $sec.Groups[1].Value.Trim()
            $secBody = $sec.Groups[2].Value
            $svcM   = [regex]::Match($secBody, '(?im)^\s*ServiceType\s*=\s*(1|2|SERVICE_KERNEL_DRIVER|SERVICE_FILE_SYSTEM_DRIVER)\s*(;.*)?$')
            $startM = [regex]::Match($secBody, '(?im)^\s*StartType\s*=\s*(0|1|2|3|SERVICE_BOOT_START|SERVICE_SYSTEM_START|SERVICE_AUTO_START|SERVICE_DEMAND_START)\s*(;.*)?$')
            if ($svcM.Success -and $startM.Success) {
                $startVal = $startM.Groups[1].Value
                $isDemand = ($startVal -eq '3' -or $startVal -eq 'SERVICE_DEMAND_START')
                $sev = if ($isDemand) { 'LOW' } else { 'MEDIUM' }
                New-TcpkFinding -Module 'os' -RuleId 'driver.inf-registers-kernel-service' `
                    -Severity $sev -Confidence 'Confirmed' `
                    -Title "INF registers a kernel driver: $($inf.Name) [$secName] (StartType=$startVal)" `
                    -File $inf.FullName -Evidence "[$secName] ServiceType=$($svcM.Groups[1].Value); StartType=$startVal" `
                    -Cwe @('CWE-1188') `
                    -Description ("The INF section [$secName] carries both a kernel/file-system ServiceType " +
                        "and a StartType. StartType 0 (Boot), 1 (System) or 2 (Auto) loads at every boot with " +
                        "SYSTEM privilege; StartType 3 (Demand) requires a trigger and is a lower-impact case.") `
                    -Fix 'If a kernel driver is not strictly required, ship a user-mode alternative. If it is, restrict install to admin, sign with WHQL, and set the narrowest StartType that fits the use case.'
                $reportedSection = $true
            }
        }

        # driver.inf-missing-catalog
        $verSection = [regex]::Match($infText, '(?is)\[Version\](.*?)(\r?\n\[|\z)')
        if ($verSection.Success) {
            $verBody = $verSection.Groups[1].Value
            if ($verBody -notmatch '(?im)^\s*CatalogFile\s*=') {
                New-TcpkFinding -Module 'os' -RuleId 'driver.inf-missing-catalog' `
                    -Severity 'MEDIUM' -Confidence 'Confirmed' `
                    -Title "INF names no CatalogFile: $($inf.Name)" `
                    -File $inf.FullName -Evidence "[Version] section has no CatalogFile= directive" `
                    -Cwe @('CWE-347') `
                    -Description ("The INF's [Version] section does not name a CatalogFile. A driver package " +
                        "without a .cat cannot be authenticode-verified as a package on install (Windows may " +
                        "warn / refuse depending on OS release and SecureBoot policy). Missing catalog is also " +
                        "consistent with a self-signed / dev-only package that was shipped by accident.") `
                    -Fix 'Add CatalogFile=<name>.cat to [Version] and ship the signed .cat alongside the .sys.'
            } else {
                # Optional: catalog named but missing on disk
                $catName = [regex]::Match($verBody, '(?im)^\s*CatalogFile\s*=\s*([^\s;]+)').Groups[1].Value
                if ($catName) {
                    $catPath = Join-Path $inf.Directory.FullName $catName
                    if (-not (Test-Path -LiteralPath $catPath)) {
                        New-TcpkFinding -Module 'os' -RuleId 'driver.inf-missing-catalog' `
                            -Severity 'MEDIUM' -Confidence 'Confirmed' `
                            -Title "INF references a CatalogFile that is not shipped: $($inf.Name) -> $catName" `
                            -File $inf.FullName -Evidence "CatalogFile=$catName; not found next to INF" `
                            -Cwe @('CWE-347') `
                            -Description ("The INF names a CatalogFile but the .cat is not present next to the INF. " +
                                "Install-time signature verification will fail and Windows will fall back to " +
                                "unsigned-driver policy for the release.") `
                            -Fix 'Ship the named .cat alongside the INF.'
                    }
                }
            }
        }
    }

    # ---- driver.installer-disables-dse ---------------------------------------------
    # Grep every shipped .ps1/.bat/.cmd/.vbs/.js/.iss for a bcdedit call that flips
    # testsigning ON or turns nointegritychecks ON. Note: this is Inferred (script
    # reachability from an installer action is not proven here).
    $scriptExts = @('.ps1','.bat','.cmd','.vbs','.js','.iss','.wxs')
    $scripts = @()
    try {
        $scripts = @(Get-ChildItem -LiteralPath $Path -Recurse -File -ErrorAction SilentlyContinue |
                     Where-Object { $scriptExts -contains $_.Extension.ToLowerInvariant() -and $_.Length -lt 262144 })
    } catch { }
    foreach ($scr in $scripts) {
        $body = $null
        try { $body = [IO.File]::ReadAllText($scr.FullName) } catch { continue }
        if (-not $body) { continue }
        $m = [regex]::Match($body,
            '(?im)bcdedit(\.exe)?\s+.*?/set\s+(TESTSIGNING\s+ON|NOINTEGRITYCHECKS\s+ON|LOADOPTIONS\s+DISABLE_INTEGRITY_CHECKS)')
        if ($m.Success) {
            New-TcpkFinding -Module 'os' -RuleId 'driver.installer-disables-dse' `
                -Severity 'HIGH' -Confidence 'Inferred' `
                -Title "Shipped script disables Driver Signature Enforcement: $($scr.Name)" `
                -File $scr.FullName -Evidence $m.Value.Trim() `
                -Cwe @('CWE-693','CWE-347') `
                -Description ("A script in the install tree calls bcdedit with a switch that turns off " +
                    "Driver Signature Enforcement (TESTSIGNING ON, NOINTEGRITYCHECKS ON, or LOADOPTIONS " +
                    "DISABLE_INTEGRITY_CHECKS). On the host that runs it, any driver (including an attacker's " +
                    "modified copy of the shipped .sys) loads without signature. Inferred because the script may " +
                    "sit under docs/ or samples/ and never be reached by the actual installer.") `
                -Fix 'Delete the bcdedit call. If a driver has to be loaded in test mode during development, do it out-of-band and never ship the script.'
        }
    }

    # ---- driver.service-regkey-dacl-writable + driver.imagepath-outside-system32 ---
    # These need the registry. Cross-reference the shipped .sys basename against
    # HKLM\SYSTEM\CurrentControlSet\Services and evaluate the DACL of the matched key.
    $svcRoot = 'HKLM:\SYSTEM\CurrentControlSet\Services'
    $svcKeys = $null
    try { $svcKeys = @(Get-ChildItem -Path $svcRoot -ErrorAction SilentlyContinue) } catch { }
    if ($svcKeys -and $kernelSysConfirmed.Count -gt 0) {
        $sysBasenames = @($kernelSysConfirmed | ForEach-Object { $_.BaseName.ToLowerInvariant() })
        $terms = @()
        if ($NameLike) { $terms = Get-TcpkNameTerms -NameLike $NameLike }
        foreach ($k in $svcKeys) {
            $keyName = $k.PSChildName
            $keyNameLc = $keyName.ToLowerInvariant()
            $props = $null
            try { $props = Get-ItemProperty -LiteralPath $k.PSPath -ErrorAction Stop } catch { continue }
            if ($props.Type -notin 1,2) { continue }
            # Match: either the service name matches a shipped .sys basename, or NameLike hits.
            $isOurs = ($sysBasenames -contains $keyNameLc)
            if (-not $isOurs -and $terms.Count -and (Test-TcpkTermMatch -Text $keyName -Terms $terms)) { $isOurs = $true }
            if (-not $isOurs) {
                # ImagePath-based fallback: does the ImagePath point INTO the install tree?
                $ip = "$($props.ImagePath)"
                if ($ip) {
                    $ipNorm = ($ip -replace '^\\SystemRoot\\','' -replace '^\\\?\?\\','').ToLowerInvariant()
                    foreach ($base in $sysBasenames) {
                        if ($ipNorm.EndsWith("\$base.sys")) { $isOurs = $true; break }
                    }
                }
            }
            if (-not $isOurs) { continue }

            # DACL check
            $keyAcl = $null
            try { $keyAcl = Get-Acl -LiteralPath $k.PSPath -ErrorAction Stop } catch { }
            if ($keyAcl) {
                $badR = @($keyAcl.Access | Where-Object { _AceIsRisky $_ $regDangerMask })
                if ($badR.Count -gt 0) {
                    $grant = ($badR | ForEach-Object { "$($_.IdentityReference) -> $($_.RegistryRights) (inherited=$($_.IsInherited))" } | Select-Object -First 4) -join '; '
                    New-TcpkFinding -Module 'os' -RuleId 'driver.service-regkey-dacl-writable' `
                        -Severity 'HIGH' -Confidence 'Confirmed' `
                        -Title "Kernel driver service key is non-admin writable: $keyName" `
                        -File ($k.PSPath -replace 'Microsoft\.PowerShell\.Core\\Registry::','') `
                        -Evidence $grant `
                        -Cwe @('CWE-732','CWE-1188') `
                        -Description ("HKLM\SYSTEM\CurrentControlSet\Services\$keyName holds Type=$($props.Type) " +
                            "(1=kernel, 2=file-system driver) and its DACL grants a non-admin principal a right " +
                            "that permits changing the ImagePath (SetValue), the DACL itself (WriteDac), or the " +
                            "owner (WriteOwner). An attacker rewrites ImagePath to point at their own file and " +
                            "loads unsigned code as SYSTEM at next boot.") `
                        -Fix 'Restrict the service key DACL to SYSTEM + BUILTIN\Administrators write. Read for authenticated users if the tooling needs it; do not grant write.'
                }
            }

            # ImagePath outside System32\drivers
            $ip = "$($props.ImagePath)"
            if ($ip) {
                # Normalise \SystemRoot\, \??\C:\, and unquoted-path splits before comparing.
                $ipCanonical = $ip.Trim().Trim('"')
                $ipCanonical = $ipCanonical -replace '^\\SystemRoot\\','C:\Windows\' -replace '^\\\?\?\\',''
                $ipLc = $ipCanonical.ToLowerInvariant()
                $inSystem32 = $ipLc.StartsWith("$($env:SystemRoot)\system32\drivers\".ToLowerInvariant()) -or
                              $ipLc.StartsWith('c:\windows\system32\drivers\')
                if (-not $inSystem32) {
                    New-TcpkFinding -Module 'os' -RuleId 'driver.imagepath-outside-system32' `
                        -Severity 'INFO' -Confidence 'Confirmed' `
                        -Title "Kernel driver service ImagePath outside System32\drivers: $keyName" `
                        -File ($k.PSPath -replace 'Microsoft\.PowerShell\.Core\\Registry::','') `
                        -Evidence "ImagePath=$ip" `
                        -Description ("The service key names a driver image that does not live under " +
                            "%SystemRoot%\System32\drivers. Legitimate for some vendor drivers, but a non-standard " +
                            "location is worth pairing with the folder-DACL rule above: if the containing folder " +
                            "is user-writable, the driver bytes can be swapped without changing the ImagePath.") `
                        -Fix 'If policy allows, move the driver under %SystemRoot%\System32\drivers so the OS-default folder DACL applies.'
                }
            }
        }
    }
}
