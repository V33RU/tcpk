function Test-TcpkComHijack {
<#
.SYNOPSIS
    Detect per-user COM CLSID hijack opportunities.

.DESCRIPTION
    When a thick-client application instantiates COM objects, the OS resolves
    CLSIDs by checking HKCU\Software\Classes\CLSID BEFORE HKLM.  If a CLSID
    is registered in HKLM but NOT in HKCU, any standard user can create their
    own HKCU entry pointing to a malicious DLL -- the next time the application
    creates that COM object it loads the attacker's code.

    This check:
      1. Collects candidate CLSIDs by scanning the raw bytes of each first-party
         PE for GUID-shaped strings, plus GUIDs in shipped .config/.json/.xml/
         .manifest files.  This is a TEXTUAL scan, NOT IL analysis: it does not
         prove the application calls CoCreateInstance on the CLSID, only that
         the GUID appears in the file.  Expect candidates the app never
         instantiates; step 2 filters to those actually registered in HKLM.
      2. For each CLSID registered in HKLM, checks whether HKCU\...\CLSID\{id}
         already exists.  If not, it is hijackable.
      3. Also checks whether the InprocServer32/LocalServer32 binary path
         under HKLM points to a writable location (direct server hijack).
      4. And the case (3) cannot see, because it needs a file to overwrite:
         the class IS registered machine-wide but the image it names is NOT
         on disk, and the path it names is one a standard user can create.
         A dangling registration is the stronger primitive of the two -- it
         takes no registry write at all, and the entry doing the work is the
         vendor's own, already in HKLM and already trusted by every process
         that asks for the class.

    Rules:
      comhijack.per-user-plantable      MEDIUM  HKLM registered, HKCU free to shadow.
      comhijack.server-writable         HIGH    Server image exists and is user-writable.
      comhijack.server-missing-plantable HIGH   Server image absent, path is plantable.
      comhijack.server-missing          INFO    Server image absent, ACL unreadable.

    WHAT THIS DOES NOT PROVE. A planted image runs in whatever process activates the
    class. That is code execution in the activating user's context; it is only
    privilege escalation if some higher-privileged process can be made to activate
    it, and nothing here attempts to establish that. Treat the severity as the
    planting primitive, not a proven privesc chain.

    KNOWN BLIND SPOT. Managed COM servers register mscoree.dll as the server and name
    the real assembly in the Assembly / Class / RuntimeVersion values. mscoree.dll
    always exists, so rule 4 never fires on them and a managed server with a missing
    or plantable assembly is not detected.

    MITRE ATT&CK T1546.015 (Component Object Model Hijacking).

.PARAMETER Path
    File or directory to scan.

.PARAMETER NameLike
    Identity search terms for registry-based COM discovery.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [string[]]$NameLike
    )

    if (-not (Assert-TcpkWindows 'Test-TcpkComHijack')) { return }

    $userPrincipals = '(?i)\b(Everyone|Authenticated Users|Users|INTERACTIVE|BUILTIN\\Users)\b'
    $writeRights    = 'Write|Modify|FullControl'

    function _IsWritable([string]$ItemPath) {
        try {
            if (-not (Test-Path -LiteralPath $ItemPath)) { return $false }
            $acl = Get-Acl -LiteralPath $ItemPath -ErrorAction Stop
        } catch { return $false }
        $bad = $acl.Access | Where-Object {
            $_.IdentityReference.Value -match $userPrincipals -and
            $_.FileSystemRights -match $writeRights -and
            $_.AccessControlType -eq 'Allow'
        }
        return ($null -ne $bad -and @($bad).Count -gt 0)
    }

    $clsidRx = '\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}'
    $clsids  = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)

    foreach ($pe in Get-TcpkPeFiles -Path $Path) {
        if (Test-TcpkIsFrameworkFile $pe.Name) { continue }
        $text = Read-TcpkAllText -Path $pe.FullName
        if (-not $text) { continue }
        $ms = [regex]::Matches($text, $clsidRx)
        foreach ($m in $ms) { [void]$clsids.Add($m.Value) }
    }

    $item = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
    if (-not $item) { return }
    $root = if ($item.PSIsContainer) { $item.FullName } else { $item.DirectoryName }
    foreach ($cfg in Get-ChildItem -LiteralPath $root -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Extension.ToLowerInvariant() -in '.config','.json','.xml','.manifest' }) {
        try {
            $raw = Get-Content -LiteralPath $cfg.FullName -Raw -ErrorAction Stop
            if (-not $raw) { continue }
        } catch { continue }
        $ms = [regex]::Matches($raw, $clsidRx)
        foreach ($m in $ms) { [void]$clsids.Add($m.Value) }
    }

    if ($clsids.Count -eq 0) { return }

    $seen = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)

    foreach ($clsid in $clsids) {
        if (-not $seen.Add($clsid)) { continue }

        $hklmKey = "HKLM:\Software\Classes\CLSID\$clsid"
        if (-not (Test-Path -LiteralPath $hklmKey)) { continue }

        foreach ($subKey in 'InprocServer32','LocalServer32') {
            $serverKey = "$hklmKey\$subKey"
            if (-not (Test-Path -LiteralPath $serverKey)) { continue }

            $serverPath = $null
            try {
                $serverPath = (Get-ItemProperty -LiteralPath $serverKey -Name '(Default)' -ErrorAction Stop).'(Default)'
            } catch {}
            if (-not $serverPath) { continue }
            # Keep the value exactly as the registry holds it. The strip below is lossy and
            # the missing-image check has to parse the original: quoting and arguments are
            # what tell an absolute path with spaces apart from a path plus a switch.
            $serverRaw  = "$serverPath"
            $serverPath = $serverPath -replace '"','' -replace '\s+/.*$','' -replace '\s+-.*$',''

            $hkcuKey = "HKCU:\Software\Classes\CLSID\$clsid"
            if (-not (Test-Path -LiteralPath $hkcuKey)) {
                New-TcpkFinding -Module 'os' -RuleId 'comhijack.per-user-plantable' `
                    -Severity 'MEDIUM' -Confidence 'Confirmed' `
                    -Title "COM CLSID hijackable via HKCU: $clsid ($subKey)" `
                    -File $serverPath `
                    -Evidence "HKLM=$subKey -> $serverPath; HKCU entry absent" `
                    -Cwe @('CWE-427') `
                    -Description ('This COM CLSID is registered in HKLM but has no HKCU entry. ' +
                        'Any standard user can create an HKCU\Software\Classes\CLSID\' + $clsid + '\' + $subKey + ' ' +
                        'key pointing to their own DLL. Because HKCU is checked before HKLM, the ' +
                        'application will load the attacker''s server instead of the legitimate one ' +
                        '(ATT&CK T1546.015 COM Hijacking).') `
                    -Fix 'Register the COM server per-user at install time to prevent pre-emption, or validate the loaded server''s signature at runtime.'
            }

            # --- server binary MISSING: the registration is dangling -------------------
            # The writable-server rule below needs a file to overwrite. This is the case it
            # cannot see: the class IS registered machine-wide, but the image it names is
            # not on disk. Nothing has to be written to the registry to exploit that. The
            # attacker creates the file, and the next activation of the class loads it.
            $img = Resolve-TcpkComServerImage -Value $serverRaw
            if ($img -and -not $img.Exists) {
                $miss = $img.Path
                $lower = "$miss".ToLowerInvariant()
                $skip = $null

                # A bare file name is resolved through the DLL search path, so there is no
                # single directory to test and the plant location depends on the loading
                # process. That surface belongs to Test-TcpkWritablePath, not here.
                if ($miss -notmatch '[\\/]') { $skip = 'name only, resolved via search path' }

                # Managed COM servers register mscoree.dll here and name the real assembly
                # in the Assembly / Class / RuntimeVersion values. mscoree.dll always
                # exists, so this branch never fires on them -- which means a managed
                # server with a missing or plantable ASSEMBLY is a known blind spot, not
                # something this check quietly decided was safe.
                elseif ($lower -like '*\mscoree.dll' -or $lower -like '*\mscorwks.dll') {
                    $skip = 'managed COM shim; real assembly lives in subkey values'
                }

                # A path inside the scanning user's own profile is not a privilege
                # boundary: that user already owns it. Reporting it would describe the
                # operator's machine rather than the target.
                elseif ($env:USERPROFILE -and $lower.StartsWith("$($env:USERPROFILE.ToLowerInvariant())\")) {
                    $skip = 'inside the scanning user profile; not a privilege boundary'
                }

                if ($skip) {
                    Write-Verbose "Test-TcpkComHijack: $clsid $subKey -> $miss skipped ($skip)"
                } else {
                    $pg = Get-TcpkPlantGrants -Path $miss
                    if (-not $pg.Ok) {
                        New-TcpkFinding -Module 'os' -RuleId 'comhijack.server-missing' `
                            -Severity 'INFO' -Confidence 'Skipped' `
                            -Title "COM server binary missing, ACL unreadable: $clsid" `
                            -File $miss `
                            -Evidence "CLSID=$clsid; $subKey=$serverRaw; image absent; ACL of $($pg.Anchor) could not be read" `
                            -Fix 'Re-run elevated, or check by hand whether a standard user can create a file at this path.'
                    }
                    elseif (@($pg.Grants).Count -gt 0) {
                        $how = if ($pg.Needed -eq 'AppendData/AddSubdirectory') {
                            "create the missing directory under $($pg.Anchor) and then the file"
                        } else {
                            "create the file directly in $($pg.Anchor)"
                        }

                        # Evidence and Description are built here rather than inline. The
                        # Description ratchet (Tests\FindingExplanation.Tests.ps1) reads a
                        # New-TcpkFinding call by following backtick continuations and stops
                        # at the first line that does not end in one, so a multi-line
                        # parenthesised argument hides every parameter after it and the rule
                        # is reported as unexplained even though it is not.
                        $ev = "CLSID=$clsid; $subKey=$serverRaw; image absent; " +
                              "$($pg.Anchor) grants $($pg.Needed) to $($pg.Grants -join '; ')"

                        $desc = 'This class is registered machine-wide, so any process on the system can ' +
                            'activate it, but the server binary the registration names does not exist. The ' +
                            'path it names sits under a directory a standard user can write to, so an ' +
                            'attacker can ' + $how + ', and the next activation of the class loads that file. ' +
                            'This needs no registry write at all, which is what separates it from the HKCU ' +
                            'shadowing case: the registration doing the work is the vendor''s own, already ' +
                            'present in HKLM and already trusted by every process that asks for the class. ' +
                            'How far it goes depends on who activates the class. In the same user''s ' +
                            'processes it is code execution in their context. It becomes privilege ' +
                            'escalation when a higher-privileged process can be made to activate it, which ' +
                            'this check does not attempt to prove. A published route is to hand a ' +
                            'privileged COM server an object whose IMarshal::GetUnmarshalClass returns this ' +
                            'CLSID, so unmarshaling loads the planted image, which works against services ' +
                            'that have not set EOAC_NO_CUSTOM_MARSHAL or a strong unmarshaling policy.'

                        $fix = 'Remove the registration if the component is no longer shipped, which is the ' +
                            'usual cause of a dangling entry. If the component is real, have the installer ' +
                            'place it under a directory only administrators can write, and register that ' +
                            'path. Do not rely on creating the directory at first run: whoever creates it ' +
                            'first owns it.'

                        New-TcpkFinding -Module 'os' -RuleId 'comhijack.server-missing-plantable' `
                            -Severity 'HIGH' -Confidence 'Confirmed' `
                            -Title "COM server binary absent from a user-writable path: $clsid ($subKey)" `
                            -File $miss `
                            -Evidence $ev `
                            -Cwe @('CWE-427','CWE-732') `
                            -Description $desc `
                            -Fix $fix
                    }
                }
                continue
            }

            if ($serverPath -and (Test-Path -LiteralPath $serverPath -ErrorAction SilentlyContinue)) {
                if (_IsWritable $serverPath) {
                    New-TcpkFinding -Module 'os' -RuleId 'comhijack.server-writable' `
                        -Severity 'HIGH' -Confidence 'Confirmed' `
                        -Title "COM server DLL is user-writable: $clsid" `
                        -File $serverPath `
                        -Evidence "CLSID=$clsid; $subKey=$serverPath; file is writable by non-admin" `
                        -Cwe @('CWE-732','CWE-427') `
                        -Description ('The COM server binary pointed to by this CLSID is writable by ' +
                            'non-admin users. An attacker can replace it directly without needing ' +
                            'the HKCU hijack technique.') `
                        -Fix 'Restrict write access on the COM server binary to administrators/SYSTEM only.'
                }
            }
        }
    }
}
