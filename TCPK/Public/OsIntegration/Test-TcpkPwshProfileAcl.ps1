function Test-TcpkPwshProfileAcl {
<#
.SYNOPSIS
    C20. PowerShell profile.ps1 auto-load points: DACL and content sniff (ATT&CK T1546.013).

.DESCRIPTION
    Every PowerShell host launch of the current user (or every launch of that host by any
    user, for the AllUsers scope) sources up to two profile files. If a non-admin can write
    the file - or, if the file does not exist yet, its parent folder - they land arbitrary
    code in the security context of anyone who opens a PowerShell session.

    Six canonical paths, checked in this order:
      1. %WINDIR%\System32\WindowsPowerShell\v1.0\profile.ps1                 (AllUsers, AllHosts, 5.1 x64)
      2. %WINDIR%\System32\WindowsPowerShell\v1.0\Microsoft.PowerShell_profile.ps1 (AllUsers, CurrentHost, 5.1 x64)
      3. %WINDIR%\SysWOW64\WindowsPowerShell\v1.0\profile.ps1                 (AllUsers, AllHosts, 5.1 x86)
      4. %PROGRAMFILES%\PowerShell\7\profile.ps1                              (AllUsers, AllHosts, 7.x)
      5. %USERPROFILE%\Documents\WindowsPowerShell\profile.ps1                (CurrentUser, 5.1)
      6. %USERPROFILE%\Documents\PowerShell\profile.ps1                       (CurrentUser, 7.x)

    Rules:
      loadpoint.pwsh-profile.file-writable   HIGH    Confirmed  The profile file exists and its
                                                                 DACL grants a non-admin principal
                                                                 write / delete / take-ownership.
      loadpoint.pwsh-profile.dir-writable    HIGH    Confirmed  The profile file does NOT exist,
                                                                 but the containing directory is
                                                                 non-admin writable so the attacker
                                                                 creates it.
      loadpoint.pwsh-profile.hijack-source   MEDIUM  Inferred   An existing profile dot-sources
                                                                 or Import-Modules a path that
                                                                 does not exist / lives on a
                                                                 user-writable directory - the
                                                                 attacker creates the file at that
                                                                 exact path.

    The per-user paths (5, 6) live under the user's own Documents folder, which the user
    obviously has write on. That is not an LPE against themselves - it is an LPE only against
    a *different* user who launches PowerShell on the same box AS them (via runas / task
    scheduler / service impersonation). To keep the finding useful, per-user paths are only
    reported when a non-admin OTHER THAN the current user (BUILTIN\Users, Everyone, INTERACTIVE)
    holds a dangerous grant on the file/directory.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()] param()

    if (-not (Assert-TcpkWindows 'Test-TcpkPwshProfileAcl')) { return }

    # File rights that permit code injection. Same mask + rationale as Test-TcpkVendorDriverAcl.
    $fileDangerMask =
        0x00000002 -bor 0x00000040 -bor 0x00010000 -bor
        0x00040000 -bor 0x00080000 -bor 0x10000000 -bor 0x40000000

    # Broadly-scoped non-admin principals. The current user's own SID is DELIBERATELY not
    # in this list for the per-user paths - see rule doc above.
    $riskySids = @(
        'S-1-1-0',      # Everyone
        'S-1-5-11',     # Authenticated Users
        'S-1-5-32-545', # BUILTIN\Users
        'S-1-5-4',      # INTERACTIVE
        'S-1-5-32-547'  # BUILTIN\Power Users
    )
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

    # Resolve the user's real Documents folder. On any Win10/11 host with OneDrive Known-
    # Folder-Move enabled (default for personal accounts and most Entra-joined boxes) this is
    # %OneDrive%\Documents, not %USERPROFILE%\Documents - checking the literal $env:USERPROFILE
    # path silently misses the most common per-user profile location. Enumerate both roots so
    # a non-redirected fallback still fires when the shell folder is redirected elsewhere.
    $docRoots = New-Object 'System.Collections.Generic.List[string]'
    try {
        $d = [Environment]::GetFolderPath('MyDocuments')
        if ($d) { [void]$docRoots.Add($d) }
    } catch { }
    $legacyDoc = Join-Path $env:USERPROFILE 'Documents'
    if ((Test-Path -LiteralPath $legacyDoc) -and -not ($docRoots -contains $legacyDoc)) { [void]$docRoots.Add($legacyDoc) }

    $paths = New-Object 'System.Collections.Generic.List[hashtable]'
    [void]$paths.Add(@{ Scope='AllUsers/AllHosts (5.1 x64)';     Path = (Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\profile.ps1');                     PerUser=$false })
    [void]$paths.Add(@{ Scope='AllUsers/CurrentHost (5.1 x64)';  Path = (Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\Microsoft.PowerShell_profile.ps1'); PerUser=$false })
    [void]$paths.Add(@{ Scope='AllUsers/AllHosts (5.1 x86)';     Path = (Join-Path $env:WINDIR 'SysWOW64\WindowsPowerShell\v1.0\profile.ps1');                     PerUser=$false })
    # PowerShell 7 has an x64 and an x86 install; each ships an AllHosts profile and a
    # CurrentHost twin (Microsoft.PowerShell_profile.ps1). A sysadmin who wants to plant a
    # hook has four AllUsers slots to choose from, not one.
    $pf7   = if ($env:ProgramFiles)       { Join-Path $env:ProgramFiles       'PowerShell\7' } else { $null }
    $pf7x86 = ${env:ProgramFiles(x86)}
    if ($pf7x86) { $pf7x86 = Join-Path $pf7x86 'PowerShell\7' }
    foreach ($root in @($pf7, $pf7x86) | Where-Object { $_ }) {
        $arch = if ($root -like '*Program Files (x86)*') { 'x86' } else { 'x64' }
        [void]$paths.Add(@{ Scope="AllUsers/AllHosts (7.x $arch)";    Path = (Join-Path $root 'profile.ps1');                       PerUser=$false })
        [void]$paths.Add(@{ Scope="AllUsers/CurrentHost (7.x $arch)"; Path = (Join-Path $root 'Microsoft.PowerShell_profile.ps1'); PerUser=$false })
    }
    # CurrentUser paths under EACH candidate Documents root (redirected and legacy).
    foreach ($d in $docRoots) {
        [void]$paths.Add(@{ Scope="CurrentUser (5.1) under $d";               Path = (Join-Path $d 'WindowsPowerShell\profile.ps1');                    PerUser=$true })
        [void]$paths.Add(@{ Scope="CurrentUser (5.1 CurrentHost) under $d";   Path = (Join-Path $d 'WindowsPowerShell\Microsoft.PowerShell_profile.ps1'); PerUser=$true })
        [void]$paths.Add(@{ Scope="CurrentUser (7.x) under $d";               Path = (Join-Path $d 'PowerShell\profile.ps1');                           PerUser=$true })
        [void]$paths.Add(@{ Scope="CurrentUser (7.x CurrentHost) under $d";   Path = (Join-Path $d 'PowerShell\Microsoft.PowerShell_profile.ps1');       PerUser=$true })
    }

    foreach ($p in $paths) {
        $target = $p.Path
        $exists = Test-Path -LiteralPath $target
        $parent = Split-Path -Parent $target

        # Choose which object to DACL-check: the file if it exists, else the parent directory.
        $subject = if ($exists) { $target } elseif ($parent -and (Test-Path -LiteralPath $parent)) { $parent } else { $null }
        if (-not $subject) { continue }

        $acl = $null
        try { $acl = Get-Acl -LiteralPath $subject -ErrorAction Stop } catch { continue }
        # _AceIsRisky already restricts to broad non-admin principals (Everyone, Authenticated
        # Users, BUILTIN\Users, INTERACTIVE, Power Users). The current user's own SID is not
        # in that set, so a per-user profile whose only permissive ACE is CurrentUser -> Modify
        # does NOT fire - which is what we want. Windows here would grant NO extra reach.
        $bad = @($acl.Access | Where-Object { _AceIsRisky $_ })
        if ($bad.Count -eq 0) { continue }

        $grant = ($bad | ForEach-Object { "$($_.IdentityReference) -> $($_.FileSystemRights) (inherited=$($_.IsInherited))" } |
                  Select-Object -First 4) -join '; '
        if ($exists) {
            New-TcpkFinding -Module 'os' -RuleId 'loadpoint.pwsh-profile.file-writable' `
                -Severity 'HIGH' -Confidence 'Confirmed' `
                -Title "PowerShell profile is non-admin writable: $target" `
                -File $target -Evidence "$($p.Scope) | $grant" `
                -Cwe @('CWE-732','CWE-269','CWE-427') `
                -Description ("A PowerShell profile file for the '$($p.Scope)' scope is present and its DACL " +
                    "grants a non-admin principal one of the file rights that permit code injection (WriteData, " +
                    "DeleteSubdirectoriesAndFiles, Delete, WriteDac, WriteOwner, GenericAll, GenericWrite). " +
                    "Every PowerShell host launch under that scope sources this file (ATT&CK T1546.013), so the " +
                    "attacker lands arbitrary code in the target user's PowerShell session on next launch.") `
                -Fix 'Restrict the profile DACL to SYSTEM + BUILTIN\Administrators write. If the profile is empty and the app does not need it, delete the file.'
        } else {
            New-TcpkFinding -Module 'os' -RuleId 'loadpoint.pwsh-profile.dir-writable' `
                -Severity 'HIGH' -Confidence 'Confirmed' `
                -Title "PowerShell profile directory is non-admin writable (no profile yet): $parent" `
                -File $parent -Evidence "$($p.Scope) | $grant | expected profile: $(Split-Path -Leaf $target)" `
                -Cwe @('CWE-732','CWE-269','CWE-427') `
                -Description ("The '$($p.Scope)' PowerShell profile does not exist, but the directory that " +
                    "would host it is non-admin writable. An attacker creates $(Split-Path -Leaf $target) at " +
                    "this location; every subsequent PowerShell host launch under the scope sources it as the " +
                    "target user.") `
                -Fix 'Restrict the profile directory DACL to admin-only write, or create an empty admin-owned profile.ps1 so the write is blocked by the file DACL.'
        }

        # Content sniff: does the existing profile dot-source or Import-Module a hijackable path?
        if ($exists) {
            $body = $null
            try { $body = [IO.File]::ReadAllText($target) } catch { $body = $null }
            if ($body) {
                $refs = [regex]::Matches($body, '(?im)^\s*(?:\.|Import-Module)\s+([^\r\n]+)$')
                foreach ($m in $refs) {
                    $rawTail = $m.Groups[1].Value.Trim()
                    # Skip parameterised calls we cannot reason about statically:
                    #   Import-Module -Name Foo
                    #   Import-Module -FullyQualifiedName @{ ModuleName='Foo'; ModuleVersion='1.0' }
                    #   Import-Module Foo, Bar               (comma list)
                    #   Import-Module $someVar               (PS-variable ref, we can't resolve)
                    #   Import-Module (Join-Path $x 'y')     (subexpression, ditto)
                    #   Import-Module $env:FOO\bar           (PS env-var ref, ExpandEnvironmentVariables
                    #                                        only expands %VAR%, not $env:VAR)
                    if ($rawTail -match '^\s*-') { continue }             # any named-parameter call
                    if ($rawTail -match ',') { continue }                 # comma-separated list
                    if ($rawTail -match '^\s*[\$\(]') { continue }        # subexpression / variable
                    if ($rawTail -match '\$env:|\$PSScriptRoot|\$HOME|\$MyInvocation|\$PROFILE') { continue }
                    # Strip a wrapping quote pair (single OR double).
                    $ref = $rawTail
                    if ($ref -match '^\s*"([^"]+)"\s*(?:;.*)?$') { $ref = $matches[1] }
                    elseif ($ref -match "^\s*'([^']+)'\s*(?:;.*)?$") { $ref = $matches[1] }
                    else {
                        # Unquoted: strip a trailing comment and any tail past the first whitespace
                        # (that tail can only be a parameter to the pipeline element we ignored above).
                        if ($ref -match '^\s*(\S+)') { $ref = $matches[1] }
                    }
                    if (-not $ref) { continue }
                    # Bare module name from PSModulePath - not a path, skip.
                    if ($ref -match '^[A-Za-z][\w.-]+$') { continue }
                    $resolved = $ref
                    try { $resolved = [Environment]::ExpandEnvironmentVariables($ref) } catch { }
                    $refDir = Split-Path -Parent $resolved
                    if (-not $refDir -or -not (Test-Path -LiteralPath $refDir)) {
                        New-TcpkFinding -Module 'os' -RuleId 'loadpoint.pwsh-profile.hijack-source' `
                            -Severity 'MEDIUM' -Confidence 'Inferred' `
                            -Title "PowerShell profile references a non-existent path: $ref" `
                            -File $target -Evidence "$($p.Scope) references '$ref' (parent dir missing)" `
                            -Cwe @('CWE-427') `
                            -Description ("The profile at $target dot-sources or Import-Modules a path whose " +
                                "parent directory does not exist. If any non-admin can create that directory + " +
                                "file, they land code on the next session. Inferred because the miss may be " +
                                "intentional (a per-machine gate) rather than a hijack primitive.") `
                            -Fix 'Remove the reference, or place the file at the referenced path with an admin-only DACL.'
                        continue
                    }
                    $refAcl = $null
                    try { $refAcl = Get-Acl -LiteralPath $refDir -ErrorAction Stop } catch { continue }
                    $badRef = @($refAcl.Access | Where-Object { _AceIsRisky $_ })
                    if ($badRef.Count -gt 0) {
                        New-TcpkFinding -Module 'os' -RuleId 'loadpoint.pwsh-profile.hijack-source' `
                            -Severity 'MEDIUM' -Confidence 'Inferred' `
                            -Title "PowerShell profile sources a path in a non-admin writable folder: $ref" `
                            -File $target -Evidence "profile references '$ref'; parent '$refDir' is non-admin writable" `
                            -Cwe @('CWE-427') `
                            -Description ("The profile at $target dot-sources or Import-Modules '$ref'. The " +
                                "referenced parent directory is non-admin writable, so an attacker can drop a " +
                                "replacement at the referenced path even when the profile itself is protected. " +
                                "Inferred because the referenced file's own DACL may still refuse the write.") `
                            -Fix 'Move the referenced file into an admin-only location and hard-code that path; or remove the .-source / Import-Module line.'
                    }
                }
            }
        }
    }
}
