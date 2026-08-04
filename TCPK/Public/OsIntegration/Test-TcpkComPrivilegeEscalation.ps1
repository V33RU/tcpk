function Test-TcpkComPrivilegeEscalation {
<#
.SYNOPSIS
    C34. COM AppID privilege escalation surface: RunAs, weak DCOM permissions,
    and auto-elevation markers.

.DESCRIPTION
    Out-of-process COM servers (LocalServer32) can run under a different account
    than the caller. If the AppID is misconfigured, any local user can activate
    a COM object that runs as SYSTEM or a privileged service account, triggering
    privileged operations without elevation.

    Three checks:

    1. AppID RunAs: if HKCR\AppID\{guid}\RunAs is set to a privileged identity
       (NT AUTHORITY\SYSTEM, any service SID, "Interactive User" on a session
       running as admin), a low-privilege caller can activate the server and
       call its methods at that privilege level.

    2. DCOM launch and access permissions: if LaunchPermission or AccessPermission
       is absent (null DACL = everyone allowed) or grants launch/activate rights
       to Everyone / Authenticated Users, any local user can activate the server.
       A null DACL falls back to the machine-wide DefaultLaunchPermission, which
       on default Windows installations allows all authenticated local users.

    3. Elevation-capable marker: HKCR\AppID\{guid} with the Elevation\Enabled
       DWORD = 1 marks a COM server as UAC auto-elevable. If combined with a
       weak AppID DACL or writable registration path, this is an elevation bypass.

    The cmdlet locates CLSIDs registered by the target app using the same
    registry query used by Test-TcpkComObjects, then traces them to their AppID.

.PARAMETER NameLike
    Substring to match in the CLSID InprocServer32/LocalServer32 value.

.PARAMETER Path
    Target install directory. When set, only COM servers whose binary resolves
    inside this path are inspected.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()]
    param([string[]]$NameLike, [string]$Path)

    if (-not (Assert-TcpkWindows 'Test-TcpkComPrivilegeEscalation')) { return }

    $terms = Get-TcpkNameTerms -NameLike $NameLike
    if (-not $terms.Count) { return }

    # Collect CLSIDs for the target product (same query pattern as Test-TcpkComObjects)
    $regOut = [System.Collections.Generic.List[string]]::new()
    foreach ($term in $terms) {
        $o = & reg.exe query 'HKCR\CLSID' /s /f "$term" /d 2>$null
        if ($o -and $LASTEXITCODE -eq 0) { $o | ForEach-Object { $regOut.Add($_) } }
    }
    if (-not $regOut.Count) { return }

    # Parse the reg output to extract (CLSID, binary path) pairs from LocalServer32 entries.
    # We only care about out-of-process (LocalServer32) servers for privilege escalation;
    # InprocServer32 runs in the caller's process and cannot cross a privilege boundary by itself.
    $clsids = [System.Collections.Generic.Dictionary[string,string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $currentKey = $null
    foreach ($line in $regOut) {
        if ($line -match '^HKEY_CLASSES_ROOT\\(.+)$') { $currentKey = $matches[1]; continue }
        if ($line -match '^\s+\(Default\)\s+REG_[A-Z_]+\s+(.+)$' -and $currentKey) {
            $val = $matches[1]
            if ($currentKey -notmatch '\\LocalServer32') { continue }
            if (-not (Test-TcpkTermMatch -Text $val -Terms $terms)) { continue }
            if ($Path -and -not (Test-TcpkPathUnderTarget -Value $val -InstallDir $Path)) { continue }
            if ($currentKey -match '^CLSID\\([^\\]+)') { $clsids[$matches[1]] = $val }
        }
    }
    if (-not $clsids.Count) { return }

    # Privileged RunAs values: SYSTEM and service accounts.
    $privilegedRunAsRx = '(?i)(nt authority\\system|localservice|networkservice|' +
                         'interactive user|nt service\\|svchost)'

    $seenAppId = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($clsid in $clsids.Keys) {
        $serverBin = $clsids[$clsid]

        # Resolve AppID for this CLSID
        $appId = $null
        try {
            $appId = (Get-ItemProperty "Registry::HKEY_CLASSES_ROOT\CLSID\$clsid" `
                          -Name AppID -ErrorAction Stop).AppID
        } catch { }

        # ---- Check 1: AppID RunAs ----
        if ($appId) {
            if (-not $seenAppId.Add($appId)) { continue }

            $runAs = $null
            try {
                $runAs = (Get-ItemProperty "Registry::HKEY_CLASSES_ROOT\AppID\$appId" `
                              -Name RunAs -ErrorAction Stop).RunAs
            } catch { }

            if ($runAs) {
                $isPrivileged = $runAs -match $privilegedRunAsRx

                New-TcpkFinding -Module 'os' -RuleId 'com.appid.runas' `
                    -Severity $(if ($isPrivileged) { 'HIGH' } else { 'MEDIUM' }) `
                    -Confidence $(if ($isPrivileged) { 'Confirmed' } else { 'Inferred' }) `
                    -Title "COM AppID $appId RunAs='$runAs' (CLSID $clsid)" `
                    -File "HKCR\AppID\$appId" `
                    -Evidence "CLSID=$clsid Binary=$serverBin RunAs=$runAs" `
                    -Cwe @('CWE-269','CWE-732') `
                    -Description ("The COM AppID has RunAs='$runAs', meaning the out-of-process " +
                        "COM server (CLSID $clsid, $serverBin) runs under that account regardless " +
                        "of the calling user's privilege level. " +
                        $(if ($isPrivileged) {
                            "This is a privileged RunAs value. Any user who can activate this COM " +
                            "object can call its methods with the server running as " + $runAs + ". " +
                            "If any method performs a privileged action (write to HKLM, create a " +
                            "file in a protected directory, start a service, etc.), this is a local " +
                            "privilege escalation primitive. Check the DCOM launch/access permissions " +
                            "next: if they allow standard users to activate the server, this is confirmed LPE."
                        } else {
                            "Verify the RunAs account does not have privilege above what callers " +
                            "should be able to exercise. If callers are restricted users and the " +
                            "RunAs account has admin/service-level privilege, review each exposed " +
                            "COM method for privileged operations."
                        })) `
                    -Fix ('Restrict DCOM launch permissions to admin-only if the server runs as a ' +
                        'privileged account (set LaunchPermission DACL via dcomcnfg.exe or ' +
                        'OleView). Alternatively, remove the RunAs value and let the server run ' +
                        'as the calling user (requires design change if the service functionality ' +
                        'needs elevated access).')
            }

            # ---- Check 2: DCOM launch/access permissions ----
            $launchPerm = $null; $accessPerm = $null
            try {
                $appIdProps = Get-ItemProperty "Registry::HKEY_CLASSES_ROOT\AppID\$appId" -ErrorAction Stop
                $launchPerm = $appIdProps.LaunchPermission
                $accessPerm = $appIdProps.AccessPermission
            } catch { }

            # NULL LaunchPermission = falls back to machine DefaultLaunchPermission
            # which on default Windows allows Authenticated Users to launch locally.
            if (-not $launchPerm) {
                New-TcpkFinding -Module 'os' -RuleId 'com.appid.no-launch-perm' `
                    -Severity 'MEDIUM' -Confidence 'Inferred' `
                    -Title "COM AppID $appId has no explicit LaunchPermission (falls back to machine default)" `
                    -File "HKCR\AppID\$appId" `
                    -Evidence "CLSID=$clsid; LaunchPermission value absent" `
                    -Cwe @('CWE-732','CWE-269') `
                    -Description ('The AppID has no LaunchPermission registry value. DCOM falls back ' +
                        'to the machine-wide DefaultLaunchPermission (HKLM\SOFTWARE\Microsoft\Ole). ' +
                        'On default Windows installations this allows all Authenticated Users to ' +
                        'launch COM servers locally. If the server runs as a privileged account ' +
                        '(see RunAs), this allows any authenticated user to activate it. ' +
                        'Confirm by checking the machine DefaultLaunchPermission SDDL and whether ' +
                        'standard user accounts can CoCreateInstance(CLSCTX_LOCAL_SERVER) this CLSID.') `
                    -Fix ('Set an explicit LaunchPermission on the AppID that restricts launch to ' +
                        'Administrators or a specific service SID. Use dcomcnfg.exe (Component Services) ' +
                        'or OleViewDotNet to set the DCOM application''s Launch and Activation ' +
                        'Permissions to Administrators only.')
            }

            # ---- Check 3: Auto-elevation marker ----
            $elevEnabled = $null
            try {
                $elevEnabled = (Get-ItemProperty "Registry::HKEY_CLASSES_ROOT\AppID\$appId\Elevation" `
                                    -Name Enabled -ErrorAction Stop).Enabled
            } catch { }

            if ($elevEnabled -eq 1) {
                New-TcpkFinding -Module 'os' -RuleId 'com.appid.auto-elevation' `
                    -Severity 'HIGH' -Confidence 'Confirmed' `
                    -Title "COM AppID $appId has Elevation\Enabled=1 (UAC auto-elevation)" `
                    -File "HKCR\AppID\$appId\Elevation" `
                    -Evidence "CLSID=$clsid; Binary=$serverBin; Elevation\Enabled=1" `
                    -Cwe @('CWE-269','CWE-250') `
                    -Description ('The COM AppID has the Elevation\Enabled DWORD set to 1, marking it ' +
                        'as a UAC auto-elevable COM server. When a standard-user caller activates ' +
                        'this CLSID, Windows automatically elevates the COM server without a UAC ' +
                        'prompt (for built-in Windows components) or shows a UAC prompt (for ' +
                        'third-party). If the server binary path is writable by a standard user ' +
                        '(binary planting) or the CLSID registration path is writable (COM hijack), ' +
                        'an attacker can replace the server binary and achieve silent elevation. ' +
                        'Check the binary path ACL and the CLSID registration key ACL for ' +
                        'non-admin write access.') `
                    -Fix ('Ensure the binary pointed to by LocalServer32 is stored in a path ' +
                        'writable only by SYSTEM/Administrators. Verify the CLSID and AppID ' +
                        'registry keys have admin-only write ACLs. If the server does not need ' +
                        'auto-elevation, remove the Elevation\Enabled value.')
            }
        }
    }
}
