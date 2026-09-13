function Test-TcpkComMachineDefaults {
<#
.SYNOPSIS
    C25. Machine-wide DCOM defaults: EnableDCOM and the machine-default
    Launch / Access restriction SDDL that inherits into every CLSID without
    its own AppID permissions.

.DESCRIPTION
    Complements Test-TcpkComHijack (per-CLSID InprocServer32) and
    Test-TcpkComPrivilegeEscalation (per-AppID LaunchPermission). This checks the
    MACHINE DEFAULT that every unregistered / permission-less COM server inherits:

      HKLM\SOFTWARE\Microsoft\Ole
        EnableDCOM               "Y" enables network DCOM activation machine-wide.
        MachineLaunchRestriction binary SDDL - the floor for who may LAUNCH/ACTIVATE
                                 any COM server that does not set its own AppID
                                 LaunchPermission.
        MachineAccessRestriction binary SDDL - the floor for who may CALL into any
                                 COM server that does not set its own AccessPermission.
        DefaultLaunchPermission  legacy per-machine default (pre-restriction).
        DefaultAccessPermission  legacy per-machine default.

    A weak machine default is a broad, quiet attack surface: it silently grants
    launch/access to every COM server on the box that relies on the default,
    including out-of-proc servers that run as SYSTEM or a service account.

    Rules:
      com.enable-dcom-network             MEDIUM  Confirmed  EnableDCOM = Y (or unset,
                                                              which defaults to Y on
                                                              older Windows). Network
                                                              DCOM activation is on.
      com.machine-default-perms-weak      HIGH    Confirmed  MachineLaunchRestriction /
                                                              MachineAccessRestriction /
                                                              DefaultLaunchPermission /
                                                              DefaultAccessPermission
                                                              SDDL grants a broad
                                                              non-admin principal
                                                              (Everyone / Authenticated
                                                              Users / Users / INTERACTIVE
                                                              / ANONYMOUS) a Launch,
                                                              Activate or Access right.
      com.machine-default-absent          LOW     Confirmed  No MachineLaunchRestriction
                                                              is set at all, so the OS
                                                              legacy default applies -
                                                              scope info for the reader.

.OUTPUTS
    [TcpkFinding]
#>
    [CmdletBinding()] param()

    if (-not (Assert-TcpkWindows 'Test-TcpkComMachineDefaults')) { return }

    $ole = 'HKLM:\SOFTWARE\Microsoft\Ole'
    if (-not (Test-Path -LiteralPath $ole)) { return }
    $props = $null
    try { $props = Get-ItemProperty -LiteralPath $ole -ErrorAction SilentlyContinue } catch { return }
    if (-not $props) { return }

    # ---- com.enable-dcom-network -----------------------------------------------
    $enableDcom = "$($props.EnableDCOM)"
    if ($enableDcom -eq '' -or $enableDcom -ieq 'Y') {
        $ev = if ($enableDcom) { "EnableDCOM=$enableDcom" } else { 'EnableDCOM not set (defaults to Y)' }
        New-TcpkFinding -Module 'os' -RuleId 'com.enable-dcom-network' `
            -Severity 'MEDIUM' -Confidence 'Confirmed' `
            -Title 'DCOM network activation is enabled machine-wide' `
            -File $ole -Evidence $ev `
            -Cwe @('CWE-284') `
            -Description ('HKLM\SOFTWARE\Microsoft\Ole\EnableDCOM is Y (or unset, which defaults to Y on ' +
                'older Windows). Any COM server exposed via an AppID can then be activated over the network by ' +
                'a remote principal subject to the launch/access permissions. Combined with a weak machine ' +
                'default (see com.machine-default-perms-weak) this becomes a remote DCOM activation surface. ' +
                'For a hardened thick-client host that does not need remote DCOM, this should be N.') `
            -Fix 'Set EnableDCOM=N if the product does not require remote DCOM activation. If it does, ensure every exposed AppID sets an explicit, narrow LaunchPermission and AccessPermission.'
    }

    # ---- machine-default permission SDDL checks --------------------------------
    # The values are REG_BINARY security descriptors. Convert to SDDL and look for a
    # broad non-admin principal granted a COM launch/activate/access right.
    #   COM access-mask bits: Execute (0x01) = Local Access, 0x02 = Remote Access,
    #   Execute_Local (0x04) = Local Launch, 0x08 = Remote Launch, 0x10 = Local Activate,
    #   0x20 = Remote Activate. In SDDL these appear as the hex mask in the ACE.
    $riskyTrusteeRx = '(?i);(WD|AU|BU|IU|AN|WD|S-1-1-0|S-1-5-11|S-1-5-32-545|S-1-5-4|S-1-5-7)\)'
    $anyRestrictionPresent = $false

    foreach ($valueName in 'MachineLaunchRestriction','MachineAccessRestriction','DefaultLaunchPermission','DefaultAccessPermission') {
        $raw = $props.$valueName
        if (-not $raw) { continue }
        $anyRestrictionPresent = $true
        $sddl = ''
        try {
            $sd = New-Object System.Security.AccessControl.RawSecurityDescriptor($raw, 0)
            $sddl = $sd.GetSddlForm([System.Security.AccessControl.AccessControlSections]::Access)
        } catch { continue }
        if (-not $sddl) { continue }
        # Split into ACE strings and check each Allow ACE for a risky trustee.
        $badAces = @()
        foreach ($aceMatch in [regex]::Matches($sddl, '\(([^()]*)\)')) {
            $ace = $aceMatch.Groups[1].Value
            $parts = $ace -split ';'
            if ($parts.Count -lt 6) { continue }
            $aceType   = $parts[0]
            $trustee   = $parts[5]
            if ($aceType -notmatch '^A') { continue }   # Allow ACEs only
            if ($trustee -match '^(WD|AU|BU|IU|AN|S-1-1-0|S-1-5-11|S-1-5-32-545|S-1-5-4|S-1-5-7)$') {
                $badAces += $ace
            }
        }
        if ($badAces.Count -gt 0) {
            New-TcpkFinding -Module 'os' -RuleId 'com.machine-default-perms-weak' `
                -Severity 'HIGH' -Confidence 'Confirmed' `
                -Title "Weak machine-default COM permission: $valueName grants a broad principal" `
                -File "$ole\$valueName" -Evidence "SDDL=$sddl; risky ACEs: $(($badAces | Select-Object -First 3) -join ' ')" `
                -Cwe @('CWE-284','CWE-732') `
                -Description ("The machine-default COM security descriptor '$valueName' grants a broad non-admin " +
                    'principal (Everyone / Authenticated Users / Users / INTERACTIVE / ANONYMOUS) a launch, ' +
                    'activate or access right. Every COM server on the box that does not set its own AppID ' +
                    'LaunchPermission / AccessPermission inherits this floor, including out-of-proc servers ' +
                    'running as SYSTEM or a service account. A low-privilege caller can then activate or call ' +
                    'into a privileged COM server that assumed the default was safe.') `
                -Fix 'Tighten the machine-default SDDL to Administrators + SYSTEM (+ the specific service accounts that must launch COM), and give every privileged AppID its own explicit LaunchPermission / AccessPermission rather than relying on the machine default.'
        }
    }

    if (-not $anyRestrictionPresent) {
        New-TcpkFinding -Module 'os' -RuleId 'com.machine-default-absent' `
            -Severity 'LOW' -Confidence 'Confirmed' `
            -Title 'No machine-default COM launch/access restriction is set' `
            -File $ole -Evidence 'MachineLaunchRestriction / MachineAccessRestriction not present' `
            -Cwe @('CWE-284') `
            -Description ('Neither MachineLaunchRestriction nor MachineAccessRestriction is set, so the OS ' +
                'legacy per-machine default applies to every permission-less COM server. On modern Windows ' +
                'this legacy default is reasonably tight, but a hardened deployment should set explicit ' +
                'restriction SDDLs. Scope information for the reader.') `
            -Fix 'Set an explicit MachineLaunchRestriction / MachineAccessRestriction SDDL that grants only Administrators + SYSTEM + required service accounts.'
    }
}
